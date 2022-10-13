from scapy.all import *
import ipaddress
import netifaces as ni

interface = "eth0"

translations = {}
portcounter = 0
myip = ni.ifaddresses(interface)[ni.AF_INET][0]["addr"]
mymac = ni.ifaddresses(interface)[ni.AF_LINK][0]["addr"]
mynetmask = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
myprefix = ipaddress.IPv4Network(f"0.0.0.0/{mynetmask}").prefixlen
mynetwork = ipaddress.ip_interface(f"{myip}/{myprefix}").network

# sniff for packets to manually forward
def start_forward_sniffer():
    virtualIP = "192.168.50.1"
    ########################
    filterstring = f"tcp and dst host not (0.0.0.0) and ether src host not {mymac} and not ip multicast"
    sniff(prn=manual_forwarding, filter=filterstring)

# manually forward packets and replace source ip of packets exiting network with own ip, dest ip of packets entering network with remembered ip
def manual_forwarding(packet):
    global portcounter
    dstaddress = ipaddress.ip_address(packet[IP].dst)
    dst_address_string = packet[IP].dst
    proto:str
    # store src ip and port in dictionary along with new src port to use for future translation back to original ip
    
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
                #packet[Ether].src = mymac
                #packet[Ether].dst = None
                packet[IP].dst = dstip
                del packet[IP].chksum
                packet[proto].dport = dstport
                del packet[proto].chksum
                send(packet[1], verbose=False)
                del translations[dport]
    #if destination is in network, just forward
    else: 
        try:
            sport = packet[TCP].sport
            proto = "TCP"
        except:
            sport = packet[UDP].sport
            proto = "UDP"
        finally:
            srcip = packet[IP].src
            newport = portcounter%60001 + 5535
            translations[newport] = srcip, sport
            portcounter += 1
            #packet[Ether].src = mymac
            packet[IP].src = myip
            del packet[IP].chksum
            #packet[Ether].dst = None
            packet[proto].sport = newport
            del packet[proto].chksum
            lst = packet[1].fragment(fragsize=1400)
            for pkt in lst:
                send(pkt, verbose=False)
            send(packet[1], verbose=False)
        
if __name__ == "__main__":
    print(myip)
    start_forward_sniffer()