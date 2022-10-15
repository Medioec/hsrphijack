from scapy.all import *
import netifaces as ni
import os
import re

#change when required
nic="wlan0"

method=b'POST'

def sniffcreds():
	pkt = sniff(filter="tcp", offline="test1.pcap")
	for i in range(len(pkt) - 1):
		if pkt[i].dport == 80:
			if pkt[i].haslayer(Raw):
				r = pkt[i][Raw].load
				if method in r:
					#os.system("echo " + r.decode(encoding='utf-8'))
					#print(r)
					r = r.decode('UTF-8')
					#print(r)
					
					w = 'Origin:' + '(.+?)' + '\n'
					web = re.search(w, r).group(1)
					print("Website is:", web)
					
					#Extract username in between uid= and &
					user = '=' + '(.+?)' + '&'
					uname = re.search(user, r).group(1)
					print("Username is:", uname)
					
					#throw away everything before of &
					k="&"
					res = re.split(k, r, 1)[-1]
					#print(res)
					
					
					if "&" in res:
						pw = '=' + '(.+?)' + '&'
						pwd = re.search(pw, res).group(1)
						print("Password is:", pwd)
					else:
						pwd = re.split("=", res)
						print("Password is:", pwd[1])
						
						#pw = '=' + '(.+?)' 
						#userpw = re.search(pw, res).group(1)
						#print("PasswordELSE is:", userpw)
						 
					#Extract Password in between passw= and &
					#pw = '=' + '(.+?)' + '&'
					#userpw = re.search(pw, res).group(1)
					#print("Password is:", userpw)
					

					
					break
					
if __name__ == "__main__":
	sniffcreds()
