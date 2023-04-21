
import os
import subprocess
import re

hostname = subprocess.run(['hostname','-I'], stdout=subprocess.PIPE).stdout.decode('utf-8')
hostname = hostname.split(" ")

subnet = hostname[0][0:9]
subnetScan = f"{subnet}.0/24"

scan = subprocess.run(['sudo','nmap','-sn',f'{subnetScan}'], stdout=subprocess.PIPE).stdout.decode('utf-8')
scan = scan.split('\n')

IPs_MAC = []
for x in range(1,len(scan)):
    ip = re.findall('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',scan[x])
    if len(ip) == 1:
        IPs_MAC.append(ip[0][0:])
    mac = re.findall('[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+\:[a-zA-Z0-9]+',scan[x])
    if len(mac) == 1:
        IPs_MAC.append(mac[0][0:])
IPs_MAC.append(hostname[0]); IPs_MAC.append(MAC) 