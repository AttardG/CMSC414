##What needs to be done
#Examine all drives on the device using ipconfig
#   Check Windows IP configuration and the DNS suffix search list
#   Locate network adapter with the same connection-specific DNS suffix
#   Check the IPv4 address and subnet mask to check for all packets with IPs in this range
#   Check arp table for interface with IPs that fall into the network adapters subnet
#   Create an array of all of these IPs and MAC addresses
#       Provide a special entry for the host IP at the end of the array
#   Return this array

import os
import subprocess
import re

try: 

    hostname = subprocess.run(['hostname','-I'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    hostname = hostname.split(" ")

    ifconfig_lines = subprocess.run(['ifconfig','-a'], stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
    ifconfig_lines = [line.strip() for line in ifconfig_lines if 1==1]


    found = 0
    iface = ""
    x = 0
    y = 0
    while found == 0:
        check = ifconfig_lines[x]
        check = check.split(" ")
        aface = re.search("^[a-zA-Z0-9_.-]*:$",check[0])
        if check[0] != "":
            if aface:
                iface = check[0].replace(":","")
                y = x

            if(check[1] == hostname[0]):
                found = 1
        x = x + 1

    done = 0
    MAC = ""
    foundit = 0
    while done == 0:
        check = ifconfig_lines[y]
        check = check.split(" ")
        if(check[0] == 'ether' and foundit == 0):
            MAC = check[1]
            done = 1
        y = y+1
        if(ifconfig_lines[x] == ""):
            done = 1

    arptable = subprocess.run(['arp','-a'], stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()

    arpdone = 0
    x = 0
    IPs_MAC = []
    tempARP = []
    paren_remove = ["(",")"]
    for x in range(len(arptable)):
        checkarp = arptable[x].split(" ")
        if(re.match(iface,checkarp[6])):
            for paren in paren_remove:
                checkarp[1] = checkarp[1].replace(paren,"")
            IPs_MAC.append(checkarp[1]); IPs_MAC.append(checkarp[3])

    IPs_MAC.append(hostname[0]); IPs_MAC.append(MAC); IPs_MAC.append(iface)      
    print(IPs_MAC)

except:
    print("An error occurred, retry or check your network config")