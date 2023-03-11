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

    ipconfig = subprocess.run(['ipconfig','/all'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    ipconfig_lines = ipconfig.splitlines()
    ipconfig_lines = [line.replace(" ","") for line in ipconfig_lines if 1==1]
    search_key = ipconfig_lines[8].split(":")

    found = 0
    x = 0
    MAC = ""
    IP = ""
    Subnet = ""
    while found == 0:
        if(ipconfig_lines[x] == f'Connection-specificDNSSuffix.:{search_key[1]}'):
            y = x
            found = 1
            temp = ipconfig_lines[y:y+22]
            MAC = temp[2]
            IP = temp[8]
            Subnet = temp[9]
        x = x+1

    MACnum = MAC[24:]; MACnum = MACnum.replace(":","")
    IPnum = IP[22:];  IPnum = IPnum.replace(":",""); IPnum = IPnum.replace("(Preferred)","")
    Subnum = Subnet[21:]; Subnum = Subnum.replace(":","")
    if(IP[:11] != "IPv4Address" or Subnet[:10] != "SubnetMask" or len(IPnum) < 4 or len(Subnum) < 4):
        raise Exception("An error occurred, please check your network")

    arptable = subprocess.run(['arp','-a'], stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()
    found = 0
    x = 0
    IPs_MAC = []
    tempARP = []
    while found == 0:
        if(re.match(f'Interface: {IPnum}(.)',arptable[x])):
            x = x + 2
            found = 1
            while arptable[x] != '':
                temp = arptable[x].split(" ")
                for line in temp:
                    if(line != ''):
                        if(line == 'dynamic'):
                            IPs_MAC.append(tempARP[0]); IPs_MAC.append(tempARP[1])
                            tempARP.clear()
                        elif(line == 'static'):
                            tempARP.clear()
                        else:
                            tempARP.append(line)
                x = x+1
        x = x+1
    IPs_MAC.append(IPnum); IPs_MAC.append(MACnum)
    print(IPs_MAC)

except:
    print("An error occurred, retry or check your network config")