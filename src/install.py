import os
from subprocess import call

print("Must be run in root or with sudo\n")
check = input("Enter I for install and U to uninstall any added packages (C to cancel): ")
check2 = input("Are you using Ubuntu Linux (U) or Windows 10 (W): ")
if check2 == "U":
    if check == "I":
        call("sudo apt update")
        call("sudo apt install net-tools", shell=True)
        call("sudo apt install php", shell=True)
        call("sudo apt install mysql-server", shell=True)
        call("sudo apt install php-mysql", shell=True)
        call("sudo apt install python3",shell=True)
        call("sudo apt install scapy", shell=True)
        call("sudo apt install apache2", shell=True)
        call("sudo apt install nmap", shell=True)
        call("sudo pip3 install pyqt5", shell=True)
        call("sudo pip3 install mysql-connector-python")
    elif check == "U":
        call("sudo apt remove net-tools", shell=True)
        call("sudo apt remove php", shell=True)
        call("sudo apt remove mysql-server", shell=True)
        call("sudo apt remove php-mysql", shell=True)
        call("sudo apt remove python3",shell=True)
        call("sudo apt remove scapy", shell=True)
        call("sudo apt remove apache2", shell=True)
        call("sudo apt remove nmap", shell=True)
        call("sudo pip3 uninstall pyqt5", shell=True)
        call("sudo pip3 uninstall mysql-connector-python")
    elif check == "C":
        sys.exit("Install/uninstall cancelled")
    else:
        sys.exit("\nInvalid value given, try again")
elif check2 == "W":
    pass

