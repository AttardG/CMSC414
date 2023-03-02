![Vcu Computer Science College of Engineering](https://user-images.githubusercontent.com/80475089/222560075-29c03b0f-7035-4172-aa00-c266862969c1.png)
# CMSC414 Spring 2023
Semester Project: 
Giselle “G” Attard,
Christian Jones

Objective:
DNS Poisoning Application/Tool using Python

Main Idea
The overall idea of this project is to create an application that will implement a DNS poisoning/spoofing attack on a particular network a host is connected to. This attack will allow for a host to impersonate themselves as a DNS server on a network which will allow them to intercept DNS requests and send altered DNS responses. They will also be able to manipulate DNS cache and where users on the network are directed when trying to access particular web domains. By spoofing the DNS server a host will also be able to send users to different domains than intended, send users to a set of well known spoofed web pages and/or enact a man in the middle attack stealing users credentials. All the aspects of this application will be accessible through a GUI created in Python to allow for a convenient and user friendly experience for the attacker. This GUI will allow for the ability to select one or multiple IPs on a network to poison by first intercepting all IPs currently accessing the host network. The GUI will also allow a host to select where a domain will redirect to, this can either be another domain or a spoofed web domain (if it is included in the application). This application will be constructed to run on a ubuntu or kali linux distro.

List of tasks along with their description
Specifics
Finds all IPs on a particular open network using.
Create GUI of DNS poisoning Application
Python, Tkinter
Retrieves packets from a particular IP or multiple to make changes to DNS request and response packets
Allows for the ability to create a list of domains to force changes to and the particular IP whose DNS will be poisoned
Creates a temporary HTTP server that spoofs a legitimate server, redirects to this server and steals info
Create a GUI for the DNS application to make it more user friendly
Prevention
Don’t connect directly to unsafe/unencrypted networks

