import sys
import os
import re
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from abc import ABC, abstractmethod
import scapy.all as scapy
from scapy.all import sniff, wrpcap, get_if_list, IP, IPv6, TCP, UDP, ICMP, ARP, Raw 
from scapy.layers.l2 import STP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSClientKeyExchange, TLSServerKeyExchange, TLSNewSessionTicket
from PyQt5.uic import loadUi
from PyQt5.QtCore import pyqtSignal, Qt, QThread, QTimer, QSize, QRegExp
from PyQt5.QtGui import QIcon, QStandardItem, QStandardItemModel, QRegExpValidator, QIntValidator
from PyQt5.QtWidgets import QApplication, QDesktopWidget, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QSpacerItem, QSizePolicy, QDialog, QLabel, QPushButton, QStyle, QHBoxLayout, QFileDialog
from urllib.parse import unquote
from queue import Queue


#--------------------------------------------Default_Packet----------------------------------------------#
class Default_Packet(ABC): #abstarct class for default packet
    name = None #represents the packet name
    packet = None #represents the packet object itself for our use later
    packetType = None #represents the packet type based on scapy known types
    id = None #represents the id for the packet object, for ease of use in dictionary later

    def __init__(self, name=None, packet=None, id=None): #ctor for default packet 
        self.name = name
        self.packet = packet
        self.id = id
        

    #get method for id
    def getId(self): 
        return self.id #return the id 
    

    #set method for packet type
    def setPacketType(self, packetType): 
        self.packetType = packetType


    #get method for packet object
    def getPacket(self):
        return self.packet #return the packet object
    

    #method for raw info capture
    def rawInfo(self):
        output = ''
        if Raw in self.packet: #insert payload data (if available)
            payload = self.packet[Raw].load #get payload data from packet
            output += f'Payload Data: {payload.hex()}\n\n' #insert payload as hexadecimal
        return output
    

    #method that handles a long string and makes it fit in the GUI 
    def fitStr(self, st, info): 
        output = ''
        if info is not None: #if info not none we continue
            if isinstance(info, bytes): #if given info is byte we convert it to utf-8 string
                info = info.decode('utf-8', errors='replace') #decode the byte to string
            if len(info) >= 46: #if the string is longer then specified length we add a new line
                temp = '\n'.join(info[i:i+46] for i in range(0, len(info), 46)) #iterating over the string and adding new line after specified amount of characters
                output += f'{st}\n{temp}\n\n' #insert to the output 
            elif len(f'{st}: {info}') >=46: #if the info string and st string togther exceed the specified characters we add new line
                output += f'{st}\n{info}\n\n' #insert to the output
            else: #else info and st strings are not exceeding the specifed amount of characters
                output += f'{st} {info}\n\n' #we add the original info and st strings to the output without a new line
        else: #else info is none
            output += f'{st} {info}\n\n' #add to output the value with none value 
        return output


    #method for retrieving login credentials from http packet
    def loginInfo(self):
        credentials = {} #credentials dictionary for username and password
        httpRegex = lambda key: rf'{key}=([^&]+)' #regex for http payload template, regex that ends in & at the end (if present)
        #list for usernames and password labels that are common in http payloads
        usernames = ['username', 'Username', 'UserName', 'user', 'User', 'uname', 'Uname', 'usr', 'Usr', 'email', 'Email', 'login', 'Login', 'usrname', 'Usrname', 'uid', 'Uid']
        passwords = ['password', 'Password', 'pass', 'Pass', 'pwd', 'Pwd', 'passwd', 'Passwd', 'pswd', 'psw', 'secret', 'Secret', 'secure', 'Secure', 'key', 'Key', 'auth', 'Auth']
        if self.packet.haslayer(Raw) and self.packet.haslayer(HTTPRequest): #if true we have http request packet and it has a payload
            payload = self.packet[Raw].load.decode('utf-8', errors='replace') #we decode the payload of the packet 
            for username in usernames: #we iterate over the usernames to check if there's a matching username label
                if username in payload or username.upper() in payload: #if true we found a matching label
                    userRegex = httpRegex(username) #create a regex with the username label and regex template
                    usr = re.search(userRegex, payload) #we call search method of regex to check if the username matching the regex 
                    if usr: #if true the username is valid
                        credentials['username'] = unquote(usr.group(1)) #we add the username to the dictionary
                        break
            if credentials: #if we found a username, we continue to get the password
                for password in passwords:  #we iterate over the passwords to check if there's a matching password label
                    if password in payload or password.upper() in payload: #if true we found a matching label
                        passRegex = httpRegex(password) #create a regex with the password label and regex template
                        pwd = re.search(passRegex, payload) #we call search method of regex to check if the password matching the regex 
                        if pwd: #if true the password is valid
                            credentials['password'] = unquote(pwd.group(1)) #we add the password to the dictionary
                            break
        return credentials


    #method for ip configuration capture
    def ipInfo(self): 
        output = ''
        if IP in self.packet: #if true means packet has ip layer
            srcIp = self.packet[IP].src #represents the source ip
            dstIp = self.packet[IP].dst #represents the destination ip
            output += f'Source IP: {srcIp}\n\n' #insert source ip to output
            output += f'Destination IP: {dstIp}\n\n' #insert denstination ip to output
            #additional Information for IPv4 and IPv6 packets
            if self.packet[IP].version == 4: #if true we have ipv4 packet
                ttl = self.packet[IP].ttl #represents ttl parameter in packet
                dscp = self.packet[IP].tos #represents dscp parameter in packet
                output += f'TTL: {ttl}, DSCP: {dscp}\n\n' #add both to output

            elif self.packet[IP].version == 6: #else we have an ipv6 packet
                hopLimit = self.packet[IPv6].hlim #represents the hop limit parameter in packet
                trafficClass = self.packet[IPv6].tc #represnets the traffic class in packet
                output += f'Hop Limit: {hopLimit}, Traffic Class: {trafficClass}\n\n' #add them both to output
        if hasattr(self.packet, 'chksum'): #if packey has checksum parameter
            output += f'Checksum: {self.packet.chksum}\n\n' #we add the checksum to output
        output += f'Packet Size: {len(self.packet)} bytes\n\n' #add the packet size to output
        return output


    #method representing the packet briefly, derived classes may need to implement for different types
    def info(self): 
        output ='' #output string for information of packet
        srcMac = self.packet.src #represents the source mac address
        dstMac = self.packet.dst #represents the destination mac address
        srcPort = '' #source port of packet
        dstPort ='' #destination port of packet
        packetSize = len(self.packet) #size of the packet

        if self.packet.haslayer(TCP) or self.packet.haslayer(UDP): #id packet is tcp or udp we get port info
            srcPort = self.packet.sport #represents the source port of packet
            dstPort = self.packet.dport #represents the destination port of packet
        if self.packet.haslayer(IP): #if true packet have ip address so we print the packet info with ip and port
            srcIp = self.packet[IP].src #represents the source ip of packet
            dstIp = self.packet[IP].dst #represents the destination ip of packet
            output += f'{self.name} Packet: ({srcIp}):({srcPort}) --> ({dstIp}):({dstPort})' #insert info to output
        elif not self.packet.haslayer(IP): #else no ip layer 
            output += f'{self.name} Packet: ({srcMac}):({srcPort}) --> ({dstMac}):({dstPort})' #insert info without ip to output
        if self.packet.haslayer(HTTP) and (self.packet.haslayer(HTTPResponse) or self.packet.haslayer(HTTPRequest)): #if true packet is http
            if self.packet.haslayer(HTTPRequest) and self.loginInfo(): #if true it means we have a login request http packet (with username and password)
                output += ' Type: Login Request' #add http login request type to ouput
            else: #else its a regular request or response http packet
                output += f' Type: {"Response" if self.packet.haslayer(HTTPResponse) else "Request"}' #add http type, response or request
        output += f' | Size: {packetSize} bytes' #insert packet size to output
        return output


    #method that represents the packet information more deeply, for derived classes to implement further
    def moreInfo(self):
        output = '' #output string for info
        if self.packet.haslayer(TCP) or self.packet.haslayer(UDP): #if packet is tcp or udp
            output += f'{self.name} Packet:\n\n' #insert packet name to output
            output += f'Source Port: {self.packet.sport}\n\n' #insert source port to output
            output += f'Destination Port: {self.packet.dport}\n\n' #insert destination port to output
        else: #else its other packet type
            output += f'{self.name} Packet:\n\n' #insert packet name to output
            output += f'Source MAC: {self.packet.src}\n\n' #insert packet source mac address
            output += f'Destination MAC: {self.packet.dst}\n\n' #insert packet destination mac address
        output += self.ipInfo() #call ip method to add neccessary info if ip layer is present
        return output

#--------------------------------------------Default_Packet-END----------------------------------------------#

#--------------------------------------------------TCP------------------------------------------------#
class TCP_Packet(Default_Packet):
    def __init__(self, packet=None, id=None): # ctor for tcp packet
        super().__init__('TCP', packet, id) # call parent ctor
        if packet.haslayer(TCP): #checks if packet is TCP
            if IP not in packet: #if true the packet is raw
                self.name = 'Raw TCP' #specify its a raw packet
            self.packetType = TCP #specify the packet type


    #method for packet information
    def moreInfo(self): 
        output = f'{super().moreInfo()}' #call parent moreInfo method
        #prints TCP flags
        flags = self.packet[self.packetType].flags #tcp has flags, we extract the binary number that represents the flags
        flagsDict = { #we add to a dictionary all the flags of tcp
            'FIN': (flags & 0x01) != 0, #we extract FIN flag with '&' operator with 0x01(0001 in binary)
            'SYN': (flags & 0x02) != 0, #we extract SYS flag with '&' operator with 0x02(0010 in binary)
            'RST': (flags & 0x04) != 0, #we extract RST flag with '&' operator with 0x04(0100 in binary)
            'PSH': (flags & 0x08) != 0, #we extract PSH flag with '&' operator with 0x08(1000 in binary)
            'ACK': (flags & 0x10) != 0, #we extract ACK flag with '&' operator with 0x10(0001 0000 in binary)
            'URG': (flags & 0x20) != 0, #we extract URG flag with '&' operator with 0x20(0010 0000 in binary)
        }

        output += f'Sequence Number: {self.packet.seq}\n\n' #add the sequence number to output
        output += f'Acknowledgment Number: {self.packet.ack}\n\n' #add the acknowledgment number to output
        output += f'Window Size: {self.packet.window}\n\n' #add window size parameter to output
        output += 'Flags:\n' #add the flags to output
        temp = '' #temp string for our use 
        for flag, value in flagsDict.items(): #iteration over the flags in tcp packet
            if flag == 'ACK': #if flag is ACK we add new line for clean gui representation
                temp += '\n' #add new line to temp
            temp += f'{flag}: {value}, ' #add the current flag with its value
        output += temp.rstrip(', ') #finally insert the flags to output 
        output += '\n\n'
        if self.packet[self.packetType].options: #add TCP Options (if available)
            temp = '' #initializing temp to an empty string
            count = 0 #counter for tcp options
            output += 'TCP Options:\n' #insert the tcp options to output
            for option in self.packet[self.packetType].options: #iteration over the options list
                if count == 4 or option[0] == 'SAck': #for clean gui representation we add new line if count is 4 or SAck option available
                    temp += '\n' #add new line
                temp += f'{option[0]}: {option[1]}, ' #add the options to temp
                count += 1 #icrease the counter
            output += temp.rstrip(', ') #strip the output for leading comma
            output += '\n\n'
        return output

#-------------------------------------------------TCP-END------------------------------------------------#

#---------------------------------------------------UDP-------------------------------------------------#
class UDP_Packet(Default_Packet):
    def __init__(self, packet=None, id=None): # ctor 
        super().__init__('UDP', packet, id) # call parent ctor
        if packet.haslayer(UDP): #checks if packet is UDP
            if IP not in packet: #if true the packet has no ip, means its raw
                self.name = 'Raw UDP' #update the packet name
            self.packetType = UDP #add packet type


#----------------------------------------------UDP-END----------------------------------------------#

#------------------------------------------------HTTP------------------------------------------------#
class HTTP_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('HTTP', packet, id) # call parent ctor
        if packet.haslayer(HTTP): #checks if packet is HTTP
            self.packetType = HTTP #add packet type


    #method for packet information
    def moreInfo(self):
        output = super().moreInfo() #call parent moreInfo method
        if self.packet and HTTP in self.packet: #if packet has HTTP layer
            httpPacket = self.packet[HTTP] #set the http packet
            headers = {} #set headers to be an empty dictionary
            if self.packet.haslayer(HTTPResponse): #if packet is http response
                httpPacket = self.packet[HTTPResponse] #set the packet as http response
            elif self.packet.haslayer(HTTPRequest): #if packet is http request
                httpPacket = self.packet[HTTPRequest] #set the packet as http request
            
            if httpPacket.haslayer(HTTPResponse) or httpPacket.haslayer(HTTPRequest): #if http packets is response or request
                for field in httpPacket.fields_desc: #iterating over fields desc list to retrive the headers dictionary
                    fieldName = field.name #field name of packet
                    fieldValue = getattr(httpPacket, fieldName) #field value of packet
                    if isinstance(fieldValue, bytes): #if field value is byte we decode it
                        fieldValue = fieldValue.decode() #decode field name byte
                    headers[fieldName] = fieldValue #finally we add field value to headers dictionary

            if self.packet.haslayer(HTTPResponse): #if the packet is response
                httpVersion = headers.get('Http_Version') #get the http version of packet
                statusCode = httpPacket.Status_Code.decode() #get the status code of response packet
                contentLength = headers.get('Content_Length') #get the content length of response packet
                server = headers.get('Server') #get the server of response packet
                output += 'Type: Response\n\n' #add type of packet to output
                output += f'HTTP Version: {httpVersion}\n\n' #add http version to output
                output += f'Status Code: {statusCode}\n\n' #add status code to output
                output += f'Content Length: {contentLength}\n\n' #add content length to output
                output += self.fitStr('Server:', server) #add server of packet to output

            elif self.packet.haslayer(HTTPRequest): #if the packet is request
                httpLogin = self.loginInfo() #call loginInfo method to get login credentials (if available)
                httpVersion = headers.get('Http_Version') #get the http version of packet
                method = httpPacket.Method.decode() #get the method name of request packet
                url = httpPacket.Host.decode() + httpPacket.Path.decode() #get the url of the request packet
                accept = headers.get('Accept') #get the accept info of request
                referer = headers.get('Referer') #get the referer of request
                output += 'Type: Login Request\n\n' if httpLogin else 'Type: Request\n\n' #add type of packet to output based on http info
                output += f'HTTP Version: {httpVersion}\n\n' #add http version to output
                output += f'Method: {method}\n\n' #add method to output
                output += self.fitStr('URL:', url) #add url to output
                if httpLogin: #if true we have captured login information
                    output += 'Login Credentials:\n\n' #add login credentials to output
                    output += self.fitStr('Username:', httpLogin['username']) #add usernname from our httpLogin dict
                    output += self.fitStr('Password:', httpLogin['password']) #add password from our httpLogin dict
                output += self.fitStr('Accept:', accept) #add accept to output
                output += self.fitStr('Referer:', referer) #add referer to output
        return output
    
#-----------------------------------------------HTTP-END------------------------------------------------#

#---------------------------------------------------DNS------------------------------------------------#
class DNS_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('DNS', packet, id) # call parent ctor
        if packet.haslayer(DNS): #checks if packet is DNS
            self.packetType = DNS #add packet type


    #method for brief packet information
    def info(self):
        output ='' #output string for information of packet
        dnsPacket = self.packet[DNS] #parameter for dns packet
        srcMac = self.packet.src #representst the source mac address
        dstMac = self.packet.dst #represents the destination mac address
        srcIp = '' #represents the source ip address
        dstIp = '' #represents the destination ip address
        srcPort = '' #represents the source port
        dstPort ='' #represents the destination port
        packetSize = len(self.packet) #represenets the packet size

        if self.packet.haslayer(IP): #if true packet has ip layer
            srcIp = self.packet[IP].src #set the source ip
            dstIp = self.packet[IP].dst #set the destination ip
        if self.packet.haslayer(TCP) or self.packet.haslayer(UDP): #if dns packet transmitted through tcp or udp it has port 
            srcPort = self.packet.sport #set the source port
            dstPort = self.packet.dport #set the destination port

        if (self.packet.haslayer(TCP) or self.packet.haslayer(UDP)) and self.packet.haslayer(IP): #if it's transmitted through tcp or udp with ip
            output += f'{self.name} Packet: ({srcIp}):({srcPort}) --> ({dstIp}):({dstPort})' #add the info with ip to output
        elif (self.packet.haslayer(TCP) or self.packet.haslayer(UDP)) and not self.packet.haslayer(IP): #if its transmitted through tcp or udp without ip
            output += f'{self.name} Packet: ({srcMac}):({srcPort}) --> ({dstMac}):({dstPort})' #add the info without ip to output
        elif self.packet.haslayer(IP): # if there's only ip layer
            f'{self.name} Packet: ({srcIp}):({srcMac}) --> ({dstIp}):({dstMac})' #add the info to output
        elif not self.packet.haslayer(IP): #else it wasn't transmitted through tcp or udp and it doesn't have ip
            f'{self.name} Packet: ({srcMac}) --> ({dstMac})' #add the info to output

        output += f' Type: {"Response" if dnsPacket.qr else "Request"}' #add the dns type, response or request
        output += f' | Size: {packetSize} bytes' #add the size of the packet
        return output


    #method for packet information
    def moreInfo(self):
        output = super().moreInfo() #call parent moreInfo method
        if self.packet and DNS in self.packet: #if packet has DNS layer
            dnsPacket = self.packet[DNS] #save the dns packet in parameter
            output += f'ID: {dnsPacket.id}\n\n' #id of the dns packet
            if dnsPacket.qr == 1: #means its a response packet
                if dnsPacket.an: #if dns packet is response packet
                    output += f'Type: Response\n\n' #add type of packet to output
                    output += self.fitStr('Response Name:', dnsPacket.an.rrname) #add repsonse name to output
                    output += f'Response Type: {dnsPacket.an.type}, ' #add response type to output
                    output += f'Response Class: {dnsPacket.an.rclass}\n\n' #add response class to output
                    output += f'Num Responses: {len(dnsPacket.an)}\n\n' #add number of responses to output
                    if hasattr(dnsPacket.an, 'rdata'): #check if rdata attribute exists
                        output += self.fitStr('Response Data:', dnsPacket.an.rdata) #specify the rdata parameter
            else: #means its a request packet
                if dnsPacket.qd:
                    output += f'Type: Request\n\n' #add type of packet to output
                    output += self.fitStr('Request Name:', dnsPacket.qd.qname) #add request name to output
                    output += f'Request Type: {dnsPacket.qd.qtype}, ' #add request type to output
                    output += f'Request Class: {dnsPacket.qd.qclass}\n\n' #add request class to output
                    output += f'Num Requests: {len(dnsPacket.qd)}\n\n' #add num of requests to output
        return output
    
#-------------------------------------------------DNS-END----------------------------------------------#

#--------------------------------------------------TLS--------------------------------------------------#
class TLS_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('TLS', packet, id) # call parent ctor
        if packet.haslayer(TLS): #checks if packet is TLS
            if IP not in packet: #if true the packet has no ip, means its raw
                self.name = 'Raw TLS' #update the packet name
            self.packetType = TLS #add packet type
    
    
    #method for packet information
    def moreInfo(self):
        output = super().moreInfo() #call parent moreInfo method
        if self.packet and TLS in self.packet: #if packet has TLS layer
            tlsPacket = self.packet[TLS] #save the TLS packet in parameter
            output += f'Version: {tlsPacket.version}\n\n' #version of the TLS packet
            if self.packet.haslayer(TLSClientHello): #if true the packet is a client hello response
                output += f'Handshake Type: Client Hello\n\n' #add handshake tyoe to output
                output += f'Length: {self.packet[TLSClientHello].msglen}\n\n' #add length to output
                output += self.fitStr('Cipher Suites:', self.packet[TLSClientHello].ciphers) #add cipher suites list to output
            elif self.packet.haslayer(TLSServerHello): #if true the packet is a server hello response
                output += f'Handshake Type: Server Hello\n\n' #add handshake tyoe to output
                output += f'Length: {self.packet[TLSServerHello].msglen}\n\n' #add length to output
                output += f'Cipher Suite: {self.packet[TLSServerHello].cipher}\n\n' #add cipher suite number to output
            elif self.packet.haslayer(TLSClientKeyExchange): #if true the packet is a client key exchange response
                output += f'Handshake Type: Client Key Exchange\n\n' #add handshake tyoe to output
                output += f'Length: {self.packet[TLSClientKeyExchange].msglen}\n\n' #add length to output
            elif self.packet.haslayer(TLSServerKeyExchange): #if true the packet is a server key exchange response
                output += f'Handshake Type: Server Key Exchange\n\n' #add handshake tyoe to output
                output += f'Length: {self.packet[TLSServerKeyExchange].msglen}\n\n' #add length to output
            elif self.packet.haslayer(TLSNewSessionTicket): #if true the packet is a new session ticket response
                output += f'Handshake Type: New Session Ticket\n\n' #add handshake tyoe to output
                output += f'Length: {self.packet[TLSNewSessionTicket].msglen}\n\n' #add length to output
        return output
    
#-----------------------------------------------TLS-END------------------------------------------------#

#------------------------------------------------ICMP------------------------------------------------#
class ICMP_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('ICMP', packet, id) # call parent ctor
        if packet.haslayer(ICMP): #checks if packet is icmp
            if IP not in packet: #if true the packet has no ip, means its raw
                self.name = 'Raw ICMP' #update the packet name
            self.packetType = ICMP #add packet type


    #method for brief packet information
    def info(self):
        output = ''
        packetSize = len(self.packet) #represent the packet size
        icmpType = self.packet[ICMP].type #represents icmp type
        icmpCode = self.packet[ICMP].code #represents icmp code
        if IP in self.packet: #if packet has ip layer
            srcIp = self.packet[IP].src #represents the source ip
            dstIp = self.packet[IP].dst #represents the destination ip
            output += f'{self.name} Packet: ({srcIp}) --> ({dstIp}) | Type: {icmpType}, Code: {icmpCode} | Size: {packetSize} bytes' #add to output the packet info with ip
        else:
            output += f'{self.name} Packet: Type: {icmpType}, Code: {icmpCode} | Size: {packetSize} bytes' #add to output the packet info 
        return output


    #method for packet information
    def moreInfo(self): 
        output = ''
        if ICMP in self.packet: #if packet has icmp layer
            icmpType = self.packet[ICMP].type #represents icmp type
            icmpCode = self.packet[ICMP].code #represents icmp code
            icmpSeq = self.packet[ICMP].seq #represents icmp sequence number
            icmpId = self.packet[ICMP].id #represents icmp identifier
            output += f'{self.name} Packet:\n\n' #add packet name to output
            output += f'Type: {icmpType}\n\n' #add icmp type to output
            output += f'Code: {icmpCode}\n\n' #add icmp code to output
            output += f'Sequence Number: {icmpSeq}\n\n' #add icmp sequence number
            output += f'Identifier: {icmpId}\n\n' #add icmp identifier
        output += self.ipInfo() #call ip method for more ip info
        return output

#--------------------------------------------ICMP-END----------------------------------------------#

# --------------------------------------------ARP----------------------------------------------#
class ARP_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('ARP', packet, id) #call parent ctor
        if packet.haslayer(ARP): #checks if packet is arp
            self.packetType = ARP #add packet type
    

    #method for brief packet information
    def info(self):
        output = ''
        srcMac = self.packet[ARP].hwsrc #represents arp source mac address
        srcIp = self.packet[ARP].psrc #represents arp source ip address
        dstMac = self.packet[ARP].hwdst #represents arp destination mac address
        dstIp = self.packet[ARP].pdst #represents arp destination ip address
        packetSize = len(self.packet) #represents the packet size 
        output += f'{self.name} Packet: ({srcIp}):({srcMac}) --> ({dstIp}):({dstMac}) | Size: {packetSize} bytes' #add the packet info to output
        return output


    #method for packet information
    def moreInfo(self):
        output = ''
        if ARP in self.packet: #if packet has layer of arp
            output += f'{self.name} Packet:\n\n' #add packet name to output
            output += f'Source MAC: {self.packet[ARP].hwsrc}\n\n' #add arp source mac address
            output += f'Destination MAC: {self.packet[ARP].hwdst}\n\n' #add arp destination mac address
            output += f'Source IP: {self.packet[ARP].psrc}\n\n' #add arp source ip address
            output += f'Destination IP: {self.packet[ARP].pdst}\n\n' #add arp destination ip address
            output += f'Packet Size: {len(self.packet)} bytes\n\n' #add packet size
            output += f'ARP Operation: {"Request" if self.packet[ARP].op == 1 else "Reply"}\n\n' #add the arp operation to output
            output += f'ARP Hardware Type: {self.packet[ARP].hwtype}\n\n' #add the hardware type to output
            output += f'ARP Protocol Type: {hex(self.packet[ARP].ptype)}\n\n' #add protocol type to output
            output += f'ARP Hardware Length: {self.packet[ARP].hwlen}\n\n' #add hardware length to output
            output += f'ARP Protocol Length: {self.packet[ARP].plen}\n\n' #add protocol length to output
            output += f'Packet Size: {len(self.packet)} bytes\n\n' #add packet size to output
        return output
        
# --------------------------------------------ARP-END----------------------------------------------#

# --------------------------------------------STP----------------------------------------------#
class STP_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('STP', packet, id) #call parent ctor
        if packet.haslayer(STP): #checks if packet is stp
            self.packetType = STP #add pacet type


    #method for brief packet information
    def info(self):
            output = ''
            packetSize = len(self.packet) #represents the stp packet size
            output += f'{self.name} Packet: ({self.packet.src}) --> ({self.packet.dst}) | Size: {packetSize} bytes' #add packet info to output
            return output

    
    #method for packet information
    def moreInfo(self):
        output = ''
        if STP in self.packet: #if packet is an stp packet
            stpProto = self.packet[STP].proto #represents stp protocol
            stpVersion = self.packet[STP].version #represents stp version
            stpBridgeId = self.packet[STP].bridgeid #represents stp bridge id
            stpPortId = self.packet[STP].portid #represents stp port id
            stpPathCost = self.packet[STP].pathcost #represents stp path cost
            stpAge = self.packet[STP].age #represents stp age
            output += f'{self.name} Packet:\n\n' #add packet name to output
            output += f'STP Protocol: {stpProto}\n\n' #add stp protocol to output
            output += f'Version: {stpVersion}\n\n' #add stp version to output
            output += f'Source MAC: {self.packet.src}\n\n' #add source mac address to output
            output += f'Destination MAC: {self.packet.dst}\n\n' #add destination mac address to output
            output += f'Bridge ID: {stpBridgeId}\n\n' #add bridge id tto output
            output += f'Port ID: {stpPortId}\n\n' #add port id to output
            output += f'Path Cost: {stpPathCost}\n\n' #add path cost to output
            output += f'Age: {stpAge}\n\n' #add stp age to output
        output += f'Packet Size: {len(self.packet)} bytes\n\n' #add packet size to output
        return output

# --------------------------------------------STP-END----------------------------------------------#

#-----------------------------------------HELPER-FUNCTIONS-----------------------------------------#

#method to print all available interfaces
def GetAvailableInterfaces():
    #get a list of all available network interfaces
    interfaces = get_if_list() #call get_if_list method to retrieve the available interfaces
    if interfaces: #if there are interfaces we print them
        print('Available network interfaces:')
        i = 1 #counter for the interfaces 
        for interface in interfaces: #print all availabe interfaces
            if sys.platform == 'win32': #if ran on windows we convert the guid number
                print(f'{i}. {guidToStr(interface)}')
            else: #else we are on other os so we print the interface 
                print(f'{i}. {interface}')
            i += 1
    else: #else no interfaces were found
        print('No network interfaces found.')


#method for retrieving interface name from GUID number (Windows only)
def guidToStr(guid):
    try: #we try to import the specific windows method from scapy library
        from scapy.arch.windows import get_windows_if_list
    except ImportError as e: #we catch an import error if occurred
        print(f'Error importing module: {e}') #print the error
    interfaces = get_windows_if_list() #use the windows method to get list of guid number interfaces
    for interface in interfaces: #iterating over the list of interfaces
        if interface['guid'] == guid: #we find the matching guid number interface
            return interface['name'] #return the name of the interface associated with guid number
    return None #else we didnt find the guid number so we return none


#method for retrieving the network interfaces
def getNetworkInterfaces():
    networkNames = ['eth', 'wlan', 'en', 'Ethernet', 'Wi-Fi'] #this list represents the usual network interfaces that are available in various platfroms
    interfaces = get_if_list() #get a list of the network interfaces
    if sys.platform == 'win32': #if current os is Windows we convert the guid number to interface name
        temp = [guidToStr(interface) for interface in interfaces if guidToStr(interface) is not None] #get a new list of network interfaces with correct names instead of guid numbers
        interfaces = temp #assign the new list to our interfaces variable
    matchedInterfaces = [interface for interface in interfaces if any(interface.startswith(name) for name in networkNames)] #we filter the list to retrieving ethernet and wifi interfaces
    return matchedInterfaces #return the matched interfaces as list

#-----------------------------------------HANDLE-FUNCTIONS-----------------------------------------#
#method that handles TCP packets
def handleTCP(packet):
    global packetCounter
    TCP_Object = TCP_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[TCP_Object.getId()] = TCP_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return TCP_Object #finally return the object

#method that handles UDP packets
def handleUDP(packet):
    global packetCounter
    UDP_Object = UDP_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[UDP_Object.getId()] = UDP_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return UDP_Object #finally return the object

#method that handles HTTP packets
def handleHTTP(packet):
    global packetCounter
    HTTP_Object = HTTP_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[HTTP_Object.getId()] = HTTP_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return HTTP_Object #finally return the object

#method that handles DNS packets
def handleDNS(packet):
    global packetCounter
    DNS_Object = DNS_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[DNS_Object.getId()] = DNS_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return DNS_Object #finally return the object

#method that handles TLS packets
def handleTLS(packet):
    global packetCounter
    if packet[TLS].type == 22: #we need to capture handshakes TLS packets so 22 is the correct type
        TLS_Object = TLS_Packet(packet, packetCounter) #create a new object for packet
        packetDictionary[TLS_Object.getId()] = TLS_Object #insert it to packet dictionary
        packetCounter += 1 #increase the counter
        return TLS_Object #finally return the object
    return None #else we return none

#method that handles ICMP packets
def handleICMP(packet):
    global packetCounter 
    ICMP_Object = ICMP_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[ICMP_Object.getId()] = ICMP_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return ICMP_Object #finally return the object

#method that handles ARP packets
def handleARP(packet):
    global packetCounter
    ARP_Object = ARP_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[ARP_Object.getId()] = ARP_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return ARP_Object #finally return the object

#method that handles STP packets
def handleSTP(packet):
    global packetCounter
    STP_Object = STP_Packet(packet, packetCounter) #create a new object for packet
    packetDictionary[STP_Object.getId()] = STP_Object #insert it to packet dictionary
    packetCounter += 1 #increase the counter
    return STP_Object #finally return the object

#-----------------------------------------HANDLE-FUNCTIONS-END-----------------------------------------#

packetDictionary = {} #initialize the packet dictionary
packetCounter = 0 # global counter for dictionary elements

#-----------------------------------------HELPER-FUNCTIONS-END-----------------------------------------#

#--------------------------------------------PacketCaptureThread----------------------------------------------#

class PacketCaptureThread(QThread):
    packetCaptured = pyqtSignal() #signal for the thread to update the main for changes
    interface = None #inerface of network (optional)
    packetQueue = None #packet queue pointer for the thread
    packetFilter = None #represents the packet type filter for sniffer
    PortandIp = None #string that represents port and ip for sniffer to filter with
    stopCapture = False #flag for capture status

    def __init__(self, packetQueue, packetFilter, PortandIp, interface=None):
        super(PacketCaptureThread, self).__init__()
        self.interface = interface #initialize the network interface if given
        self.packetQueue = packetQueue #setting the packetQueue from the packet sniffer class
        self.packetFilter = packetFilter #set the packet filter for scapy sniff method
        self.PortandIp = PortandIp #set the port and ip string for filthering with desired pord and ip
        self.updateTimer = QTimer(self) #initialzie the QTimer
        self.updateTimer.timeout.connect(lambda: self.packetCaptured.emit()) #connect the signal to gui to update the packet list when timer elapses
        self.updateTimer.start(2000) #setting the timer to elapse every 2 seconds (can adjust according to the load)


    #methdo that handles stopping the scan
    def stop(self):
        self.stopCapture = True #setting the stop flag to true will stop the loop in sniff


    #method for sniff method of scapy to know status of flag 
    def checkStopFlag(self, packet):
        return self.stopCapture #return the stopCapture flag


    #method that handles the packet capturing
    def PacketCapture(self, packet): 
        #for each packet we receive we send it to the dict to determine its identity and call the necessary handle method
        for packetType, handler in self.packetFilter.items():
            if packet.haslayer(packetType): #if we found matching packet we call its handle method
                handledPacket = handler(packet) #call handler method of each packet
                if handledPacket != None: #check if its not none
                    self.packetQueue.put(handledPacket.info()) #we put the packet's info in the queue for later use 
                break
        #else:
        #    print(f'Unknown Packet Type --> {packet.summary()}') #print summary of the packet


    #run method for the thread, initialzie the scan, call scapy sniff method with necessary parameters
    def run(self):
        if self.interface is not None: #if interface is specified we call sniff with desired interface
            sniff(iface=self.interface, prn=self.PacketCapture, filter=self.PortandIp, stop_filter=self.checkStopFlag, store=0)
        else: #else we initiate the sniff with default network interface
            sniff(prn=self.PacketCapture, filter=self.PortandIp, stop_filter=self.checkStopFlag, store=0)

#--------------------------------------------PacketCaptureThread-END----------------------------------------------#
    
#---------------------------------------------------Application----------------------------------------------------#

class PacketSniffer(QMainWindow):
    packetCaptureThread = None #current thread that capturing packets 
    packetModel = None #packet list model for QListView 
    packetQueue = None #queue for packets before adding them to list (thread safe)
    validIp = True #set validIp flag to true

    def __init__(self):
        super(PacketSniffer, self).__init__()
        loadUi("PacketSniffer.ui", self) #load the ui file of the sniffer
        self.initUI() #call init method
        self.packetModel = QStandardItemModel() #set the QListView model for adding items to it
        self.PacketList.setModel(self.packetModel) #set the model for the packetlist in gui
        self.packetQueue = Queue() #initialize the packet queue
        

    def initUI(self):
        self.setWindowTitle('Packet Sniffer') #set title of window
        self.StartScanButton.clicked.connect(self.StartScanClicked) #add method to handle start scan button
        self.StopScanButton.clicked.connect(self.StopScanClicked) #add method to handle stop scan button 
        self.ClearButton.clicked.connect(self.ClearClicked) #add method to handle clear button 
        self.SaveScanButton.clicked.connect(self.saveScan) #add method to handle save scan button
        self.PacketList.doubleClicked.connect(self.handleItemDoubleClicked) #add method to handle clicks on the items in packet list
        self.setLineEditValidate() #call the method to set the validators for the QLineEdit for port and ip
        self.IPLineEdit.textChanged.connect(self.checkIPValidity) #connect signal for textChanged for IP to determine its validity
        self.initComboBox() #set the combobox interface names 
        self.center() #make the app open in center of screen
        self.show() #show the application
		

    #method for making the app open in the center of screen
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
    

    #method to check the IP Line edit validity in gui (using signals)
    def checkIPValidity(self):
        ip = self.IPLineEdit.text().strip() #get the ip user entered in gui

        if ip: #if ip is set, we check
            octets = ip.split('.') #splite the ip into 4 octets
            self.validIp = (len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets))  #check if ip is valid and not missing numbers (e.g 192.168.1.1)
        else: #else ip is empty so its not specified by user (optional)
            self.validIp = True #set the validIp flag to true
        if self.validIp: #if ip is valid we set the default style of the edit line lable
            style = "background-color: rgba(247, 247, 247,150); border-radius: 15px; border-style: outset; border-width: 2px; border-radius: 15px; border-color: black;	padding: 4px;"
            self.IPLineEdit.setStyleSheet(style)
        else: #else the user input is invalid, we show a red border on the edit line lable for error indication
            style = "background-color: rgba(247, 247, 247,150); border-radius: 15px; border-style: outset; border-width: 2px; border-radius: 15px; border-color: red; padding: 4px;"
            self.IPLineEdit.setStyleSheet(style)
    

    #method for setting the settings for ip and port line edit lables
    def setLineEditValidate(self):
        IPRegex = QRegExp("^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$") #regex for IP template (192.168.1.1)
        IPValidator = QRegExpValidator(IPRegex) #create the validator for ip using the regex
        portValidator = QIntValidator(0, 65535) #create a validator for port (number between 0 to 65535)
        self.IPLineEdit.setValidator(IPValidator) #set validator for IP
        self.IPLineEdit.setPlaceholderText('Optional') #set placeholder text for IP
        self.PortLineEdit.setValidator(portValidator) #set validaotr for port
        self.PortLineEdit.setPlaceholderText('Optional') #set placeholder text for port
    
    
    #method for setting the parameters for the interfaces combobox 
    def initComboBox(self):
        self.InterfaceComboBox.view().window().setWindowFlags(Qt.Popup | Qt.FramelessWindowHint)
        self.InterfaceComboBox.view().window().setAttribute(Qt.WA_TranslucentBackground)
        interfaces = getNetworkInterfaces() #call our method to receive the network interfaces
        if interfaces: #if not empty we add them to the combobox
            self.InterfaceComboBox.addItems(interfaces) #add items to combobox
        if len(interfaces) >= 2: #if we have more then one available interface 
            self.InterfaceComboBox.addItem('All') #we add "All" option to scan all available interfaces
            

    #method to handle the start scan button, initializing the packet sniffing
    def StartScanClicked(self):
        if self.packetCaptureThread is None or not self.packetCaptureThread.isRunning(): #checks if no thread is set for sniffer  
            try:
                packetFilter = self.packetFilter() #call packet filter for filtered dictionary based on check boxes state
                PortAndIP = self.getPortIP() #call the getPortId method to recevie the input for port and ip from user
            except (Exception, ValueError) as e: #if an exception is raised we show a messagebox for user with the error
                title = 'Format Error' if not self.validIp else 'Type Error'
                icon = 'Warning' if title == 'Format Error' else 'Critical'
                CustomMessageBox(title, str(e), icon)
                return #stop the initialization of scan
            self.ClearClicked() #call clear method for clearing the memory and screen for new scan
            self.handleCheckBoxes(False) #call our method for disabling the checkboxes
            interface = self.InterfaceComboBox.currentText() #get the chosen network interface from combobox
            if interface == '': #if the input is empty it means no availabe interface found
                CustomMessageBox('No Available Interface', 'Cannot find available network interface.', 'Critical', False) #show error message
                return #stop the initialization of scan
            if interface != 'All': #if true it means we need to scan on a specific interface
                self.packetCaptureThread = PacketCaptureThread(self.packetQueue, packetFilter, PortAndIP, interface) #initialzie the packet thread with the queue we initialized and interface
            else: #else user chose "All" option so we scan all available network interfaces
                self.packetCaptureThread = PacketCaptureThread(self.packetQueue, packetFilter, PortAndIP) #initialzie the packet thread without specifing a interface, we scan all interfaces
            self.packetCaptureThread.packetCaptured.connect(self.updatePacketList) #connect the packet thread to updatePacketList method
            self.packetCaptureThread.start() #calling the run method of the thread to start the scan
            self.StartScanButton.setEnabled(False) #set the scan button to be unclickable while scan in progress
        else: #else we show error message
            CustomMessageBox('Scan Running', 'Scan is already running!', 'Information', False)


    #method to handle the stop scan button, stops the packet sniffing
    def StopScanClicked(self):
        if self.packetCaptureThread is not None and self.packetCaptureThread.isRunning(): #checks if there is a running thread
            self.packetCaptureThread.stop() #calls stop method of the thread 
            self.packetCaptureThread.exit() #kills the thread 
            self.packetCaptureThread = None #setting the packetCaptureThread to None for next scan 
            self.handleCheckBoxes(True) #set the checkboxes to be enabled again
            self.StartScanButton.setEnabled(True) #set scan button back to being clickable
            CustomMessageBox('Scan Stopped', 'Packet capturing stopped.', 'Information', False)
    
    
    #method for saving scan data into a text file
    def saveScan(self):
        #if packet dictionary isn't empty and if there's no scan in progress we open the save window
        if any(packetDictionary.values()) and self.packetCaptureThread is None:
            defaultDirectory = os.path.join(os.path.expanduser('~'), 'Desktop') #set default directory to be desktop 
            if not os.path.exists(defaultDirectory): #if desktop directory isn't available we set it to home directory
                defaultDirectory = os.path.expanduser('~') #setting the default directory to be home directory
            defaultFilePath = os.path.join(defaultDirectory, 'Packet Scan') #we set the default file name, user can change that in dialog
            options = QFileDialog.Options() #this is for file options
            filePath, _ = QFileDialog.getSaveFileName(self, 'Save Scan Data', defaultFilePath, 'Text File (*.txt);;PCAP File (*.pcap)', options=options) #save the file in a specific path
            if filePath: #if user chose valid path we continue
                try: 
                    if filePath.endswith('.pcap'): #means user chose pcap file
                        packetList = [packet.getPacket() for packet in packetDictionary.values()] #we convert the packet dictionary to list for scapy wrpcap method
                        wrpcap(filePath, packetList) #call wrpcap method to write the captured packets into pcap file
                        CustomMessageBox('Scan Saved', 'Saved scan detalis to PCAP file.', 'Information', False) #notify the user for success
                    else: #else user chose a txt file
                        with open(filePath, 'w') as file: #we open the file for writing
                            for packet in packetDictionary.values(): #iterating over the packet dictionary to extract the info 
                                file.write('------------------------------------------------------------------------------------\n\n')
                                file.write(packet.moreInfo()) #write the packet info to the file (extended information)
                                file.write('------------------------------------------------------------------------------------\n\n')
                            CustomMessageBox('Scan Saved', 'Saved scan detalis to text file.', 'Information', False) #notify the user for success
                except Exception as e: #if error happend we print the error to terminal
                    print(f"Error occurred while saving: {e}")
            else: #else user didnt specify a file path
                CustomMessageBox('Save Error', 'You must choose a file type for saving!', 'Critical', False) #show message box with error
        elif self.packetCaptureThread is not None and self.packetCaptureThread.isRunning(): #if scan in progress we notify the user
            CustomMessageBox('Scan In Progress', 'Cannot save scan while in progress!', 'Information', False)
        else: #else we show a "saved denied" error if something happend
            CustomMessageBox('Save Denied', 'No scan data to save.', 'Information', False)


    def ClearClicked(self):
        global packetDictionary #declare global parameter for clearing packet dictionary
        global packetCounter #declare global parameter for resetting the packet counter
        if self.packetCaptureThread is None or (self.packetCaptureThread is not None and not self.packetCaptureThread.isRunning()):
            packetDictionary.clear() #clear the main packet dictionary
            packetCounter = 0 #reset the packet counter
            self.packetQueue = Queue() #clear the queue if there're packets in
            self.PacketList.model().clear() #clear the packet list in GUI
            self.MoreInfoTextEdit.setText('') #clear the extended information in GUI
        elif self.packetCaptureThread is not None and self.packetCaptureThread.isRunning():
            CustomMessageBox('Thread Running Error', 'Cannot clear while scan is in progress!', 'Warning', False)
        

    #method that checks all the check boxs state, return a string with filtered packets
    def packetFilter(self):
        #check each check box to filter the packet kinds
        packetFilter = ''
        if not self.HTTPCheckBox.isChecked():
            packetFilter += 'HTTP,'
        if not self.TLSCheckBox.isChecked():
            packetFilter += 'TLS,'
        if not self.TCPCheckBox.isChecked():
            packetFilter += 'TCP,'
        if not self.DNSCheckBox.isChecked():
            packetFilter += 'DNS,'
        if not self.UDPCheckBox.isChecked():
            packetFilter += 'UDP,'
        if not self.ICMPCheckBox.isChecked():
            packetFilter += 'ICMP,'
        if not self.ARPCheckBox.isChecked():
            packetFilter += 'ARP,'
        if not self.STPCheckBox.isChecked():
            packetFilter += 'STP,'
        #dicionary for packet kinds and their methods for handling:
        captureDictionary = {
        HTTP: handleHTTP,
        TLS: handleTLS,
        TCP: handleTCP,
        DNS: handleDNS,
        UDP: handleUDP,
        ICMP: handleICMP,
        ARP: handleARP,
        STP: handleSTP,
        }
        if packetFilter != '': #if packetFilter isn't empty it means we need to filter the dictionary 
            packetFilter.rstrip(',').split(',') #splite the original string to get a list of the packet types
            temp = captureDictionary.copy() #save the original dictionary in temp var
            for packetType, handler in temp.items(): #iterating on the dictionary to remove the filtered packets
                if packetType == TLS: #if true we need to strip a TLS packet string
                    p = str(packetType).split('.')[4].rstrip("'>") #strip the str representation of the TLS packet for extracting its name
                else: #else its a regular packet so we strip it 
                    p = str(packetType).split('.')[3].rstrip("'>") #strip the str representation of the packet for extracting its name
                if p in packetFilter: #if true we need to delete the packet type from the dictionary
                    del captureDictionary[packetType] #delete packet from dictionary
        if not captureDictionary: #if dictionary is empty we raise a new exception to indicate of an error 
            raise Exception('Error, you must choose at least one type for scan.')
        return captureDictionary
     

    #method that checks the ip and port line edit lables, if valid it returns the string representing the option, else raises a ValueError exception
    def getPortIP(self):
        output = ''
        if self.IPLineEdit.text() != '': #if true user typed a ip for us to search for 
            if not self.validIp: #if ip isnt valid we raise a ValueError exeption
                raise ValueError('Error, please enter a valid IP address in the format {xxx.xxx.xxx.xxx}.')
            else: #else the ip is valid we add it to output string
                output += f'(src {self.IPLineEdit.text()} or {self.IPLineEdit.text()})'
        if self.PortLineEdit.text() != '': #if user typed a port to seach for
            if output != '': #if true we need to divide the ip and port with 'add' word 
                output += ' and ' #add the word that divides the ip and port
            output += f'port {self.PortLineEdit.text()}' #add the port to the output
        return output


    #method for updating the packet list
    def updatePacketList(self):
        buffer = min(self.packetQueue.qsize(), 100) #buffer for the amount of packets to add at a time, min betweenn queue size and 100 packets
        if self.packetCaptureThread != None and not self.packetQueue.empty(): #we add packets when queue if not empty 
            while buffer > 0: #add the packets to packet list while buffer isn't empty 
                packetInfo = self.packetQueue.get() #taking a packet from the queue
                self.packetModel.appendRow(QStandardItem(packetInfo)) #adding to packet list in GUI
                buffer -= 1 #subtracting from buffer


    #method the double clicks in packet list, extended information section
    def handleItemDoubleClicked(self, index):
        packetIndex = index.row() #get the index of the row of the specific packet we want
        item = self.PacketList.model().itemFromIndex(index) #taking the packet from the list in GUI
        if item is not None and packetIndex in packetDictionary: #checking if the packet in GUI list isn't None 
            p = packetDictionary[packetIndex] #taking the matching packet from the packetDictionary
            self.MoreInfoTextEdit.setText(p.moreInfo()) #add the information to the extended information section in GUI
    
    
    #method to handle state of checkboxes, if state false we disable them, otherwise we enable them
    def handleCheckBoxes(self, state):
        if state: #if true we set the checkboxes and ip/port line edit to be enabled
            self.HTTPCheckBox.setEnabled(True)
            self.TLSCheckBox.setEnabled(True)
            self.TCPCheckBox.setEnabled(True)
            self.DNSCheckBox.setEnabled(True)
            self.UDPCheckBox.setEnabled(True)
            self.ICMPCheckBox.setEnabled(True)
            self.ARPCheckBox.setEnabled(True)
            self.STPCheckBox.setEnabled(True)
            self.IPLineEdit.setEnabled(True)
            self.PortLineEdit.setEnabled(True)
            self.InterfaceComboBox.setEnabled(True)
        else: #else we disable the checkboxes and ip/port line edit
            self.HTTPCheckBox.setEnabled(False)
            self.TLSCheckBox.setEnabled(False)
            self.TCPCheckBox.setEnabled(False)
            self.DNSCheckBox.setEnabled(False)
            self.UDPCheckBox.setEnabled(False)
            self.ICMPCheckBox.setEnabled(False)
            self.ARPCheckBox.setEnabled(False)
            self.STPCheckBox.setEnabled(False)
            self.IPLineEdit.setEnabled(False)
            self.PortLineEdit.setEnabled(False)
            self.InterfaceComboBox.setEnabled(False)
            
#---------------------------------------------------Application-END----------------------------------------------------#

#---------------------------------------------------CustomMessageBox----------------------------------------------------#
class CustomMessageBox(QDialog):
    def __init__(self, title, text, icon='NoIcon',wordWrap=True, width=400, height=150, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title) #set the title for message box
        self.setWindowFlags(Qt.Dialog | Qt.WindowTitleHint | Qt.CustomizeWindowHint | Qt.WindowCloseButtonHint) #set the window flags
        self.wordWrap = wordWrap #set the wordWrap for text
        self.setFixedSize(QSize(width, height)) #set the width and height for window
        self.initMessageBox(text, icon) #call initMessageBox for initializing the message box
        self.exec_() #execute the message box (show)

    def initMessageBox(self, text, icon):
        layout = QVBoxLayout() #create new layout
        horizontalLayout = QHBoxLayout() #create new horizontal layout
        textLabel = QLabel(text) #creat a text lable 
        textLabel.setAlignment(Qt.AlignCenter)  #set text alignment to center
        textLabel.setStyleSheet("font-size: 18px;") #set font size of text
        textLabel.setWordWrap(self.wordWrap) #set a wordWrap for better text representation

        if icon != 'NoIcon': #if true it means we need to set an icon for message box
            iconLabel = QLabel()
            if icon == 'Information':
                iconLabel.setPixmap(QApplication.style().standardIcon(QStyle.SP_MessageBoxInformation).pixmap(QSize(64, 64)))
                self.setWindowIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
            elif icon == 'Warning':
                iconLabel.setPixmap(QApplication.style().standardIcon(QStyle.SP_MessageBoxWarning).pixmap(QSize(64, 64)))
                self.setWindowIcon(self.style().standardIcon(QStyle.SP_MessageBoxWarning))
            elif icon == 'Critical':
                iconLabel.setPixmap(QApplication.style().standardIcon(QStyle.SP_MessageBoxCritical).pixmap(QSize(64, 64)))
                self.setWindowIcon(self.style().standardIcon(QStyle.SP_MessageBoxCritical))
            elif icon == 'Question':
                iconLabel.setPixmap(QApplication.style().standardIcon(QStyle.SP_MessageBoxQuestion).pixmap(QSize(64, 64)))
                self.setWindowIcon(self.style().standardIcon(QStyle.SP_MessageBoxQuestion))
            iconLabel.setAlignment(Qt.AlignLeft) #set the icon to the left
            spacer = QSpacerItem(10, 10, QSizePolicy.Fixed, QSizePolicy.Fixed) #create new spacer for the message box
            horizontalLayout.addWidget(iconLabel) #add the icon to layout
            horizontalLayout.addItem(spacer) #add the spacer to layout
            horizontalLayout.addWidget(textLabel) #add the text label to layout
        else: #else no need for an icon 
            horizontalLayout.addWidget(textLabel) #add only the text label to layout

        horizontalLayout.setAlignment(Qt.AlignCenter) #set alignment of horizontal layout
        layout.addLayout(horizontalLayout) #add the horizontal layout to the vertical layout
        OKButton = QPushButton('OK') #create new OK button
        layout.addWidget(OKButton, alignment=Qt.AlignCenter) #add the button to the layout
        style = """
            QPushButton {
                background-color: rgb(123, 180, 255);
                border: 2px solid black;
                border-radius: 15px;
                padding: 4px;
                font-size: 17px; 
                font-family: Arial; 
                min-width: 60px;  
                min-height: 20px;
            }
            QPushButton:hover {
                background-color: rgb(171, 201, 255);
            }
            QPushButton:pressed {
                background-color: rgb(96, 141, 199);
            }
        """
        OKButton.setStyleSheet(style) #set stylesheet for the OK button
        OKButton.clicked.connect(self.accept) #set an accept operation to the clicks of OK button
        self.setLayout(layout) #finally set the layout of the messsage box
#---------------------------------------------------CustomMessageBox-END----------------------------------------------------#

#-----------------------------------------------------------MAIN------------------------------------------------------------#

if __name__ == '__main__':
    #----------------APP----------------#
    app = QApplication(sys.argv)
    sniffer = PacketSniffer()
    try:
        sys.exit(app.exec_())
    except:
        print('Exiting')
    #----------------APP----------------#
    #GetAvailableInterfaces()

#-----------------------------------------------------------MAIN-END---------------------------------------------------------#

