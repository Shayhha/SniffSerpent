import sys, os, re, logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from abc import ABC, abstractmethod
from urllib.parse import unquote
from scapy.all import AsyncSniffer, wrpcap, rdpcap, get_if_list, Packet, IP, IPv6, TCP, UDP, ICMP, ARP, Raw 
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSClientKeyExchange, TLSServerKeyExchange, TLSNewSessionTicket
from scapy.contrib.igmp import IGMP
from scapy.layers.l2 import STP
from interface.ui_SniffSerpent import Ui_SniffSerpent
from PySide6.QtCore import QObject, Signal, Slot, Qt, QTimer, QStandardPaths, QRegularExpression, QThread, QModelIndex
from PySide6.QtGui import QGuiApplication, QIcon, QCursor, QStandardItem, QStandardItemModel, QRegularExpressionValidator
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QDialog, QFileDialog, QLabel, QPushButton, QStyle, QVBoxLayout, QHBoxLayout, QHBoxLayout
from PySide6.QtNetwork import QLocalServer, QLocalSocket


#------------------------------------------------------Default_Packet-------------------------------------------------------#
class Default_Packet(ABC): #abstarct class for default packet
    name: str = None #represents the packet name
    packet: Packet = None #represents the packet object itself for our use later
    packetType: Packet = None #represents the packet type based on scapy known types
    id: int = None #represents the id for the packet object, for ease of use in dictionary later

    def __init__(self, name: str=None, packet: Packet=None, id: int=None) -> None: #ctor for default packet 
        self.name = name
        self.packet = packet
        self.id = id
        

    #get method for packet object
    def GetPacket(self) -> Packet:
        return self.packet #return the packet object


    #get method for id
    def GetId(self) -> int: 
        return self.id #return the id


    #set method for id
    def SetId(self, id: int) -> None:
        self.id = id #set the id


    #method for raw info capture
    def RawInfo(self) -> str:
        output = ''
        if Raw in self.packet: #insert payload data (if available)
            payload = self.packet[Raw].load #get payload data from packet
            output += f'Payload Data: {payload.hex()}\n\n' #insert payload as hexadecimal
        return output
    

    #method that handles a long string and makes it fit in the GUI 
    def FitStr(self, label: str, info: int | str | bytes | list) -> str: 
        output = ''
        if info != None: #if info not none we continue
            if isinstance(info, bytes): #if given info is byte we convert it to utf-8 string
                info = info.decode('utf-8', 'replace') #decode the byte to string
            elif isinstance(info, list): #if given info is list we convert it to utf-8 string
                info = ', '.join(item.decode('utf-8', 'replace') if isinstance(item, bytes) else str(item) for item in info) #decode the list into string
            info = info.rstrip('.') #remove trailing dot if present
            if len(info) >= 52: #if the string is longer then specified length we add a new line
                temp = '\n'.join(info[i:i+52] for i in range(0, len(info), 52)) #iterating over the string and adding new line after specified amount of characters
                output += f'{label}\n{temp}\n\n' #insert to the output 
            elif len(f'{label}: {info}') >= 52: #if the info string and st string togther exceed the specified characters we add new line
                output += f'{label}\n{info}\n\n' #insert to the output
            else: #else info and st strings are not exceeding the specifed amount of characters
                output += f'{label} {info}\n\n' #we add the original info and st strings to the output without a new line
        else: #else info is none
            output += f'{label} {info}\n\n' #add to output the value with none value 
        return output


    #method for retrieving login credentials from http packet
    def LoginInfo(self) -> dict:
        credentials = {} #credentials dictionary for username and password
        httpRegex = lambda key: rf'{key}=([^&]+)' #regex for http payload template, regex that ends in & at the end (if present)
        #list for usernames and password labels that are common in http payloads
        usernames = ['username', 'Username', 'UserName', 'user', 'User', 'uname', 'Uname', 'usr', 'Usr', 'email', 'Email', 'login', 'Login', 'usrname', 'Usrname', 'uid', 'Uid']
        passwords = ['password', 'Password', 'pass', 'Pass', 'pwd', 'Pwd', 'passwd', 'Passwd', 'pswd', 'psw', 'secret', 'Secret', 'secure', 'Secure', 'key', 'Key', 'auth', 'Auth']
        if self.packet.haslayer(Raw) and self.packet.haslayer(HTTPRequest): #if true we have http request packet and it has a payload
            payload = self.packet[Raw].load.decode('utf-8', 'replace') #we decode the payload of the packet 
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
    def IpInfo(self) -> str: 
        output = ''
        if self.packet.haslayer(IP): #if packet has ip layer
            srcIp = self.packet[IP].src #represents the source ip
            dstIp = self.packet[IP].dst #represents the destination ip
            ttl = self.packet[IP].ttl #represents ttl parameter in packet
            dscp = self.packet[IP].tos #represents dscp parameter in packet
            output += self.FitStr('Source IP:', srcIp) #insert source ip to output
            output += self.FitStr('Destination IP:', dstIp) #insert denstination ip to output
            output += f'TTL: {ttl}, DSCP: {dscp}\n\n' #add both to output
        elif self.packet.haslayer(IPv6): #if packet has ipv6 layer
            srcIp = self.packet[IPv6].src #represents the source ip
            dstIp = self.packet[IPv6].dst #represents the destination ip
            hopLimit = self.packet[IPv6].hlim #represents the hop limit parameter in packet
            trafficClass = self.packet[IPv6].tc #represnets the traffic class in packet
            output += self.FitStr('Source IP:', srcIp) #insert source ip to output
            output += self.FitStr('Destination IP:', dstIp) #insert denstination ip to output
            output += f'Hop Limit: {hopLimit}, Traffic Class: {trafficClass}\n\n' #add them both to output
        if hasattr(self.packet, 'chksum') and not self.packet.haslayer(IGMP): #if packet has checksum parameter (IGMP has its own)
            output += f'Checksum: {self.packet.chksum}\n\n' #we add the checksum to output
        output += f'Packet Size: {len(self.packet)} bytes\n\n' #add the packet size to output
        return output


    #method representing the packet briefly, derived classes may need to implement for different types
    def Info(self) -> str: 
        output = '' #output string for information of packet
        srcMac = self.packet.src #represents the source mac address
        dstMac = self.packet.dst #represents the destination mac address
        srcPort = '' #source port of packet
        dstPort = '' #destination port of packet
        packetSize = len(self.packet) #size of the packet

        if self.packet.haslayer(TCP) or self.packet.haslayer(UDP): #if packet is tcp or udp we get port info
            srcPort = self.packet.sport #represents the source port of packet
            dstPort = self.packet.dport #represents the destination port of packet
            if self.packet.haslayer(IP): #if packet have ip address so we print the packet info with ip and port
                srcIp = self.packet[IP].src #represents the source ip of packet
                dstIp = self.packet[IP].dst #represents the destination ip of packet
                output += f'{self.name} Packet: ({srcIp}):({srcPort}) --> ({dstIp}):({dstPort})' #insert info to output
            elif self.packet.haslayer(IPv6): #if packet have ipv6 address so we print the packet info with ip and port
                srcIp = self.packet[IPv6].src #represents the source ip of packet
                dstIp = self.packet[IPv6].dst #represents the destination ip of packet
                output += f'{self.name} Packet: ({srcIp}):({srcPort}) --> ({dstIp}):({dstPort})' #insert info to output
            else: #else no ip layer 
                output += f'{self.name} Packet: ({srcMac}):({srcPort}) --> ({dstMac}):({dstPort})' #insert info without ip to output
        if self.packet.haslayer(HTTP) and (self.packet.haslayer(HTTPResponse) or self.packet.haslayer(HTTPRequest)): #if true packet is http
            if self.packet.haslayer(HTTPRequest) and self.LoginInfo(): #if true it means we have a login request http packet (with username and password)
                output += ' Type: Login Request' #add http login request type to ouput
            else: #else its a regular request or response http packet
                output += f' Type: {"Response" if self.packet.haslayer(HTTPResponse) else "Request"}' #add http type, response or request
        if self.packet.haslayer(DHCP): #if packet is DHCP 
            output += ' Type: Discover' if self.packet[DHCP].options[0][1] == 1 else '' #add type if discover
            output += ' Type: Offer' if self.packet[DHCP].options[0][1] == 2 else '' #add type if offer
            output += ' Type: Request' if self.packet[DHCP].options[0][1] == 3 else '' #add type if request
            output += ' Type: Acknowledge' if self.packet[DHCP].options[0][1] == 5 else '' #add type if acknowledge
            output += ' Type: Release' if self.packet[DHCP].options[0][1] == 7 else '' #add type if release
            output += ' Type: Info' if self.packet[DHCP].options[0][1] == 8 else '' #add type if info
        output += f' | Size: {packetSize} bytes' #insert packet size to output
        return output


    #method that represents the packet information more deeply, for derived classes to implement further
    def MoreInfo(self) -> str:
        output = '' #output string for info
        if self.packet.haslayer(TCP) or self.packet.haslayer(UDP): #if packet is tcp or udp
            output += f'{self.name} Packet:\n\n' #insert packet name to output
            output += f'Source Port: {self.packet.sport}\n\n' #insert source port to output
            output += f'Destination Port: {self.packet.dport}\n\n' #insert destination port to output
        else: #else its other packet type
            output += f'{self.name} Packet:\n\n' #insert packet name to output
            output += f'Source MAC: {self.packet.src}\n\n' #insert packet source mac address
            output += f'Destination MAC: {self.packet.dst}\n\n' #insert packet destination mac address
        output += self.IpInfo() #call ip method to add neccessary info if ip layer is present
        return output

#----------------------------------------------------Default_Packet-END-----------------------------------------------------#

#-----------------------------------------------------------TCP-------------------------------------------------------------#
class TCP_Packet(Default_Packet):
    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for tcp packet
        super().__init__('TCP', packet, id) #call parent ctor
        if packet.haslayer(TCP): #checks if packet is TCP
            self.packetType = TCP #specify the packet type


    #method for packet information
    def MoreInfo(self) -> str: 
        output = f'{super().MoreInfo()}' #call parent MoreInfo method
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
        output += f'Window Size: {self.packet.window} bytes\n\n' #add window size parameter to output
        output += 'Flags:\n' #add the flags to output
        temp = '' #temp string for our use 
        for flag, value in flagsDict.items(): #iteration over the flags in tcp packet
            if flag == 'ACK': #if flag is ACK we add new line for clean gui representation
                temp += '\n' #add new line to temp
            temp += f'{flag}: {value}, ' #add the current flag with its value
        output += temp.rstrip(', ') #finally insert the flags to output 
        output += '\n\n'
        if self.packet[self.packetType].options: #add TCP Options (if available)
            output += 'TCP Options:\n' #insert the tcp options to output
            temp = '' #initializing temp to an empty string
            for option in self.packet[self.packetType].options: #iteration over the options list
                temp += f'{option[0]}: {option[1]}, ' #add the options to temp
            output += temp.rstrip(', ') #strip the output for leading comma
            output += '\n\n'
        return output

#---------------------------------------------------------TCP-END-----------------------------------------------------------#

#-----------------------------------------------------------UDP-------------------------------------------------------------#
class UDP_Packet(Default_Packet):
    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for udp packet 
        super().__init__('UDP', packet, id) #call parent ctor
        if packet.haslayer(UDP): #checks if packet is UDP
            self.packetType = UDP #add packet type


#---------------------------------------------------------UDP-END-----------------------------------------------------------#

#-----------------------------------------------------------HTTP------------------------------------------------------------#
class HTTP_Packet(Default_Packet):
    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for http packet
        super().__init__('HTTP', packet, id) # call parent ctor
        if packet.haslayer(HTTP): #checks if packet is HTTP
            self.packetType = HTTP #add packet type


    #method for packet information
    def MoreInfo(self) -> str:
        output = super().MoreInfo() #call parent MoreInfo method
        if self.packet.haslayer(HTTP): #if packet has HTTP layer
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
                output += f'Content Length: {contentLength} bytes\n\n' #add content length to output
                output += self.FitStr('Server:', server) #add server of packet to output

            elif self.packet.haslayer(HTTPRequest): #if the packet is request
                httpLogin = self.LoginInfo() #call LoginInfo method to get login credentials (if available)
                httpVersion = headers.get('Http_Version') #get the http version of packet
                method = httpPacket.Method.decode() #get the method name of request packet
                url = httpPacket.Host.decode() + httpPacket.Path.decode() #get the url of the request packet
                accept = headers.get('Accept') #get the accept info of request
                referer = headers.get('Referer') #get the referer of request
                output += 'Type: Login Request\n\n' if httpLogin else 'Type: Request\n\n' #add type of packet to output based on http info
                output += f'HTTP Version: {httpVersion}\n\n' #add http version to output
                output += f'Method: {method}\n\n' #add method to output
                output += self.FitStr('URL:', url) #add url to output
                if httpLogin: #if true we have captured login information
                    output += 'Login Credentials:\n\n' #add login credentials to output
                    output += self.FitStr('Username:', httpLogin['username']) #add usernname from our httpLogin dict
                    output += self.FitStr('Password:', httpLogin['password']) #add password from our httpLogin dict
                output += self.FitStr('Accept:', accept) #add accept to output
                output += self.FitStr('Referer:', referer) #add referer to output
        return output
    
#---------------------------------------------------------HTTP-END----------------------------------------------------------#

#-----------------------------------------------------------DNS-------------------------------------------------------------#
class DNS_Packet(Default_Packet):
    DNSRecordTypes: dict = {
        1: 'A', 28: 'AAAA', 18: 'AFSDB', 42: 'APL', 257: 'CAA', 60: 'CDNSKEY', 59: 'CDS', 37: 'CERT', 5: 'CNAME', 62: 'CSYNC',
        49: 'DHCID', 32769: 'DLV', 39: 'DNAME', 48: 'DNSKEY', 43: 'DS', 108: 'EUI48', 109: 'EUI64', 13: 'HINFO', 55: 'HIP',
        65: 'HTTPS', 45: 'IPSECKEY', 25: 'KEY', 36: 'KX', 29: 'LOC', 15: 'MX', 35: 'NAPTR', 2: 'NS', 47: 'NSEC', 50: 'NSEC3',
        51: 'NSEC3PARAM', 61: 'OPENPGPKEY', 12: 'PTR', 17: 'RP', 46: 'RRSIG', 24: 'SIG', 53: 'SMIMEA', 6: 'SOA', 33: 'SRV',
        44: 'SSHFP', 64: 'SVCB', 32768: 'TA', 249: 'TKEY', 52: 'TLSA', 250: 'TSIG', 16: 'TXT', 256: 'URI', 63: 'ZONEMD', 255: 'ANY'}
    
    DNSClassTypes: dict = {1: 'IN', 2: 'CS', 3: 'CH', 4: 'HS', 255: 'ANY', 254: 'NONE', 32769: 'DLV'}

    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for dns packet
        super().__init__('DNS', packet, id) #call parent ctor
        if packet.haslayer(DNS): #checks if packet is DNS
            self.packetType = DNS #add packet type


    #method for brief packet information
    def Info(self) -> str:
        output = '' #output string for information of packet
        dnsPacket = self.packet[DNS] #parameter for dns packet
        srcMac = self.packet.src #representst the source mac address
        dstMac = self.packet.dst #represents the destination mac address
        srcIp = '' #represents the source ip address
        dstIp = '' #represents the destination ip address
        srcPort = '' #represents the source port
        dstPort = '' #represents the destination port
        packetSize = len(self.packet) #represenets the packet size

        if self.packet.haslayer(TCP) or self.packet.haslayer(UDP): #if dns packet transmitted through tcp or udp 
            srcPort = self.packet.sport #set the source port
            dstPort = self.packet.dport #set the destination port
            if self.packet.haslayer(IP): #if packet has ip layer
                srcIp = self.packet[IP].src #set the source ip
                dstIp = self.packet[IP].dst #set the destination ip
                output += f'{self.name} Packet: ({srcIp}):({srcPort}) --> ({dstIp}):({dstPort})' #add the info with ip to output
            elif self.packet.haslayer(IPv6): #else packet has ipv6 layer
                srcIp = self.packet[IPv6].src #set the source ip
                dstIp = self.packet[IPv6].dst #set the destination ip
                output += f'{self.name} Packet: ({srcIp}):({srcPort}) --> ({dstIp}):({dstPort})' #add the info with ip to output
            else: #else no ip layer 
                output += f'{self.name} Packet: ({srcMac}):({srcPort}) --> ({dstMac}):({dstPort})' #insert info without ip to output

        output += f' Type: {"Response" if dnsPacket.qr == 1 else "Request"}' #add the dns type, response or request
        
        if dnsPacket.an and dnsPacket.ancount > 0: #check if its response packet
            dnsResponseType = self.DNSRecordTypes[dnsPacket.an[0].type] if dnsPacket.an[0].type in self.DNSRecordTypes else dnsPacket.an[0].type #represents dns record type based on the DNSRecordTypes dictionary
            output += f' {dnsResponseType}' #add response record type
        elif dnsPacket.qd and dnsPacket.qdcount > 0: #else we check if its request packet
            dnsRequestType = self.DNSRecordTypes[dnsPacket.qd[0].qtype] if dnsPacket.qd[0].qtype in self.DNSRecordTypes else dnsPacket.qd[0].qtype #represents dns record type based on the DNSRecordTypes dictionary
            output += f' {dnsRequestType}' #add request record type
            
        output += f' | Size: {packetSize} bytes' #add the size of the packet
        return output


    #method for packet information
    def MoreInfo(self) -> str:
        output = super().MoreInfo() #call parent MoreInfo method
        if self.packet.haslayer(DNS): #if packet has DNS layer
            dnsPacket = self.packet[DNS] #save the dns packet in parameter
            output += f'ID: {dnsPacket.id}\n\n' #id of the dns packet
            if dnsPacket.qr == 1: #means its a response packet
                if dnsPacket.an and dnsPacket.ancount > 0: #if dns packet is response packet
                    dnsResponseType = self.DNSRecordTypes[dnsPacket.an[0].type] if dnsPacket.an[0].type in self.DNSRecordTypes else dnsPacket.an[0].type #represents dns record type based on the DNSRecordTypes dictionary
                    dnsResponseClass = self.DNSClassTypes[dnsPacket.an[0].rclass] if dnsPacket.an[0].rclass in self.DNSClassTypes else dnsPacket.an[0].rclass #represents dns class type based on the DNSClassTypes dictionary
                    output += f'Type: Response\n\n' #add type of packet to output
                    output += self.FitStr('Response Name:', dnsPacket.an[0].rrname) #add repsonse name to output
                    output += f'Response Type: {dnsResponseType}, ' #add response type to output
                    output += f'Response Class: {dnsResponseClass}\n\n' #add response class to output
                    output += f'Response Count: {dnsPacket.ancount}\n\n' #add number of responses to output
                    if hasattr(dnsPacket.an[0], 'rdata'): #check if rdata attribute exists
                        output += self.FitStr('Response Data:', dnsPacket.an[0].rdata) #specify the rdata parameter
            else: #means its a request packet
                if dnsPacket.qd and dnsPacket.qdcount > 0:
                    dnsRequestType = self.DNSRecordTypes[dnsPacket.qd[0].qtype] if dnsPacket.qd[0].qtype in self.DNSRecordTypes else dnsPacket.qd[0].qtype #represents dns record type based on the DNSRecordTypes dictionary
                    dnsRequestClass = self.DNSClassTypes[dnsPacket.qd[0].qclass] if dnsPacket.qd[0].qclass in self.DNSClassTypes else dnsPacket.qd[0].qclass #represents dns class type based on the DNSClassTypes dictionary
                    output += f'Type: Request\n\n' #add type of packet to output
                    output += self.FitStr('Request Name:', dnsPacket.qd[0].qname) #add request name to output
                    output += f'Request Type: {dnsRequestType}, ' #add request type to output
                    output += f'Request Class: {dnsRequestClass}\n\n' #add request class to output
                    output += f'Request Count: {dnsPacket.qdcount}\n\n' #add num of requests to output
        return output

#---------------------------------------------------------DNS-END-----------------------------------------------------------#

#-----------------------------------------------------------TLS-------------------------------------------------------------#
class TLS_Packet(Default_Packet):
    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for tls packet
        super().__init__('TLS', packet, id) #call parent ctor
        if packet.haslayer(TLS): #checks if packet is TLS
            self.packetType = TLS #add packet type
    
    
    #method for packet information
    def MoreInfo(self) -> str:
        output = super().MoreInfo() #call parent MoreInfo method
        if self.packet.haslayer(TLS): #if packet has TLS layer
            tlsPacket = self.packet[TLS] #save the TLS packet in parameter
            output += f'Version: {tlsPacket.version}\n\n' #version of the TLS packet
            if self.packet.haslayer(TLSClientHello): #if true the packet is a client hello response
                output += f'Handshake Type: Client Hello\n\n' #add handshake type to output
                output += f'Length: {self.packet[TLSClientHello].msglen} bytes\n\n' #add length to output
                output += self.FitStr('Cipher Suites:', self.packet[TLSClientHello].ciphers) #add cipher suites list to output
            elif self.packet.haslayer(TLSServerHello): #if true the packet is a server hello response
                output += f'Handshake Type: Server Hello\n\n' #add handshake tyoe to output
                output += f'Length: {self.packet[TLSServerHello].msglen} bytes\n\n' #add length to output
                output += f'Cipher Suite: {self.packet[TLSServerHello].cipher}\n\n' #add cipher suite number to output
            elif self.packet.haslayer(TLSClientKeyExchange): #if true the packet is a client key exchange response
                output += f'Handshake Type: Client Key Exchange\n\n' #add handshake tyoe to output
                output += f'Length: {self.packet[TLSClientKeyExchange].msglen} bytes\n\n' #add length to output
            elif self.packet.haslayer(TLSServerKeyExchange): #if true the packet is a server key exchange response
                output += f'Handshake Type: Server Key Exchange\n\n' #add handshake tyoe to output
                output += f'Length: {self.packet[TLSServerKeyExchange].msglen} bytes\n\n' #add length to output
            elif self.packet.haslayer(TLSNewSessionTicket): #if true the packet is a new session ticket response
                output += f'Handshake Type: New Session Ticket\n\n' #add handshake tyoe to output
                output += f'Length: {self.packet[TLSNewSessionTicket].msglen} bytes\n\n' #add length to output
        return output
    
#---------------------------------------------------------TLS-END-----------------------------------------------------------#

#-----------------------------------------------------------ICMP------------------------------------------------------------#
class ICMP_Packet(Default_Packet):
    icmpTypes: dict = { 
        0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench', 5: 'Redirect', 8: 'Echo Request', 9: 'Router Advertisement',
        10: 'Router Selection', 11: 'Time Exceeded', 12: 'Parameter Problem', 13: 'Timestamp', 14: 'Timestamp Reply', 15: 'Information Request',
        16: 'Information Reply', 17: 'Address Mask Request', 18: 'Address Mask Reply'}
    
    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for icmp packet
        super().__init__('ICMP', packet, id) #call parent ctor
        if packet.haslayer(ICMP): #checks if packet is icmp
            self.packetType = ICMP #add packet type

    
    #method for brief packet information
    def Info(self) -> str:
        output = ''
        packetSize = len(self.packet) #represent the packet size
        icmpType = self.icmpTypes[self.packet[ICMP].type] if self.packet[ICMP].type in self.icmpTypes else self.packet[ICMP].type #represents icmp type based on the icmpTypes dictionary
        icmpCode = self.packet[ICMP].code #represents icmp code
        if self.packet.haslayer(IP): #if packet has ip layer
            srcIp = self.packet[IP].src #represents the source ip
            dstIp = self.packet[IP].dst #represents the destination ip
            output += f'{self.name} Packet: ({srcIp}) --> ({dstIp}) | Type: {icmpType}, Code: {icmpCode} | Size: {packetSize} bytes' #add to output the packet info with ip
        elif self.packet.haslayer(IPv6): #if packet has ipv6 layer
            srcIp = self.packet[IPv6].src #represents the source ip
            dstIp = self.packet[IPv6].dst #represents the destination ip
            output += f'{self.name} Packet: ({srcIp}) --> ({dstIp}) | Type: {icmpType}, Code: {icmpCode} | Size: {packetSize} bytes' #add to output the packet info with ip
        else:
            output += f'{self.name} Packet: Type: {icmpType}, Code: {icmpCode} | Size: {packetSize} bytes' #add to output the packet info 
        return output


    #method for packet information
    def MoreInfo(self) -> str: 
        output = ''
        if self.packet.haslayer(ICMP): #if packet has icmp layer
            icmpType = self.icmpTypes[self.packet[ICMP].type] if self.packet[ICMP].type in self.icmpTypes else self.packet[ICMP].type #represents icmp type based on the icmpTypes dictionary
            icmpCode = self.packet[ICMP].code #represents icmp code
            icmpSeq = self.packet[ICMP].seq #represents icmp sequence number
            icmpId = self.packet[ICMP].id #represents icmp identifier
            output += f'{self.name} Packet:\n\n' #add packet name to output
            output += self.IpInfo() #call ip method for more ip info
            output += f'Type: {icmpType}\n\n' #add icmp type to output
            output += f'Code: {icmpCode}\n\n' #add icmp code to output
            output += f'Sequence Number: {icmpSeq}\n\n' #add icmp sequence number
            output += f'Identifier: {icmpId}\n\n' #add icmp identifier
        return output

#---------------------------------------------------------ICMP-END----------------------------------------------------------#

#-----------------------------------------------------------DHCP------------------------------------------------------------#
class DHCP_Packet(Default_Packet):
    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for dhcp packet
        super().__init__('DHCP', packet, id) #call parent ctor
        if packet.haslayer(DHCP): #if packet is DHCP
            self.packetType = DHCP #set packet type


    #method to retreive the option from the options list in DHCP packet
    def GetOption(self, parameter: str) -> str | list | None:
        for option in self.packet[DHCP].options: #if true the packet is DHCP
            if option[0] == parameter: # if true we found a valid parameter in the list
                if parameter == 'name_server' and len(option) > 2: #if DHCP returned multiple name servers 
                    return ', '.join(option[1:]) #return all names with a comma seperating them
                elif isinstance(option[1], bytes): #if parameter is bytes
                    return option[1].decode() #we return the decoded parameter
                else: #else we return the parameter in the list
                    return option[1] #return the value in the tuple in list
        return None #else we return none if parameter is'nt in the list


    #method for packet information
    def MoreInfo(self) -> str:
        output = super().MoreInfo() #call parent MoreInfo method
        if self.packet.haslayer(DHCP): #if true its a DHCP packet
            dhcpPacket = self.packet[DHCP] #set the DHCP packet in variable
            if dhcpPacket.options[0][1] == 1 or dhcpPacket.options[0][1] == 3: #if true its a dicovery/request DHCP packet
                hostname = self.GetOption('hostname') #get the hostname from options
                serverID = self.GetOption('server_id') #get the server id from options
                requestedAddress = self.GetOption('requested_addr') #get the requested address from options
                vendorClassID = self.GetOption('vendor_class_id') #get vendor class id from options
                paramReqList = self.GetOption('param_req_list') #get parameter request list from options
                output += f'DHCP Type: Discover\n\n' if dhcpPacket.options[0][1] == 1 else f'DHCP Type: Request\n\n' #add type of DHCP, discovery or request
                output += f'Host Name: {hostname}\n\n' if hostname else '' #add hostname to output
                output += f'Server ID: {serverID}\n\n' if dhcpPacket.options[0][1] == 3 and serverID else '' #add server id to output
                output += f'Requested Address: {requestedAddress}\n\n' if requestedAddress else '' #add requested addresses to outpit
                output += f'Vendor Class ID: {vendorClassID}\n\n' if vendorClassID else '' #add vendor class id to output
                output += self.FitStr('Parameter Request list:', ', '.join(map(str, paramReqList))) if paramReqList else '' #add parameter request list to output
            elif dhcpPacket.options[0][1] == 2 or dhcpPacket.options[0][1] == 5: #if true its a offer/aknowledge DHCP packet
                subnetMask = self.GetOption('subnet_mask') #get subnet mask from options
                broadcastAddress = self.GetOption('broadcast_address') #get boradcast address from options
                leaseTime = self.GetOption('lease_time') #get lease time from options
                router = self.GetOption('router') #get router from options
                serverName = self.GetOption('name_server') #get server name from options
                output += f'DHCP Type: Offer\n\n' if dhcpPacket.options[0][1] == 2 else f'DHCP Type: Acknowledge\n\n' #add type of DHCP, offer or acknowledge
                output += f'Subnet Mask: {subnetMask}\n\n' if subnetMask else '' #add subnet mask to output
                output += f'Broadcast Address: {broadcastAddress}\n\n' if broadcastAddress else '' #add broadcast address to output
                output += f'Lease Time: {leaseTime}\n\n' if leaseTime else '' #add lease time to output
                output += f'Router Address: {router}\n\n' if router else '' #add router address to output
                output += f'Offered Address: {self.packet[BOOTP].yiaddr}\n\n' if dhcpPacket.options[0][1] == 2 else f'Acknowledged Address: {self.packet[BOOTP].yiaddr}\n\n' #add specific info about the packet
                output += self.FitStr('Server Name:', serverName) if serverName else '' #add server name to output
            elif dhcpPacket.options[0][1] == 7: #if true its a release DHCP packet
                serverID = self.GetOption('server_id') #get server id from options
                output += f'DHCP Type: Release\n\n' #add type to output
                output += f'Server ID: {serverID}\n\n' if serverID else '' #add server id to output
            elif dhcpPacket.options[0][1] == 8: #if true its a information DHCP packet
                hostname = self.GetOption('hostname') #get hostname from output
                vendorClassID = self.GetOption('vendor_class_id') #get vendor class id from options
                output += f'DHCP Type: Information\n\n' #add type to output
                output += f'Host Name: {hostname}\n\n' if hostname else '' #add hostname to output
                output += f'Vendor Class ID: {vendorClassID}\n\n' if vendorClassID else '' #add vendor class id to output
        return output
    
#----------------------------------------------------------DHCP-END---------------------------------------------------------#

# -----------------------------------------------------------ARP------------------------------------------------------------#
class ARP_Packet(Default_Packet):
    hardwareTypes: dict = {
        1: 'Ethernet', 4: 'Ethernet II', 6: 'IEEE 802 (Token Ring)', 8: 'ArcNet', 15: 'Frame Relay', 17: 'ATM',
        18: 'HDLC', 23: 'IEEE 802.11 (Wi-Fi)', 32: 'Fibre Channel', 41: 'InfiniBand', 42: 'IPv6 over Ethernet', 512: 'PPP'}

    protocolTypes: dict = {
        1: 'Ethernet', 2045: 'VLAN Tagging (802.1Q)', 2046: 'RARP', 2048: 'IPv4', 2049: 'X.25', 2054: 'ARP', 32902: 'RARP', 33058: 'AppleTalk (Appletalk AARP)', 
        33079: 'AppleTalk', 34304: 'PPP', 4525: 'IPv6', 34887: 'PPPoE Discovery', 35020: 'MPLS', 35023: 'PPPoE (PPP over Ethernet)', 35048: 'MPLS Multicast', 35117: 'PPPoE Session'}

    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for arp packet
        super().__init__('ARP', packet, id) #call parent ctor
        if packet.haslayer(ARP): #checks if packet is arp
            self.packetType = ARP #add packet type
    

    #method for brief packet information
    def Info(self) -> str:
        output = ''
        srcMac = self.packet[ARP].hwsrc #represents arp source mac address
        srcIp = self.packet[ARP].psrc #represents arp source ip address
        dstMac = self.packet[ARP].hwdst #represents arp destination mac address
        dstIp = self.packet[ARP].pdst #represents arp destination ip address
        arpOperation = 'Request' if self.packet[ARP].op == 1 else 'Response' #represents arp operation
        packetSize = len(self.packet) #represents the packet size 
        output += f'{self.name} Packet: ({srcIp}):({srcMac}) --> ({dstIp}):({dstMac}) Type: {arpOperation} | Size: {packetSize} bytes' #add the packet info to output
        return output


    #method for packet information
    def MoreInfo(self) -> str:
        output = ''
        if self.packet.haslayer(ARP): #if packet has layer of arp
            hardwareType = self.hardwareTypes[self.packet[ARP].hwtype] if self.packet[ARP].hwtype in self.hardwareTypes else self.packet[ARP].hwtype #represents hardware type based on the hardwareTypes dictionary
            protocolType = self.protocolTypes[self.packet[ARP].ptype] if self.packet[ARP].ptype in self.protocolTypes else self.packet[ARP].ptype #represents protocol type based on the protocolTypes dictionary
            output += f'{self.name} Packet:\n\n' #add packet name to output
            output += f'Source MAC: {self.packet[ARP].hwsrc}\n\n' #add arp source mac address
            output += f'Destination MAC: {self.packet[ARP].hwdst}\n\n' #add arp destination mac address
            output += f'Source IP: {self.packet[ARP].psrc}\n\n' #add arp source ip address
            output += f'Destination IP: {self.packet[ARP].pdst}\n\n' #add arp destination ip address
            output += f'Packet Size: {len(self.packet)} bytes\n\n' #add packet size
            output += f'Operation: {"Request" if self.packet[ARP].op == 1 else "Response"}\n\n' #add the arp operation to output
            output += f'Hardware Type: {hardwareType}\n\n' #add the hardware type to output
            output += f'Hardware Length: {self.packet[ARP].hwlen} bytes\n\n' #add hardware length to output
            output += f'Protocol Type: {protocolType}\n\n' #add protocol type to output
            output += f'Protocol Length: {self.packet[ARP].plen} bytes\n\n' #add protocol length to output
        return output
        
#-----------------------------------------------------------ARP-END---------------------------------------------------------#

#-----------------------------------------------------------IGMP------------------------------------------------------------#
class IGMP_Packet(Default_Packet):
    igmpTypes: dict = {
        17: 'Membership Query', 18: 'Membership Report v1', 22: 'Membership Report v2', 23: 'Leave Group', 30: 'Membership Report v3',
        31: 'Multicast Router Advertisement', 32: 'Multicast Router Solicitation', 33: 'Multicast Router Termination'}

    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for igmp packet
        super().__init__('IGMP', packet, id) #call parent ctor
        if packet.haslayer(IGMP): #checks if packet is IGMP
            self.packetType = IGMP #add pacet type
            

    #method for brief packet information
    def Info(self) -> str:
        output = ''
        srcMac = self.packet.src #represents the source mac address
        dstMac = self.packet.dst #represents the destination mac address
        packetSize = len(self.packet) #size of the packet
        igmpType = self.igmpTypes[self.packet[IGMP].type] #represents the igmp type
        if self.packet.haslayer(IP): #if packet have ip address so we add the packet info with ip and type
            srcIp = self.packet[IP].src #represents the source ip of packet
            dstIp = self.packet[IP].dst #represents the destination ip of packet
            output += f'{self.name} Packet: ({srcIp}) --> ({dstIp}) Type: {igmpType} | Size: {packetSize} bytes' #insert info to output
        elif self.packet.haslayer(IPv6):  #if packet have ipv6 address so we add the packet info with ip and type
            srcIp = self.packet[IPv6].src #set the source ip
            dstIp = self.packet[IPv6].dst #set the destination ip
            output += f'{self.name} Packet: ({srcIp}) --> ({dstIp}) Type: {igmpType} | Size: {packetSize} bytes' #insert info to output
        else: #if packet doesnt have ip layer we print its mac address annd type
            output += f'{self.name} Packet: ({srcMac}) --> ({dstMac}) Type: {igmpType} | Size: {packetSize} bytes' #insert info to output
        return output   


    #method for packet information
    def MoreInfo(self) -> str:
        output = super().MoreInfo() #call parent MoreInfo
        if self.packet.haslayer(IGMP): #if true it means packet is IGMP
            igmpType = self.igmpTypes[self.packet[IGMP].type] if self.packet[IGMP].type in self.igmpTypes else self.packet[IGMP].type #represents IGMP type based on the igmpTypes dictionary
            output += f'Type: {igmpType}\n\n' #add IGMP type to output
            output += f'Group Address: {self.packet[IGMP].gaddr}\n\n' #add IGMP group address to output
            output += f'Maximum Response Code: {self.packet[IGMP].mrcode}\n\n' #add IGMP mrcode to output
            output += f'Checksum: {self.packet[IGMP].chksum}\n\n' #add IGMP checksum to output
        return output

#---------------------------------------------------------IGMP-END----------------------------------------------------------#

#-----------------------------------------------------------STP-------------------------------------------------------------#
class STP_Packet(Default_Packet):
    def __init__(self, packet: Packet=None, id: int=None) -> None: #ctor for stp packet
        super().__init__('STP', packet, id) #call parent ctor
        if packet.haslayer(STP): #checks if packet is stp
            self.packetType = STP #add pacet type


    #method for brief packet information
    def Info(self) -> str:
        output = ''
        packetSize = len(self.packet) #represents the stp packet size
        output += f'{self.name} Packet: ({self.packet.src}) --> ({self.packet.dst}) | Size: {packetSize} bytes' #add packet info to output
        return output

    
    #method for packet information
    def MoreInfo(self) -> str:
        output = ''
        if self.packet.haslayer(STP): #if packet is an stp packet
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

# ---------------------------------------------------------STP-END----------------------------------------------------------#

#--------------------------------------------------INTERFACE-INFORMATION----------------------------------------------------#
#static class that represents information of network interfaces
class InterfaceInformation(ABC):
    #this list represents the usual network interfaces that are available in various platfroms
    supportedInterfaces: list = ['eth', 'wlan', 'en', 'enp', 'wlp', 'Ethernet', 'Wi-Fi', 'lo', '\\Device\\NPF_Loopback']

    #method to print all available interfaces
    def PrintAvailableInterfaces() -> None:
        #get a list of all available network interfaces
        interfaces = get_if_list() #call get_if_list method to retrieve the available interfaces
        if interfaces: #if there are interfaces we print them
            print('Available network interfaces:')
            i = 1 #counter for the interfaces 
            for interface in interfaces: #print all availabe interfaces
                if sys.platform.startswith('win32'): #if ran on windows we convert the guid number
                    print(f'{i}. {InterfaceInformation.GuidToStr(interface)}')
                else: #else we are on other os so we print the interface 
                    print(f'{i}. {interface}')
                i += 1
        else: #else no interfaces were found
            print('No network interfaces found.')


    #method for retrieving interface name from GUID number (Windows only)
    def GuidToStr(guid: str) -> str:
        try: #we try to import the specific windows method from scapy library
            from scapy.arch.windows import get_windows_if_list
        except ImportError as e: #we catch an import error if occurred
            print(f'Error importing module: {e}') #print the error
            return guid #we exit the function
        interfaces = get_windows_if_list() #use the windows method to get list of guid number interfaces
        for interface in interfaces: #iterating over the list of interfaces
            if interface['guid'] == guid: #we find the matching guid number interface
                return interface['name'] #return the name of the interface associated with guid number
        return guid #else we didnt find the guid number so we return given guid


    #method for retrieving the network interfaces
    def GetNetworkInterfaces() -> list:
        interfaces = get_if_list() #get a list of the network interfaces
        if sys.platform.startswith('win32'): #if current os is Windows we convert the guid number to interface name
            interfaces = [InterfaceInformation.GuidToStr(interface) for interface in interfaces] #get a new list of network interfaces with correct names instead of guid numbers
        matchedInterfaces = [interface for interface in interfaces if any(interface.startswith(name) for name in InterfaceInformation.supportedInterfaces)] #we filter the list to retrieving interfaces
        return matchedInterfaces #return the matched interfaces as list

#------------------------------------------------INTERFACE-INFORMATION-END--------------------------------------------------#

#------------------------------------------------------SNIFFSERPENT---------------------------------------------------------#
#main class for SniffSerpent that handles the GUI and the packet sniffing
class SniffSerpent(QMainWindow):
    ui: Ui_SniffSerpent = None #represents main ui object of GUI with all our objects
    server: QLocalServer = None #represents listening server for our app to make sure one instance is showing
    serverName: str = 'SniffSerpent' #represents our listening server name
    packetDictionary: dict = {} #initialize the packet dictionary
    packetQueue: list = [] #queue for packets before adding them to listView
    packetCounter: int = 0 #counter for number of packets captured
    packetThreshold: int = 500 #represents the threshold for number of packets
    packetTimerTimout: int = 5000 #represents the timeout for the timer (5 seconds)
    packetTimer: QTimer = None #represents the timer for packet capture
    PacketCaptureThread: QThread = None #represents current thread that capturing packets 
    packetModel: QStandardItemModel = None #represents packet list model for QListView
    IPValidator, portValidator = None, None #represents line edit validators
    validIp: bool = True #represents validIp flag
    isClosing: bool = False #represents isClosing flag

    def __init__(self) -> None:
        super(SniffSerpent, self).__init__()
        self.ui = Ui_SniffSerpent() #set mainwindow ui object
        self.ui.setupUi(self) #load the ui file of the sniffer
        self.initUI() #call init method


    #method to initialize GUI methods and events
    def initUI(self) -> None:
        self.setWindowTitle('SniffSerpent') #set title of window
        self.setWindowIcon(QIcon('images/serpent.ico')) #set icon of window
        self.packetModel = QStandardItemModel() #set the QListView model for adding items to it
        self.packetTimer = QTimer(self) #initialize the timer for packet capture
        self.ui.PacketList.setModel(self.packetModel) #set the model for the packetlist in gui
        self.ui.infoLabel.mousePressEvent = lambda event: self.InfoLabelClicked() #add method to handle info label
        self.ui.StartScanButton.clicked.connect(self.StartScanClicked) #add method to handle start scan button
        self.ui.StopScanButton.clicked.connect(self.StopScanClicked) #add method to handle stop scan button 
        self.ui.LoadScanButton.clicked.connect(self.LoadScanClicked) #add method to handle load scan button
        self.ui.ClearButton.clicked.connect(self.ClearClicked) #add method to handle clear button 
        self.ui.SaveScanButton.clicked.connect(self.SaveScanClicked) #add method to handle save scan button
        self.ui.PacketList.doubleClicked.connect(self.HandleItemDoubleClicked) #add method to handle clicks on the items in packet list
        self.packetTimer.timeout.connect(self.UpdatePacketListView) #connect the timeout signal to the method that updates the packet listView
        self.SetLineEditValidators() #call the method to set the validators for the QLineEdit for port and ip
        self.ui.IPLineEdit.textChanged.connect(self.CheckIPValidity) #connect signal for textChanged for IP to determine its validity
        self.InitComboBox() #set the combobox interface names
        self.center() #make the app open in center of screen


    #method for making the app open in the center of screen
    def center(self) -> None:
        qr = self.frameGeometry()
        cp = QGuiApplication.primaryScreen().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


    #method for closing the program and managing the PacketCapture thread
    def closeEvent(self, event) -> None:
        if self.PacketCaptureThread != None and self.PacketCaptureThread.isRunning(): #if true we have a scan running
            self.isClosing = True #set the isClosing flag to true to indicate that user wants to close program
            self.StopScanClicked() #call StopScanClicked method to stop the scan
        SniffSerpent.CloseServer() #close listening server
        event.accept() #accept the close event


    #function for initializing listening server for managing one instance
    @staticmethod
    def InitServer() -> bool:
        #check if server is already initialized
        if SniffSerpent.server:
            return True; #return true if already initialized

        #create server to listen for new instances
        SniffSerpent.server = QLocalServer()

        #check if failed to listen on our server name, if so we remove old entries and try again
        if not SniffSerpent.server.listen(SniffSerpent.serverName):
            SniffSerpent.server.removeServer(SniffSerpent.serverName) #clear server name entries
            #try to listen again for our server name, if failed we return false
            if not SniffSerpent.server.listen(SniffSerpent.serverName):
                SniffSerpent.server = None #set server back to none
                return False #return false to indicate failure
        return True #return true if server listening successfully


    #function for checking if listening server is running
    @staticmethod
    def CheckServer() -> bool:
        socket = QLocalSocket() #create socket for checking is server running
        socket.connectToServer(SniffSerpent.serverName) # try to connect to server
        #wait for server to response to our request,if we receive response we return true
        if socket.waitForConnected(100):
            return True #return true to indicate that server is running
        return False #return false to indicate that server is down


    #function for closing listening server
    @staticmethod
    def CloseServer() -> None:
        #check if listening server is initialized
        if SniffSerpent.server:
            SniffSerpent.server.close() #close listening server
            QLocalServer.removeServer(SniffSerpent.serverName) #remove server entry
            SniffSerpent.server = None #set server back to none


    #method for setting the settings for ip and port line edit lables
    def SetLineEditValidators(self) -> None:
        self.IPValidator = QRegularExpressionValidator(QRegularExpression(r'^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'), self) #initialize the validator for IP
        self.portValidator = QRegularExpressionValidator(QRegularExpression( r'^(0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$'), self) #initialize the validator for port (between 0 to 65535)
        self.ui.IPLineEdit.setValidator(self.IPValidator) #set validator for IP
        self.ui.PortLineEdit.setValidator(self.portValidator) #set validaotr for port


    #method to check the IP LineEdit validity in gui
    def CheckIPValidity(self) -> None:
        ip = self.ui.IPLineEdit.text().strip() #get the ip user entered in gui

        #check if ip is valid and not empty
        if ip: #we check if ip is not empty
            octets = ip.split('.') #splite the ip into 4 octets
            self.validIp = (len(octets) == 4 and all(octet.isdigit() and 0 <= int(octet) <= 255 for octet in octets)) #check if ip is valid and not missing numbers (e.g 192.168.1.1)
        else: #else ip is empty we set the validIp flag to false
            self.validIp = True #set the validIp flag to true

        #check IP validity and set the style of the LineEdit
        if self.validIp: #if ip is valid we set the default style of the edit line lable
            style = 'QLineEdit { background-color: rgba(32,33,35,255); border-radius: 15px; border-style: outset; border-width: 2px; border-radius: 15px; border-color: black; padding: 4px; }'
            self.ui.IPLineEdit.setStyleSheet(style)
        else: #else the user input is invalid, we show a red border on the edit line lable for error indication
            style = 'QLineEdit { background-color: rgba(32,33,35,255); border-radius: 15px; border-style: outset; border-width: 2px; border-radius: 15px; border-color: rgb(139,0,0); padding: 4px; }'
            self.ui.IPLineEdit.setStyleSheet(style)


    #method for setting the parameters for the interfaces combobox 
    def InitComboBox(self) -> None:
        interfaces = InterfaceInformation.GetNetworkInterfaces() #call our method to receive the network interfaces
        interfaces = ['Loopback' if interface == '\\Device\\NPF_Loopback' else interface for interface in interfaces] #replace the loopback interface name
        if interfaces: #if not empty we add them to the combobox
            self.ui.InterfaceComboBox.addItems(interfaces) #add items to combobox
        if len(interfaces) >= 2: #if we have more then one available interface 
            self.ui.InterfaceComboBox.addItem('All') #we add "All" option to scan all available interfaces
    

    #method for showing file dialog for user to choose his desired path and file name
    def GetPathFromFileDialog(self, title: str, fileName: str, extensions: str, location: str='desktop') -> tuple:
        options = QFileDialog.Options() #represents options for file dialog
        defaultDirectory = '' #represents default directory for file dialog

        #check if location given, if so set desired directory for file dialog
        if location == 'desktop':
            defaultDirectory = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation)
        elif location == 'home':
            defaultDirectory = QStandardPaths.writableLocation(QStandardPaths.HomeLocation)

        filePath, fileType = QFileDialog.getSaveFileName(
            parent=None, #represents parent window
            caption=title, #represents dialog title
            dir=os.path.join(defaultDirectory, fileName), #represents default path with filename
            filter=extensions, #represents supported extensions
            options=options #represents options for file dialog
        )
        return filePath, fileType


    #method for showing file dialog for user to choose his desired file path
    def GetPathFromOpenFileDialog(self, title: str, extensions: str, location: str='desktop') -> tuple:
        options = QFileDialog.Options() #represents options for file dialog
        defaultDirectory = '' #represents default directory for file dialog

        #check if location given, if so set desired directory for file dialog
        if location == 'desktop':
            defaultDirectory = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation)
        elif location == 'home':
            defaultDirectory = QStandardPaths.writableLocation(QStandardPaths.HomeLocation)

        filePath, fileType = QFileDialog.getOpenFileName(
            parent=None, #represents parent window
            caption=title, #represents dialog title
            dir=defaultDirectory, #represents default path
            filter=extensions, #represents supported extensions
            options=options #represents options for file dialog
        )
        return filePath, fileType


    #method that updates the packet timer state
    @Slot(bool)
    def UpdatePacketTimer(self, state: bool) -> None:
        if state: #check if the state is true
            self.packetTimer.start(self.packetTimerTimout) #start the packet timer
        else: 
            self.packetTimer.stop() #stop the packet timer


    #method for sniff thread to show message box in GUI
    @Slot(str, str, str)
    def CaptureThreadMessageBox(self, title: str, message: str, iconType: str) -> None:
        CustomMessageBox.ShowMessageBox(title, message, iconType) #show message box for capture thread


    #method for initialize the packet thread
    def InitPacketThread(self, interface: str='', packetFilter: list=None, portAndIP: str='', packetList: list=None) -> None:
        self.PacketCaptureThread = PacketCaptureThread(interface=interface, packetFilter=packetFilter, portAndIP=portAndIP, packetList=packetList) #initialzie the packet thread with the queue we initialized and interface
        self.PacketCaptureThread.UpdatePacketQueue.connect(self.UpdatePacketQueue) #connect the packet thread to UpdatePacketQueue method
        self.PacketCaptureThread.UpdatePacketTimer.connect(self.UpdatePacketTimer) #connect the packet thread to UpdatePacketTimer method
        self.PacketCaptureThread.ShowMessageBox.connect(self.CaptureThreadMessageBox) #connnect the packet thread to CaptureThreadMessageBox method
        self.PacketCaptureThread.start() #calling the run method of the thread to start the scan    


    #method to handle the start scan button, initializing the packet sniffing
    def StartScanClicked(self) -> None:
        if not self.PacketCaptureThread or not self.PacketCaptureThread.isRunning(): #checks if no thread is set for sniffer  
            packetFilter = self.GetPacketFilter() #call GetPacketFilter method for filtered list based on check boxes state
            portAndIP = self.GetPortIP() #call the getPortId method to recevie the input for port and ip from user
            
            if packetFilter == None or portAndIP == None: #if the packetFilter or portAndIP are not valid
                return #stop the initialization of scan

            interface = self.ui.InterfaceComboBox.currentText() #get the chosen network interface from combobox
            if not interface: #if the input is empty it means no availabe interface found
                CustomMessageBox.ShowMessageBox('No Available Interface', 'Cannot find available network interface.', 'Critical') #show error message box
                return #stop the initialization of scan
            else:
                self.ClearClicked() #call clear method for clearing the memory and screen for new scan
                self.HandleGUIState(False) #we set the GUI elements to be unclickable while scan in progress
                self.ui.StartScanButton.setEnabled(False) #set the scan button to be unclickable while scan in progress

                if interface == 'All': #if user chose "All" option so we scan all available network interfaces
                    self.InitPacketThread(packetFilter=packetFilter, portAndIP=portAndIP) #initialzie the packet thread without specifing a interface, we scan all interfaces
                else: #if true it means we need to scan on a specific interface
                    interface = '\\Device\\NPF_Loopback' if interface == 'Loopback' else interface #set the interface to be loopback interface name if user chose loopback
                    self.InitPacketThread(interface=interface, packetFilter=packetFilter, portAndIP=portAndIP) #initialzie the packet thread
        else: #else we show error message
            CustomMessageBox.ShowMessageBox('Scan Running', 'Scan in progress!', 'Warning') #show error message box


    #method to handle the stop scan button, stops the packet sniffing
    def StopScanClicked(self) -> None:
        if self.PacketCaptureThread != None and self.PacketCaptureThread.isRunning(): #checks if there is a running thread
            self.PacketCaptureThread.StopThread() #calls stop method of the thread
            self.PacketCaptureThread = None #setting the PacketCaptureThread to None for next scan
            self.HandleGUIState(True) #we set the GUI elements to be clickable again
            self.ui.StartScanButton.setEnabled(True) #set scan button back to being clickable
            if not self.isClosing: #if false we show messagebox
                CustomMessageBox.ShowMessageBox('Scan Stopped', 'Packet capturing stopped.', 'Information') #show messagebox
            else: #else user wants to close program
                self.isClosing = False #set isClosing flag to false
                self.close() #call close method to close program
    
    
    #method for saving scan data into a text file
    def SaveScanClicked(self) -> None:
        try:
            #if packet dictionary isn't empty and if there's no scan in progress we open the save window
            if any(self.packetDictionary.values()) and (not self.PacketCaptureThread or not self.PacketCaptureThread.isRunning()):
                filePath, fileType = self.GetPathFromFileDialog('Save Scan Data', 'Packet Scan', 'Text File (*.txt);;PCAP File (*.pcap)')
                if filePath: #if user chose valid path we continue
                    if fileType == 'PCAP File (*.pcap)': #means user chose pcap file
                        packetList = [packet.GetPacket() for packet in self.packetDictionary.values()] #we convert the packet dictionary to list for scapy wrpcap method
                        wrpcap(filePath, packetList) #call wrpcap method to write the captured packets into pcap file
                        CustomMessageBox.ShowMessageBox('Scan Saved', 'Saved scan detalis to PCAP file.', 'Information') #notify the user for success
                    elif fileType == 'Text File (*.txt)': #else user chose a txt file
                        with open(filePath, 'w') as file: #we open the file for writing
                            for packet in self.packetDictionary.values(): #iterating over the packet dictionary to extract the info 
                                file.write('-' * 85 + '\n\n') #add seperator line to the file
                                file.write(packet.MoreInfo()) #write the packet info to the file (extended information)
                                file.write('-' * 85 + '\n\n') #add seperator line to the file
                            CustomMessageBox.ShowMessageBox('Scan Saved', 'Saved scan detalis to text file.', 'Information') #notify the user for success
                    else: #else user didnt choose a valid file type
                        CustomMessageBox.ShowMessageBox('Save Error', 'You must choose a valid file type for saving!', 'Critical') #show error message box
            elif self.PacketCaptureThread != None and self.PacketCaptureThread.isRunning(): #if scan in progress we notify the user
                CustomMessageBox.ShowMessageBox('Scan In Progress', 'Cannot save scan while scan in progress!', 'Warning') #show error message box  
            else: #else we show a "saved denied" error if something happend
                CustomMessageBox.ShowMessageBox('Save Denied', 'No scan data to save.', 'Information') #show error message box
        except Exception as e: #if exeption happend while saving scan
            CustomMessageBox.ShowMessageBox('Save Error', 'Error occured while saving, try again later.', 'Critical') #show error message box
            print(f'Error occurred while saving: {e}.')

    
    #method to handle loading pcap file scan data to interface
    def LoadScanClicked(self) -> None:
        try:
            if not self.PacketCaptureThread or not self.PacketCaptureThread.isRunning(): #if there's no scan in progress we can load pcap file
                packetFilter = self.GetPacketFilter() #call GetPacketFilter method for filtered list based on check boxes state
                portAndIP = self.GetPortIP() #call the getPortId method to recevie the input for port and ip from user

                if packetFilter == None or portAndIP == None: #if the packetFilter or portAndIP are not valid
                    return #stop the loading of pcap file

                filePath, fileType = self.GetPathFromOpenFileDialog('Choose PCAP File', 'PCAP File (*.pcap)') #load the pcap file from a specific path
                if filePath and fileType == 'PCAP File (*.pcap)': #if the file path is valid we proceed and the type is pcap
                    self.ClearClicked() #call clear method
                    self.HandleGUIState(False) #we set the GUI elements to be unclickable while scan in progress

                    packetList = rdpcap(filePath) #read all the content of the pcap file and save in variable
                    if packetList:
                        self.InitPacketThread(packetFilter=packetFilter, portAndIP=portAndIP, packetList=packetList) #initialize the packet thread with packetList
                    else:
                        CustomMessageBox.ShowMessageBox('Load Error', 'Error loading PCAP file, please try again.', 'Critical')
                    CustomMessageBox.ShowMessageBox('Load Successful', 'Loaded PCAP file successfully, loading data to interface...', 'Information') #notify the user for success
                elif filePath and fileType != 'PCAP File (*.pcap)': #else user didn't specify a valid pcap file
                    CustomMessageBox.ShowMessageBox('Load Error', 'You must choose a PCAP file to load!', 'Critical') #show error message box 
            else: #else we show error message
                CustomMessageBox.ShowMessageBox('Scan Running', 'Scan in progress, cannot load file.', 'Warning') #show error message box
        except Exception as e: #if exeption happend while loading scan
            CustomMessageBox.ShowMessageBox('Load Error', 'Error occured while loading, try again later.', 'Critical') #show error message box
            print(f'Error occured while loading: {e}.')


    #method to handle clearing the screen
    def ClearClicked(self) -> None:
        if not self.PacketCaptureThread or (self.PacketCaptureThread != None and not self.PacketCaptureThread.isRunning()):
            self.packetDictionary.clear() #clear the main packet dictionary
            self.packetQueue.clear() #clear the main packet queue
            self.packetCounter = 0 #reset the packet counter
            self.ui.PacketList.model().clear() #clear the packet list in GUI
            self.ui.MoreInfoTextEdit.setText('') #clear the extended information in GUI
        elif self.PacketCaptureThread != None and self.PacketCaptureThread.isRunning():
            CustomMessageBox.ShowMessageBox('Thread Running Error', 'Cannot clear while scan is in progress!', 'Warning') #show error message box


    #method that shows information about SniffSerpent 
    def InfoLabelClicked(self) -> None:
        sniffSerpentInfo = (
        '<br/>SniffSerpent is an easy to use packet sniffer that allows users to capture packets<br/> on various network interfaces, save packet scans in various file types<br/> as well as load PCAP files for future analysis.<br/><br/>'
        'SniffSerpent supports the following packet types:<br/>'
        'TCP, UDP, HTTP, DNS, TLS, ICMP, DHCP, ARP, IGMP, STP.<br/><br/>'
        'SniffSerpent is licensed under the MIT license, all rights are reserved<br/> to Shay Hahiashvili (Shayhha).<br/><br/>'
        'For questions or feedback, <a href="https://github.com/Shayhha/SniffSerpent"><span style="text-decoration: underline; color: rgb(0, 116, 217);">visit SniffSerpent on GitHub</span></a>.'
        )
        CustomMessageBox.ShowMessageBox('SniffSerpent General Information', sniffSerpentInfo, 'NoIcon', 700, 360, False) #shows messagebox with info about the application


    #method that checks all the check boxs state, return a string with filtered packets
    def GetPacketFilter(self) -> list:
        packetFilter = [] #list of packet kinds for filthering

        #check each check box to filter the packet kinds
        if self.ui.HTTPCheckBox.isChecked():
            packetFilter.append('HTTP')
        if self.ui.TLSCheckBox.isChecked():
            packetFilter.append('TLS')
        if self.ui.DHCPCheckBox.isChecked():
            packetFilter.append('DHCP')
        if self.ui.DNSCheckBox.isChecked():
            packetFilter.append('DNS')
        if self.ui.TCPCheckBox.isChecked():
            packetFilter.append('TCP')
        if self.ui.UDPCheckBox.isChecked():
            packetFilter.append('UDP')
        if self.ui.ICMPCheckBox.isChecked():
            packetFilter.append('ICMP')
        if self.ui.ARPCheckBox.isChecked():
            packetFilter.append('ARP')
        if self.ui.IGMPCheckBox.isChecked():
            packetFilter.append('IGMP')
        if self.ui.STPCheckBox.isChecked():
            packetFilter.append('STP')

        if not packetFilter: #if list is empty we raise a new exception to indicate of an error 
            CustomMessageBox.ShowMessageBox('No Packets Selected', 'Error, you must choose at least one packet type for scan.', 'Information')
            return None #return None if no packets selected
        return packetFilter
     

    #method that checks the ip and port line edit lables, if valid it returns the string representing the option
    def GetPortIP(self) -> str | None:
        portIPFilter = '' #string for the port and ip filter

        if self.ui.IPLineEdit.text() != '': #if true user typed a ip for us to search for 
            if not self.validIp: #if ip isnt valid we raise a ValueError exeption
               CustomMessageBox.ShowMessageBox('IP Is Not Valid', 'Error, please provide a valid IP address (e.g., 172.16.254.1).', 'Information')
               return None #return None if ip is invalid
            else: #else the ip is valid we add it to portIPFilter string
                portIPFilter += f'(src {self.ui.IPLineEdit.text()} or {self.ui.IPLineEdit.text()})'
        if self.ui.PortLineEdit.text() != '': #if user typed a port to seach for
            if portIPFilter != '': #if true we need to divide the ip and port with 'add' word 
                portIPFilter += ' and ' #add the word that divides the ip and port
            portIPFilter += f'port {self.ui.PortLineEdit.text()}' #add the port to the portIPFilter
        return portIPFilter


    #method for updating the packet queue with new packets
    @Slot(Default_Packet)
    def UpdatePacketQueue(self, packet: Default_Packet) -> None:
        if packet != None: #if the packet isn't None we proceed
            packet.SetId(self.packetCounter) #set the packet id to be the packet counter
            self.packetDictionary[packet.GetId()] = packet #insert it to packet dictionary
            self.packetQueue.append(packet) #add the packet to the queue
            self.packetCounter += 1 #increase the packet counter

            #check if we reached the packet threshold and call the method to update the packet list
            if len(self.packetQueue) >= self.packetThreshold: #if true we reached packet threshold
                self.packetTimer.stop() #stopping packet timer
                self.packetTimer.start(self.packetTimerTimout) #resetting packet timer
                self.UpdatePacketListView() #call the method to update the packet list in GUI


    #method for updating the packet listView
    def UpdatePacketListView(self) -> None:
        if self.PacketCaptureThread != None and self.packetQueue: #we add packets when packet queue if not empty
            numberOfPackets = min(len(self.packetQueue), self.packetThreshold) #represents the amount of packets to add at a time
            packetList = self.packetQueue[:numberOfPackets] #take packets from the queue based on numberOfPackets

            #we add the packets to the listView based on the amount of packets acccording to the threshold
            for packet in packetList:
                item = QStandardItem(packet.Info()) #creating standard item for the packet
                self.packetModel.appendRow(item) #adding the item to the listView
            del self.packetQueue[:numberOfPackets] #deleting the packets we added to the listView from the queue


    #method the double clicks in packet list, extended information section
    def HandleItemDoubleClicked(self, index: QModelIndex) -> None:
        packetIndex = index.row() #get the index of the row of the specific packet we want
        item = self.ui.PacketList.model().itemFromIndex(index) #taking the packet from the list in GUI
        if item != None and packetIndex in self.packetDictionary: #checking if the packet in GUI list isn't None 
            packet = self.packetDictionary[packetIndex] #taking the matching packet from the packetDictionary
            self.ui.MoreInfoTextEdit.setText(packet.MoreInfo()) #add the information to the extended information section in GUI


    #method to handle state of checkboxes, if state false we disable them, otherwise we enable them
    def HandleGUIState(self, state: bool) -> None:
        if state: #if true we set the checkboxes and ip/port line edit to be enabled
            self.ui.HTTPCheckBox.setEnabled(True)
            self.ui.TLSCheckBox.setEnabled(True)
            self.ui.TCPCheckBox.setEnabled(True)
            self.ui.DNSCheckBox.setEnabled(True)
            self.ui.UDPCheckBox.setEnabled(True)
            self.ui.ICMPCheckBox.setEnabled(True)
            self.ui.DHCPCheckBox.setEnabled(True)
            self.ui.ARPCheckBox.setEnabled(True)
            self.ui.IGMPCheckBox.setEnabled(True)
            self.ui.STPCheckBox.setEnabled(True)
            self.ui.IPLineEdit.setEnabled(True)
            self.ui.PortLineEdit.setEnabled(True)
            self.ui.InterfaceComboBox.setEnabled(True)
        else: #else we disable the checkboxes and ip/port line edit
            self.ui.HTTPCheckBox.setEnabled(False)
            self.ui.TLSCheckBox.setEnabled(False)
            self.ui.TCPCheckBox.setEnabled(False)
            self.ui.DNSCheckBox.setEnabled(False)
            self.ui.UDPCheckBox.setEnabled(False)
            self.ui.ICMPCheckBox.setEnabled(False)
            self.ui.DHCPCheckBox.setEnabled(False)
            self.ui.ARPCheckBox.setEnabled(False)
            self.ui.IGMPCheckBox.setEnabled(False)
            self.ui.STPCheckBox.setEnabled(False)
            self.ui.IPLineEdit.setEnabled(False)
            self.ui.PortLineEdit.setEnabled(False)
            self.ui.InterfaceComboBox.setEnabled(False)
            
#-----------------------------------------------------SNIFFSERPENT-END------------------------------------------------------#

#---------------------------------------------------PACKETCAPTURETHREAD-----------------------------------------------------#
#thread class for capturing packets in real time
class PacketCaptureThread(QThread):
    captureDictionary: dict = None #represents the dictionary with packet types and their init methods
    UpdatePacketQueue: Signal = Signal(Default_Packet) #signal for updating the packet queue in GUI
    UpdatePacketTimer: Signal = Signal(bool) #signal for the thread to update packet timer in main thread
    ShowMessageBox: Signal = Signal(str, str, str) #signal for showing messagebox in GUI

    #constructor for the packet capture thread
    def __init__(self, interface: str='', packetFilter: list=None, portAndIP: str='', packetList: list=None) -> None:
        super(PacketCaptureThread, self).__init__()
        #initalize capture dictionary with packet types and their init methods
        self.captureDictionary = {('HTTP', HTTP): self.InitHTTP, ('TLS', TLS): self.InitTLS, ('DHCP', DHCP): self.InitDHCP, ('DNS', DNS): self. InitDNS, ('TCP', TCP): self.InitTCP, 
                                    ('UDP', UDP): self.InitUDP, ('ICMP', ICMP): self.InitICMP, ('ARP', ARP): self.InitARP, ('IGMP', IGMP): self.InitIGMP, ('STP', STP): self.InitSTP}
        self.interface = interface #initialize the network interface if given
        self.packetFilter = packetFilter #represents the packet type filter for sniffer
        self.portAndIP = portAndIP #represents port and ip filter for sniffer
        self.packetList = packetList #represents the list of packets to be loaded
        self.interface = None #represents the selected interface for sniffer
        self.sniffer = None #represents our sniffer scapy object for sniffing packets
        self.stopFlag = False #represents stop flag for indicating when to stop the sniffer


    #method for stopping the packet capture thread
    @Slot()
    def StopThread(self) -> None:
        try:
            self.stopFlag = True #set stop flag
            #we check if sniffer is still running, if so we stop it
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop() #stop async sniffer
        except Exception as e:
            self.ShowMessageBox.emit('Permission Denied', 'Sniffing unavailable, please run again with administrative privileges.', 'Critical') #emit a signal to GUI to show error message box
            print('Permission denied. Please run again with administrative privileges.') #print permission error message in terminal
        finally:
            self.quit() #exit main loop and end task
            self.wait(2000) #we wait to ensure thread cleanup


    #method for checking when to stop sniffing packets
    def StopScan(self, packet: Packet) -> bool:
        return self.stopFlag #return the stop flag


    #method that handles the packet capturing
    def PacketCapture(self, packet: Packet) -> None:         
        # iterate over capture dictionary and find coresponding initPacket method for each packet that is not filtered
        for packetType, initPacket in self.captureDictionary.items():
            if packetType[0] in self.packetFilter and packet.haslayer(packetType[1]): #if we found matching packet we call its initPacket method
                initPacket(packet) #call initPacket method of each packet
                break #break the loop if we found a matching packet


    #run method for the thread, initialize packet scan with necessary parameters or load packets from given packet list
    def run(self) -> None:
        try:
            self.UpdatePacketTimer.emit(True) #start packet timer when thread starts
            if self.packetList != None: #if true we received a packet list meaning we need to load scan from pcap file
                for packet in self.packetList: #iterate through the packet list 
                    self.PacketCapture(packet) #call PacketCapture method to handle the packets
                QThread.sleep(2) #we give the thread to sleep for 2 seconds for gui responsiveness
            else: #else we need to start a packet scan
                #we call sniff with desired interface and filters for port and ip
                self.sniffer = AsyncSniffer(iface=self.interface, prn=self.PacketCapture, filter=self.portAndIP, stop_filter=self.StopScan, store=False)
                self.sniffer.start() #start our async sniffing
                self.exec() #start packet capture thread process
        except PermissionError: #if user didn't run in administrative privileges we emit signal to show messagebox with error
            self.ShowMessageBox.emit('Permission Denied', 'Sniffing unavailable, please run again with administrative privileges.', 'Critical') #emit a signal to GUI to show error message box
            print('Permission denied. Please run again with administrative privileges.') #print permission error message in terminal
        except Exception as e: #we catch an exception if something happend while sniffing
            self.ShowMessageBox.emit('Error Occured While Sniffing', f'An error occurred: {e}.', 'Critical') #emit a signal to GUI to show error message box
            print(f'An error occurred: {e}.') #print error message in terminal
        finally:
            self.UpdatePacketTimer.emit(False) #after thread finishes we stop packet timer


    #---------------------------------------------------INIT-PACKET-METHODS-----------------------------------------------------#
    #method that initialize TCP packets
    def InitTCP(self, packet: Packet) -> None:
        TCP_Object = TCP_Packet(packet) #create a new object for packet
        self.UpdatePacketQueue.emit(TCP_Object) #emit signal to update packet queue in main thread


    #method that initialize UDP packets
    def InitUDP(self, packet: Packet) -> None:
        UDP_Object = UDP_Packet(packet) #create a new object for packet
        self.UpdatePacketQueue.emit(UDP_Object) #emit signal to update packet queue in main thread


    #method that initialize HTTP packets
    def InitHTTP(self, packet: Packet) -> None:
        HTTP_Object = HTTP_Packet(packet) #create a new object for packet
        self.UpdatePacketQueue.emit(HTTP_Object) #emit signal to update packet queue in main thread


    #method that initialize DNS packets
    def InitDNS(self, packet: Packet) -> None:
        DNS_Object = DNS_Packet(packet) #create a new object for packet
        self.UpdatePacketQueue.emit(DNS_Object) #emit signal to update packet queue in main thread


    #method that initialize TLS packets
    def InitTLS(self, packet: Packet) -> None:
        if packet[TLS].type == 22: #we need to capture handshakes TLS packets so 22 is the correct type
            TLS_Object = TLS_Packet(packet) #create a new object for packet
            self.UpdatePacketQueue.emit(TLS_Object) #emit signal to update packet queue in main thread


    #method that initialize ICMP packets
    def InitICMP(self, packet: Packet) -> None:
        ICMP_Object = ICMP_Packet(packet) #create a new object for packet
        self.UpdatePacketQueue.emit(ICMP_Object) #emit signal to update packet queue in main thread


    #method that initialize DHCP packets
    def InitDHCP(self, packet: Packet) -> None:
        if packet[DHCP].options[0][1] in [1, 2, 3, 5, 7, 8]: #we check if its a valid parameter for DHCP
            DHCP_Object = DHCP_Packet(packet) #create a new object for packet
            self.UpdatePacketQueue.emit(DHCP_Object) #emit signal to update packet queue in main thread


    #method that initialize ARP packets
    def InitARP(self, packet: Packet) -> None:
        ARP_Object = ARP_Packet(packet) #create a new object for packet
        self.UpdatePacketQueue.emit(ARP_Object) #emit signal to update packet queue in main thread


    #method that initialize IGMP packets
    def InitIGMP(self, packet: Packet) -> None:
        if packet[IGMP].type in [17, 18, 22, 23]: #we check if its a valid parameter for IGMP
            IGMP_Object = IGMP_Packet(packet) #create a new object for packet
            self.UpdatePacketQueue.emit(IGMP_Object) #emit signal to update packet queue in main thread


    #method that initialize STP packets
    def InitSTP(self, packet: Packet) -> None:
        STP_Object = STP_Packet(packet) #create a new object for packet
        self.UpdatePacketQueue.emit(STP_Object) #emit signal to update packet queue in main thread

    #--------------------------------------------------INIT-PACKET-METHODS-END--------------------------------------------------#

#--------------------------------------------------PACKETCAPTURETHREAD-END--------------------------------------------------#

#-----------------------------------------------------CUSTOMMESSAGEBOX------------------------------------------------------#
class CustomMessageBox(QDialog):
    isMessageBox: bool = False #represents flag for indicating if messagebox already exists

    #constructor of custom message box class
    def __init__(self, title: str, message: str, iconType: str='Information', width: int=400, height: int=150, wordWrap: bool=True, parent: QObject=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title) #set the title for message box
        self.setObjectName('customMessageBox') #set object name for message box
        self.setWindowIcon(QIcon('images/serpent.ico')) #set the icon for message box

        #create the main vertical layout
        layout = QVBoxLayout(self)

        #create a horizontal layout for the icon and message
        horizontalLayout = QHBoxLayout()

        #we add an icon only if iconType is not "NoIcon"
        if iconType != 'NoIcon': #if true it means we need to set an icon for message box
            iconLabel = QLabel()
            icon = self.GetMessageBoxIcon(iconType) #use the method to get message box icon
            
            #create pixmap for icon and set size and margin
            pixmap = icon.pixmap(48, 48)
            iconLabel.setPixmap(pixmap)
            iconLabel.setContentsMargins(15, 0, 15, 0)
            iconLabel.setAlignment(Qt.AlignCenter) #center the icon vertically
            horizontalLayout.addWidget(iconLabel) #add icon to horizontal layout

        #set the message
        messageLabel = QLabel(message)
        messageLabel.setWordWrap(wordWrap) #ensure long messages wrap properly
        messageLabel.setAlignment(Qt.AlignVCenter | Qt.AlignHCenter) #vertically center the text
        messageLabel.setOpenExternalLinks(True) #open links in an external web browser
        messageLabel.setContentsMargins(0, 0, 0, 0)
        messageLabel.setMinimumWidth(250)

        #add message to the horizontal layout
        horizontalLayout.addWidget(messageLabel)
        horizontalLayout.setAlignment(Qt.AlignCenter) #center the entire horizontalLayout

        #add stretchable space around the horizontalLayout to center it vertically in the dialog
        layout.addStretch(1) #add stretch before the content
        layout.addLayout(horizontalLayout)
        layout.addStretch(1) #add stretch after the content

        #create buttons layout
        buttonLayout = QHBoxLayout()
        buttonLayout.setAlignment(Qt.AlignCenter) #center the buttons

        #if question message box, we show "Yes" and "No" buttons
        if iconType == 'Question':
            yesButton = QPushButton('Yes')
            yesButton.setCursor(QCursor(Qt.PointingHandCursor))
            yesButton.clicked.connect(self.accept)
            noButton = QPushButton('No')
            noButton.setCursor(QCursor(Qt.PointingHandCursor))
            noButton.clicked.connect(self.reject)
            buttonLayout.addWidget(yesButton)
            buttonLayout.addSpacing(15)
            buttonLayout.addWidget(noButton)
        #else we show "OK" button
        else:
            okButton = QPushButton('OK')
            okButton.setCursor(QCursor(Qt.PointingHandCursor))
            okButton.clicked.connect(self.accept)
            buttonLayout.addWidget(okButton)

        #apply layout to the dialog
        layout.addLayout(buttonLayout)
        self.setLayout(layout)

        #set custom stylesheet
        self.setStyleSheet('''
            #customMessageBox {
                background-color: rgb(245, 245, 245);
            }
                
            #customMessageBox QLabel {
                color: black;
                font-family: Arial;
                font-size: 18px;
            }
            
            #customMessageBox QPushButton {
                background-color: rgba(32, 33, 35, 255);
                color: rgb(245, 245, 245);
                border: 2px solid black;
                border-radius: 15px;
                padding: 4px;
                font-family: Arial;
                font-size: 17px;
                font-weight: bold;
                min-width: 60px;
                min-height: 20px;
            }
                    
            #customMessageBox QPushButton:hover {
                background-color: rgb(87, 89, 101);
            }
                  
            #customMessageBox QPushButton:pressed {
                background-color: rgb(177, 185, 187);
            }
        ''')

        #set dialog properties
        self.setMinimumSize(width, height) #set a reasonable minimum size
        self.adjustSize() #adjust the size based on content
        self.setFixedSize(self.size()) #lock the size to prevent resizing


    #method for overriting the original accept function and setting isMessageBox flag
    def accept(self) -> None:
        CustomMessageBox.isMessageBox = False
        super().accept()


    #method for overriting the original reject function and setting isMessageBox flag
    def reject(self) -> None:
        CustomMessageBox.isMessageBox = False
        super().reject()
    

    #method for mapping the iconType to the appropriate StandardPixmap icon
    def GetMessageBoxIcon(self, iconType: str) -> QIcon:
        if iconType == 'Warning':
            return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxWarning)
        elif iconType == 'Critical':
            return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxCritical)
        elif iconType == 'Question':
            return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxQuestion)
        return QApplication.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation)


    #function for showing message box window
    def ShowMessageBox(title: str, message: str, iconType: str='Information', width: int=400, height: int=150, wordWrap: bool=True) -> bool:
        #iconType options can be Information, Warning, Critical, Question, NoIcon
        if not CustomMessageBox.isMessageBox:
            messageBox = CustomMessageBox(title, message, iconType, width, height, wordWrap)

            #set isMessageBox and show message box
            CustomMessageBox.isMessageBox = True
            result = messageBox.exec()

            #return result value for question message box, else true
            return result == QDialog.Accepted if iconType == 'Question' else True
        return False #if there's already a message box showing we return false

#---------------------------------------------------CUSTOMMESSAGEBOX-END----------------------------------------------------#

#-----------------------------------------------------------MAIN------------------------------------------------------------#

if __name__ == '__main__':
    #check if listening server is running
    if SniffSerpent.CheckServer():
        print('Another instance is already running.')
        sys.exit(0)

    #initalize listening server for application
    if not SniffSerpent.InitServer():
        print('Failed to initialize listening server.')
        sys.exit(1)

    #start SniffSerpent application
    app = QApplication(sys.argv)
    sniffSerpent = SniffSerpent()
    sniffSerpent.show()

    #execute application and return execution code
    ret = app.exec()
    print('Exiting.')
    sys.exit(ret)

#-----------------------------------------------------------MAIN-END---------------------------------------------------------#