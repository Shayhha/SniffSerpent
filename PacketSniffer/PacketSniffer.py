import sys
import signal
from abc import ABC, abstractmethod
import scapy.all as scapy
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP
from scapy.layers.l2 import Ether, Dot1Q, STP
from scapy.layers.dns import DNSQR, DNSRR
from scapy.all import Raw
import netifaces
from PyQt5.uic import loadUi
from PyQt5.QtCore import pyqtSignal, Qt, QThread, QTimer, QSize, QRegExp
from PyQt5.QtGui import QIcon, QStandardItem, QStandardItemModel, QRegExpValidator, QIntValidator
from PyQt5.QtWidgets import QApplication, QDesktopWidget, QMainWindow, QWidget, QCheckBox, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QSpacerItem, QSizePolicy, QMessageBox, QDialog, QLabel, QPushButton, QStyle, QHBoxLayout
from queue import Queue


#--------------------------------------------Default_Packet----------------------------------------------#
class Default_Packet(ABC): #abstarct class for default packet
    name=None
    packet = None
    packetType = None
    id = None

    def __init__(self, name=None, packet=None, id=None): # ctor 
        self.name = name
        self.packet = packet
        self.id = id


    def getId(self): # get method for id
        return self.id
    
    def setPacketType(self, packetType): #set method for packet type
        self.packetType = packetType

    def getPacket(self):
        return self.packet
    

    def rawInfo(self): #method for raw info capture
        output = ''
        if Raw in self.packet: # insert Payload Data (if available)
            payload = self.packet[Raw].load
            output += f'Payload Data: {payload.hex()}\n'  # insert payload as hexadecimal
        return output
    

    def dnsInfo(self, extended=True):
        output = ''
        if DNSQR in self.packet:
            dnsQry = self.packet[DNSQR].qname.decode('utf-8')
            if extended:
                if len(dnsQry) >= 45:
                    dnsQry = '\n'.join(dnsQry[i:i+45] for i in range(0, len(dnsQry), 45))
                    output += f'DNS Query:\n{dnsQry}'
                elif len(f'DNS Query: {dnsQry}') >=45:
                    output += f'DNS Query:\n{dnsQry}'
                else:
                    output += f'DNS Query: {dnsQry}'
            else:
                 if len(f'DNS Query: {dnsQry}') >=45:
                    output += f'DNS Query:\n{dnsQry}'
                 else:
                    output += f'DNS Query: {dnsQry}'
        elif DNSRR in self.packet:
            dnsAns = self.packet[DNSRR].rdata
            if not isinstance(dnsAns, list) and isinstance(dnsAns, bytes):
                dnsAns = dnsAns.decode('utf-8')
                if len(dnsAns) >= 45:
                    dnsAns = '\n'.join(dnsAns[i:i+45] for i in range(0, len(dnsAns), 45))
                    output += f'DNS Answer:\n{dnsAns}'
                elif len(f'DNS Answer: {dnsAns}') >=45:
                    output += f'DNS Answer:\n{dnsAns}'
                else:
                    output += f'DNS Answer: {dnsAns}'
        return output


    def ipInfo(self): # method for ip configuration capture
        output = ''
        if IP in self.packet: 
            srcIp = self.packet[IP].src
            dstIp = self.packet[IP].dst
            output += f'Source IP: {srcIp}\n\n'
            output += f'Destination IP: {dstIp}\n\n'
            # additional Information for IPv4 and IPv6 packets
            if self.packet[IP].version == 4:
                ttl = self.packet[IP].ttl
                dscp = self.packet[IP].tos
                output += f'TTL: {ttl}, DSCP: {dscp}\n\n'

            elif self.packet[IP].version == 6:
                hopLimit = self.packet[IPv6].hlim
                trafficClass = self.packet[IPv6].tc
                output += f'Hop Limit: {hopLimit}, Traffic Class: {trafficClass}\n\n'
            output += f'Checksum: {self.packet.chksum}\n\n'
        output += f'Packet Size: {len(self.packet)} bytes\n\n'
        return output


    def info(self): # method to print packet information
        output ='' # output string for information of packet
        srcMac = self.packet.src
        dstMac = self.packet.dst
        srcPort = ''
        dstPort =''
        packetSize = len(self.packet)

        if self.packet.haslayer(IP):
            srcIp = self.packet[IP].src
            dstIp = self.packet[IP].dst
        if (self.packetType == TCP or self.packetType == UDP) and (TCP in self.packet or UDP in self.packet):
            srcPort = self.packet[self.packetType].sport
            dstPort = self.packet[self.packetType].dport

        if (self.packetType == TCP or self.packetType == UDP) and self.packet.haslayer(IP):
            output += f'{self.name} Packet: ({srcIp}):({srcPort}) --> ({dstIp}):({dstPort})'
        elif (self.packetType == TCP or self.packetType == UDP) and not self.packet.haslayer(IP):
            output += f'{self.name} Packet: ({srcMac}):({srcPort}) --> ({dstMac}):({dstPort})'
        elif self.packetType == Ether and self.packet.haslayer(IP):
            output += f'{self.name} Packet: ({srcIp}):({srcMac}) --> ({dstIp}):({dstMac})'
        elif self.packetType == Ether and not self.packet.haslayer(IP):
            output += f'{self.name} Packet: ({srcMac}) --> ({dstMac})'

        dnsInfo = self.dnsInfo() #call dns method
        if dnsInfo != '':
            output += f' {dnsInfo}'
        output += f' | Size: {packetSize} bytes'
        return output


    def moreInfo(self): # method to print more information for derived classes to implement
        output = ''
        # print the packet information
        if (self.packetType == TCP or self.packetType == UDP):
            output += f'{self.name} Packet:\n\n' 
            output += f'Source Port: {self.packet.sport}\n\n'
            output += f'Destination Port: {self.packet.dport}\n\n'
        else:
            output += f'{self.name} Packet:\n\n'
            output += f'Source MAC: {self.packet.src}\n\n'
            output += f'Destination MAC: {self.packet.dst}\n\n'

        dnsInfo = self.dnsInfo() #call dns method
        if dnsInfo != '':
            output += f'{dnsInfo}\n\n'
        output += self.ipInfo() #call ip method 
        return output


#--------------------------------------------Default_Packet-END----------------------------------------------#

    
#--------------------------------------------TCP----------------------------------------------#
class TCP_Packet(Default_Packet):
 
    def __init__(self, packet=None, id=None): # ctor 
        super().__init__('TCP', packet, id) # call parent ctor
        if packet.haslayer(TCP): #checks if packet is TCP
            if IP not in packet:
                self.name = 'Raw TCP'
            self.packetType = TCP


    def moreInfo(self): # method for packet information
        output = f'{super().moreInfo()}'
        #prints TCP flags
        flags = self.packet[self.packetType].flags
        flagsDict = {
            'FIN': (flags & 0x01) != 0,
            'SYN': (flags & 0x02) != 0,
            'RST': (flags & 0x04) != 0,
            'PSH': (flags & 0x08) != 0,
            'ACK': (flags & 0x10) != 0,
            'URG': (flags & 0x20) != 0,
        }

        output += f'Sequence Number: {self.packet.seq}\n\n'
        output += f'Acknowledgment Number: {self.packet.ack}\n\n'
        output += f'Window Size: {self.packet.window}\n\n'
        output += 'Flags:\n'
        temp = ''
        for flag, value in flagsDict.items():
            if flag == 'ACK':
                temp += '\n'
            temp += f'{flag}: {value}, '
        output += temp.rstrip(', ')
        output += '\n\n'
        if self.packet[self.packetType].options: # print TCP Options (if available)
            temp = ''
            count = 0
            output += 'TCP Options:\n'
            for option in self.packet[self.packetType].options:
                if count == 4 or option[0] == 'SAck':
                    temp += '\n'
                temp += f'{option[0]}: {option[1]}, '
                count += 1
            output += temp.rstrip(', ')
            output += '\n\n'
        return output

#--------------------------------------------TCP-END----------------------------------------------#


#--------------------------------------------UDP----------------------------------------------#
class UDP_Packet(Default_Packet):
 
    def __init__(self, packet=None, id=None): # ctor 
        super().__init__('UDP', packet, id) # call parent ctor
        if packet.haslayer(UDP): #checks if packet is UDP
            if IP not in packet:
                self.name = 'Raw UDP'
            self.packetType = UDP


#--------------------------------------------UDP-END----------------------------------------------#

#--------------------------------------------ICMP----------------------------------------------#
class ICMP_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('ICMP', packet, id) # call parent ctor
        if packet.haslayer(ICMP): #checks if packet is icmp
            if IP not in packet:
                self.name = 'Raw ICMP'
            self.packetType = ICMP

    def info(self):
        output = ''
        packetSize = len(self.packet)
        icmpType = self.packet[ICMP].type
        icmpCode = self.packet[ICMP].code
        if IP in self.packet:
            srcIp = self.packet[IP].src
            dstIp = self.packet[IP].dst
            output += f'{self.name} Packet: ({srcIp}) --> ({dstIp}) | Type: {icmpType}, Code: {icmpCode} | Size: {packetSize} bytes'
        else:
            output += f'{self.name} Packet: --> {self.packet.summary()}, Type: {icmpType}, Code: {icmpCode} | Size: {packetSize} bytes'
        return output


    def moreInfo(self): # method for packet information
        output = ''
        if ICMP in self.packet:
            # insert ICMP specific information
            icmpType = self.packet[ICMP].type
            icmpCode = self.packet[ICMP].code
            icmpSeq = self.packet[ICMP].seq
            icmpId = self.packet[ICMP].id
            output += f'{self.name} Packet:\n\n'
            output += f'Type: {icmpType}\n\n'
            output += f'Code: {icmpCode}\n\n'
            output += f'Sequence Number: {icmpSeq}\n\n'
            output += f'Identifier: {icmpId}\n\n'
        output += self.ipInfo() #call ip method 
        return output

#--------------------------------------------ICMP-END----------------------------------------------#

# --------------------------------------------ARP----------------------------------------------#
class ARP_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('ARP', packet, id) # call parent ctor
        if packet.haslayer(ARP): #checks if packet is arp
            self.packetType = ARP
    

    def info(self):
        output = ''
        srcMac = self.packet[ARP].hwsrc
        srcIp = self.packet[ARP].psrc
        dstMac = self.packet[ARP].hwdst
        dstIp = self.packet[ARP].pdst
        packetSize = len(self.packet)
        output += f'{self.name} Packet: ({srcIp}):({srcMac}) --> ({dstIp}):({dstMac}) | Size: {packetSize} bytes'
        return output


    def moreInfo(self):  # method for ARP packet information
        output = ''
        if ARP in self.packet:
            output += f'{self.name} Packet:\n\n'
            output += f'Source MAC: {self.packet[ARP].hwsrc}\n\n'
            output += f'Destination MAC: {self.packet[ARP].hwdst}\n\n'
            output += f'Source IP: {self.packet[ARP].psrc}\n\n'
            output += f'Destination IP: {self.packet[ARP].pdst}\n\n'
            output += f'Packet Size: {len(self.packet)} bytes\n\n'
            output += f'ARP Operation: {"Request" if self.packet[ARP].op == 1 else "Reply"}\n\n'
            output += f'ARP Hardware Type: {self.packet[ARP].hwtype}\n\n'
            output += f'ARP Protocol Type: {hex(self.packet[ARP].ptype)}\n\n'
            output += f'ARP Hardware Length: {self.packet[ARP].hwlen}\n\n'
            output += f'ARP Protocol Length: {self.packet[ARP].plen}\n\n'
            output += f'Packet Size: {len(self.packet)} bytes\n\n'
        return output
        
# --------------------------------------------ARP-END----------------------------------------------#

# --------------------------------------------STP----------------------------------------------#
class STP_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('STP', packet, id)
        if packet.haslayer(STP):
            self.packetType = STP

    def info(self):
            output = ''
            packet_size = len(self.packet)
            output += f'{self.name} Packet: ({self.packet.src}) --> ({self.packet.dst}) | Size: {packet_size} bytes'
            return output

    def moreInfo(self):
        output = ''
        if STP in self.packet:
            stpProto = self.packet[STP].proto
            stpVersion = self.packet[STP].version
            stpBridgeId = self.packet[STP].bridgeid
            stpPortId = self.packet[STP].portid
            stpPathCost = self.packet[STP].pathcost
            stpAge = self.packet[STP].age
            output += f'{self.name} Packet:\n\n'
            output += f'STP Protocol: {stpProto}\n\n'
            output += f'Version: {stpVersion}\n\n'
            output += f'Source MAC: {self.packet.src}\n\n'
            output += f'Destination MAC: {self.packet.dst}\n\n'
            output += f'Bridge ID: {stpBridgeId}\n\n'
            output += f'Port ID: {stpPortId}\n\n'
            output += f'Path Cost: {stpPathCost}\n\n'
            output += f'Age: {stpAge}\n\n'
        output += f'Packet Size: {len(self.packet)} bytes\n\n'
        return output

# --------------------------------------------STP-END----------------------------------------------#

# --------------------------------------------Ether----------------------------------------------#
class Ether_Packet(Default_Packet):
    def __init__(self, packet=None, id=None):
        super().__init__('Ether', packet, id) # call parent ctor
        if packet.haslayer(Ether): #checks if packet is ether
            self.packetType = Ether


    def moreInfo(self): # method for packet information
        output = f'{super().moreInfo()}' #call super class method 
        if Dot1Q in self.packet: # check for VLAN tags
            vlan_id = self.packet[Dot1Q].vlan
            output += f'VLAN ID: {vlan_id}\n\n'
        return output

# --------------------------------------------Ether-END----------------------------------------------#

# -----------------------------------------------DNS------------------------------------------------#

#TODO
# --------------------------------------------DNS-END----------------------------------------------#

#-----------------------------------------HELPER-FUNCTIONS-----------------------------------------#

def GetAvailableNetworkInterfaces(): # method to print all available network interfaces
    # Get a list of all available network interfaces
    interfaces = netifaces.interfaces()
    if interfaces:
        print('Available network interfaces:')
        i = 1
        for interface in interfaces:
            print(f'{i}. {interface}')
            i += 1
    else:
        print('No network interfaces found.')


def GetNetworkInterface(inter): # method to receive desired interface on demand
    interfaces = netifaces.interfaces() #represents a list of network interfaces
    for interface in interfaces: # iterating over the list to get desired interface
        if interface == inter:
            return interface
    # If no suitable interface is found, return none
    return None

#-----------------------------------------HANDLE-FUNCTIONS-----------------------------------------#
def handleTCP(packet):
    global packetCounter
    TCP_Object = TCP_Packet(packet, packetCounter)
    packetDicitionary[TCP_Object.getId()] = TCP_Object
    packetCounter += 1
    #print(TCP_Object.info())
    #print(f'id: {packetCounter}')
    return TCP_Object


def handleUDP(packet):
    global packetCounter
    UDP_Object = UDP_Packet(packet, packetCounter)
    packetDicitionary[UDP_Object.getId()] = UDP_Object
    packetCounter += 1
    #print(UDP_Object.info())
    #print(f'id: {packetCounter}')
    return UDP_Object


def handleICMP(packet):
    global packetCounter
    ICMP_Object = ICMP_Packet(packet, packetCounter)
    packetDicitionary[ICMP_Object.getId()] = ICMP_Object
    packetCounter += 1
    #print(ICMP_Object.info())
    #print(f'id: {packetCounter}')
    return ICMP_Object


def handleARP(packet):
    global packetCounter
    ARP_Object = ARP_Packet(packet, packetCounter)
    packetDicitionary[ARP_Object.getId()] = ARP_Object
    packetCounter += 1
    #print(ARP_Object.info())
    #print(f'id: {packetCounter}')
    return ARP_Object


def handleSTP(packet):
    global packetCounter
    STP_Object = STP_Packet(packet, packetCounter)
    packetDicitionary[STP_Object.getId()] = STP_Object
    packetCounter += 1
    #print(STP_Object.info())
    #print(f'id: {packetCounter}')
    return STP_Object

def handleEther(packet):
    global packetCounter
    Ether_Object = Ether_Packet(packet, packetCounter)
    packetDicitionary[Ether_Object.getId()] = Ether_Object
    packetCounter += 1
    #print(Ether_Object.info())
    #print(f'id: {packetCounter}')
    return Ether_Object

#-----------------------------------------HANDLE-FUNCTIONS-END-----------------------------------------#

packetDicitionary = {} #initialize the packet dictionary
packetCounter = 0 # global counter for dictionary elements
stopCapture = False # for ctrl + c operation (stopping capture)

def signalHandler(signal, frame): # handle method for stopping the program
    global stopCapture
    print('\nStopping packet capturing...')
    stopCapture = True

signal.signal(signal.SIGINT, signalHandler) # signal the stopping operation

#-----------------------------------------HELPER-FUNCTIONS-END-----------------------------------------#

#--------------------------------------------PacketCaptureThread----------------------------------------------#

class PacketCaptureThread(QThread):
    packetCaptured = pyqtSignal(object)
    interface = None #inerface of network (optional)
    packetQueue = None #packet queue pointer for the thread
    stopCapture = False #flag for capture status

    def __init__(self, packetQueue, packetFilter, interface=None):
        super(PacketCaptureThread, self).__init__()
        self.interface = interface #initialize the network interface if given
        self.packetQueue = packetQueue #setting the packetQueue from the packet sniffer class
        self.packetFilter = packetFilter

    #methdo that handles stopping the scan
    def stop(self):
        self.stopCapture = True


    #method for sniff method of scapy to know status of flag 
    def checkStopFlag(self, packet):
        return self.stopCapture 


    #method that handles the packet capturing
    def PacketCapture(self, packet): 
        #for each packet we receive we send it to the dict to determine its identity and call the necessary handle method
        for packetType, handler in self.packetFilter.items():
            if packet.haslayer(packetType): #if we found matching packet we call its handle method
                self.packetQueue.put(handler(packet).info()) #call handler methods of each packet signaling it to the GUI
                break
        #else:
        #    print(f'Unknown Packet Type --> {packet.summary()}') #print summary of the packet


    #run method for the thread, initialzie the scan, call scapy sniff method with necessary parameters
    def run(self):
        if self.interface is not None:
            sniff(iface=self.interface, prn=self.PacketCapture, filter='', stop_filter=self.checkStopFlag, store=0)
        else:
            sniff(prn=self.PacketCapture, filter='', stop_filter=self.checkStopFlag, store=0)

#--------------------------------------------PacketCaptureThread-END----------------------------------------------#
    
#---------------------------------------------------Application----------------------------------------------------#

class PacketSniffer(QMainWindow):
    packetCaptureThread = None #current thread that capturing packets 
    packetModel = None #packet list model for QListView 
    packetQueue = None #queue for packets before adding them to list (thread safe)

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
        self.PacketList.doubleClicked.connect(self.handleItemDoubleClicked) #add method to handle clicks on the items in packet list
        self.setLineEditValidate() #call the method to set the validators for the QLineEdit for port and ip
        self.IPLineEdit.textChanged.connect(self.checkIPValidity) #connect signal for textChanged for IP to determine its validity
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
        validIp = True #set validIp flag to true

        if ip: #if ip is set, we check
            octets = ip.split(".") #splite the ip into 4 octets
            validIp = len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets) #check if ip is valid and not missing numbers (e.g 192.168.1.1)

        if validIp: #if ip is valid we set the default style of the edit line lable
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
        self.IPLineEdit.setPlaceholderText("Optional") #set placeholder text for IP
        self.PortLineEdit.setValidator(portValidator) #set validaotr for port
        self.PortLineEdit.setPlaceholderText("Optional") #set placeholder text for port


    #method to handle the start scan button, initializing the packet sniffing
    def StartScanClicked(self):
        if self.packetCaptureThread is None or not self.packetCaptureThread.isRunning(): #checks if no thread is set for sniffer 
            packetFilter = self.packetFilter() #call packet filter for filtered dictionary based on check boxes state
            self.StopScanClicked()  #stop previous capture thread if exists
            self.packetCaptureThread = PacketCaptureThread(self.packetQueue, packetFilter) #initialzie the packet thread with the queue we initialized
            self.packetCaptureThread.packetCaptured.connect(self.addPacketToQueue) #connect the packet thread to addPacketToQueue method
            self.packetCaptureThread.packetCaptured.connect(self.updatePacketList) #connect the packet thread to updatePacketList method
            #start a QTimer to periodically check the packet queue and update the GUI
            self.updateTimer = QTimer(self) #initialzie the QTimer
            self.updateTimer.timeout.connect(self.updatePacketList) #connect a method that runs when time elapses
            self.updateTimer.start(2000) #setting the timer to elapse every 2 seconds (can adjust according to the load)
            self.packetCaptureThread.start() #calling the run method of the thread to start the scan
            print("Start Scan button clicked")


    #method to handle the stop scan button, stops the packet sniffing
    def StopScanClicked(self):
        if self.packetCaptureThread is not None and self.packetCaptureThread.isRunning(): #checks if there is a running thread
            self.packetCaptureThread.stop() #calls stop method of the thread 
            self.packetCaptureThread.exit() #kills the thread 
            self.packetCaptureThread = None #setting the packetCaptureThread to None for next scan 
            #QMessageBox.information(self, "Scan Stopped", "Packet capturing stopped.") #message box for stop scan
            CustomMessageBox("Scan Stopped", "Error, you have to choose at least one type", 'Information')

    
    #method to handle adding packets to queue
    def addPacketToQueue(self, packetInfo):
        self.packetQueue.put(packetInfo) #add packet to queue
    

    #method that checks all the check boxs state, return a string with filtered packets
    def packetFilter(self):
        #check each check box to filter the packet kinds
        packetFilter = ''
        if not self.TCPCheckBox.isChecked():
            packetFilter += 'TCP,'
        if not self.UDPCheckBox.isChecked():
            packetFilter += 'UDP,'
        if not self.ICMPCheckBox.isChecked():
            packetFilter += 'ICMP,'
        if not self.ARPCheckBox.isChecked():
            packetFilter += 'ARP,'
        if not self.STPCheckBox.isChecked():
            packetFilter += 'STP,'
        if not self.EtherCheckBox.isChecked():
            packetFilter += 'Ether,'
        #dicionary for packet kinds and their methods for handling:
        captureDictionary = {
        TCP: handleTCP,
        UDP: handleUDP,
        ICMP: handleICMP,
        ARP: handleARP,
        STP: handleSTP,
        Ether: handleEther
        }
        if packetFilter != '': #if packetFilter isn't empty it means we need to filter the dictionary 
            packetFilter.rstrip(',').split(',')
            temp = captureDictionary.copy()
            for packetType, handler in temp.items():
                p = str(packetType).split('.')[3].rstrip("'>")
                if p in packetFilter:
                    del captureDictionary[packetType]
        return captureDictionary
        
        
    #method for updating the packet list
    def updatePacketList(self):
        while self.packetCaptureThread != None and not self.packetQueue.empty(): #check if there's a thread running and if the queue no empty
            packetInfo = self.packetQueue.get() #taking a packet from the queue
            self.packetModel.appendRow(QStandardItem(packetInfo)) #adding to packet list in GUI


    #method the double clicks in packet list, extended information section
    def handleItemDoubleClicked(self, index):
        packetIndex = index.row() #get the index of the row of the specific packet we want
        item = self.PacketList.model().itemFromIndex(index) #taking the packet from the list in GUI
        if item is not None and packetIndex in packetDicitionary: #checking if the packet in GUI list isn't None 
            p = packetDicitionary[packetIndex] #taking the matching packet from the packetDictionary
            self.MoreInfoLable.setText(p.moreInfo()) #add the information to the extended information section in GUI

#---------------------------------------------------Application-END----------------------------------------------------#

#---------------------------------------------------CustomMessageBox----------------------------------------------------#
class CustomMessageBox(QDialog):
    def __init__(self, title, text, icon='NoIcon', width=400, height=150, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title) #set the title for message box
        self.setWindowFlags(Qt.Dialog | Qt.WindowTitleHint | Qt.CustomizeWindowHint | Qt.WindowCloseButtonHint) #set the window flags
        self.setFixedSize(QSize(width, height)) #set the width and height for window
        self.initMessageBox(text, icon) #call initMessageBox for initializing the message box
        self.exec_() #execute the message box (show)

    def initMessageBox(self, text, icon):
        layout = QVBoxLayout() #create new layout
        horizontalLayout = QHBoxLayout() #create new horizontal layout
        textLabel = QLabel(text) #creat a text lable 
        textLabel.setAlignment(Qt.AlignCenter)  #set text alignment to center
        textLabel.setStyleSheet("font-size: 18px;") #set font size of text
        textLabel.setWordWrap(True) #set a wordWrap for better text representation

        if icon != 'NoIcon': #if true it means we need to set an icon for message box
            icon_label = QLabel()
            if icon == 'Information':
                icon_label.setPixmap(QApplication.style().standardIcon(QStyle.SP_MessageBoxInformation).pixmap(QSize(64, 64)))
                self.setWindowIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
            elif icon == 'Warning':
                icon_label.setPixmap(QApplication.style().standardIcon(QStyle.SP_MessageBoxWarning).pixmap(QSize(64, 64)))
                self.setWindowIcon(self.style().standardIcon(QStyle.SP_MessageBoxWarning))
            elif icon == 'Critical':
                icon_label.setPixmap(QApplication.style().standardIcon(QStyle.SP_MessageBoxCritical).pixmap(QSize(64, 64)))
                self.setWindowIcon(self.style().standardIcon(QStyle.SP_MessageBoxCritical))
            elif icon == 'Question':
                icon_label.setPixmap(QApplication.style().standardIcon(QStyle.SP_MessageBoxQuestion).pixmap(QSize(64, 64)))
                self.setWindowIcon(self.style().standardIcon(QStyle.SP_MessageBoxQuestion))
            icon_label.setAlignment(Qt.AlignLeft) #set the icon to the left
            spacer = QSpacerItem(10, 10, QSizePolicy.Fixed, QSizePolicy.Fixed) #create new spacer for the message box
            horizontalLayout.addWidget(icon_label) #add the icon to layout
            horizontalLayout.addItem(spacer) #add the spacer to layout
            horizontalLayout.addWidget(textLabel) #add the text label to layout
        else: #else no need for an icon 
            horizontalLayout.addWidget(textLabel) #add only the text label to layout

        horizontalLayout.setAlignment(Qt.AlignCenter) #set alignment of horizontal layout
        layout.addLayout(horizontalLayout) #add the horizontal layout to the vertical layout
        OKButton = QPushButton("OK") #create new OK button
        layout.addWidget(OKButton, alignment=Qt.AlignCenter) #add the button to the layout
        style = """
            QPushButton {
                background-color: rgb(123, 180, 255);
                border: 2px solid black;
                border-radius: 15px;
                padding: 4px;
                font-size: 15px; 
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
        print("Exiting")
    #----------------APP----------------#
    #GetAvailableNetworkInterfaces()
    #InitSniff()

