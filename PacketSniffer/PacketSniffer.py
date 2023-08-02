import sys
import signal
from abc import ABC, abstractmethod
import scapy.all as scapy
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP
from scapy.layers.l2 import Ether, Dot1Q, STP
from scapy.layers.dns import DNSQR, DNSRR
from scapy.all import Raw
import netifaces
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, Qt, QtGui
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QGroupBox, QWidget, QCheckBox, QDesktopWidget, QVBoxLayout, QTableWidgetItem


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
    

    def dnsInfo(self):
        output = ''
        if DNSQR in self.packet:
            dnsQry = self.packet[DNSQR].qname.decode('utf-8')
            output += f'DNS Query: {dnsQry}'
        elif DNSRR in self.packet:
            dnsAns = self.packet[DNSRR].rdata
            output += f'DNS Answer: {dnsAns}'
        return output


    def ipInfo(self): # method for ip configuration capture
        output = ''
        if IP in self.packet: 
            srcIp = self.packet[IP].src
            dstIp = self.packet[IP].dst
            output += f'Source IP: {srcIp}, Destination IP: {dstIp}\n'
            # additional Information for IPv4 and IPv6 packets
            if self.packet[IP].version == 4:
                ttl = self.packet[IP].ttl
                output += f'TTL: {ttl}\n'
                dscp = self.packet[IP].tos
                output += f'DSCP: {dscp}\n'

            elif self.packet[IP].version == 6:
                hopLimit = self.packet[IPv6].hlim
                output += f'Hop Limit: {hopLimit}\n'
                trafficClass = self.packet[IPv6].tc
                output += f'Traffic Class: {trafficClass}\n'

            output += f'Checksum: {self.packet.chksum}\n'
        output += f'Packet Size: {len(self.packet)} bytes\n'
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
            output += f'{self.name} Packet: {srcIp}:{srcPort} --> {dstIp}:{dstPort}'
        elif (self.packetType == TCP or self.packetType == UDP) and not self.packet.haslayer(IP):
            output += f'{self.name} Packet: {srcMac} --> {dstMac}'
        elif self.packetType == Ether and self.packet.haslayer(IP):
            output += f'{self.name} Packet: {srcMac}:({srcIp}) --> {dstMac}:({dstIp})'
        elif self.packetType == Ether and not self.packet.haslayer(IP):
            output += f'{self.name} Packet: {srcMac} --> {dstMac}'

        dnsInfo = self.dnsInfo() #call dns method
        if dnsInfo != '':
            output += f' {dnsInfo}'
        output += f' | Size: {packetSize} bytes'
        return output


    def moreInfo(self): # method to print more information for derived classes to implement
        output = ''
        # print the packet information
        if (self.packetType == TCP or self.packetType == UDP) and self.packet.haslayer(IP):
            output += f'{self.name} Packet - Source Port: {self.packet.sport}, Destination Port: {self.packet.dport}\n'
        else:
            output += f'{self.name} Packet - Source MAC: {self.packet.src}, Destination MAC: {self.packet.dst}\n'

        dnsInfo = self.dnsInfo() #call dns method
        if dnsInfo != '':
            output += f'{dnsInfo}\n'
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

        if self.packet[self.packetType].options: # print TCP Options (if available)
            output += 'TCP Options:\n'
            for option in self.packet[self.packetType].options:
                output += f'{option[0]}: {option[1]}\n'
        
        output += f'Sequence Number: {self.packet.seq}, Acknowledgment Number: {self.packet.ack}\n'
        output += f'Flags: {flagsDict}\n'
        output += f'Window Size: {self.packet.window}\n'
        output += '\n----------------------------------------------------------\n'
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


    def moreInfo(self): # method for packet information
        output = f'{super().moreInfo()}'
        output += '\n----------------------------------------------------------\n'
        return output

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
            output += f'{self.name} Packet: {srcIp} --> {dstIp} | Type: {icmpType}, Code: {icmpCode} | Size: {packetSize} bytes'
        else:
            output += f'{self.name} Packet: --> {self.packet.summary()}, Type: {icmpType}, Code: {icmpCode} | Size: {packetSize} bytes'
        return output


    def moreInfo(self): # method for packet information
        output = ''
        if ICMP in self.packet:
            # insert ICMP specific information
            icmpType = self.packet[ICMP].type
            icmpCode = self.packet[ICMP].code
            output += f'{self.name} Packet - Type: {icmpType}, Code: {icmpCode}\n'
            
        output += self.ipInfo() #call ip method 
        output += '\n----------------------------------------------------------\n'
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
        output += f'{self.name} Packet: {srcMac}:({srcIp}) --> {dstMac}:({dstIp}) | Size: {packetSize} bytes'
        return output


    def moreInfo(self):  # method for ARP packet information
        output = ''
        output += f'{self.name} Packet - Source MAC: {self.packet[self.packetType].hwsrc}, Destination MAC: {self.packet[self.packetType].hwdst}\n'
        output += f'Source IP: {self.packet[self.packetType].psrc}, Destination IP: {self.packet[self.packetType].pdst}\n'
        if ARP in self.packet:
            srcMac = self.packet[ARP].hwsrc
            dstMac = self.packet[ARP].hwdst
            srcIp = self.packet[ARP].psrc
            dstIp = self.packet[ARP].pdst
            output += f'Sender MAC: {srcMac}, Sender IP: {srcIp}\n'
            output += f'Target MAC: {dstMac}, Target IP: {dstIp}\n'
            output += f'Packet Size: {len(self.packet)} bytes\n'
        output += '\n----------------------------------------------------------\n'
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
            output += f'{self.name} Packet: {self.packet.src} --> {self.packet.dst} | Size: {packet_size} bytes'
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
            output += f'{self.name} Packet - STP Protocol: {stpProto}, Version: {stpVersion}\n'
            output += f'Source MAC: {self.packet.src}, Destination MAC: {self.packet.dst}\n'
            output += f'Bridge ID: {stpBridgeId}, Port ID: {stpPortId}\n'
            output += f'Path Cost: {stpPathCost}, Age: {stpAge}\n'
        output += f'Packet Size: {len(self.packet)} bytes\n'
        output += '\n----------------------------------------------------------\n'
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
            output += f'VLAN ID: {vlan_id}\n'
        output += '\n----------------------------------------------------------\n'
        return output

# --------------------------------------------Ether-END----------------------------------------------#

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
    print(TCP_Object.info())
    print(f'id: {packetCounter}')


def handleUDP(packet):
    global packetCounter
    UDP_Object = UDP_Packet(packet, packetCounter)
    packetDicitionary[UDP_Object.getId()] = UDP_Object
    packetCounter += 1
    print(UDP_Object.info())
    print(f'id: {packetCounter}')


def handleICMP(packet):
    global packetCounter
    ICMP_Object = ICMP_Packet(packet, packetCounter)
    packetDicitionary[ICMP_Object.getId()] = ICMP_Object
    packetCounter += 1
    print(ICMP_Object.info())
    print(f'id: {packetCounter}')


def handleARP(packet):
    global packetCounter
    ARP_Object = ARP_Packet(packet, packetCounter)
    packetDicitionary[ARP_Object.getId()] = ARP_Object
    packetCounter += 1
    print(ARP_Object.info())
    print(f'id: {packetCounter}')


def handleSTP(packet):
    global packetCounter
    STP_Object = STP_Packet(packet, packetCounter)
    packetDicitionary[STP_Object.getId()] = STP_Object
    packetCounter += 1
    print(STP_Object.info())
    print(f'id: {packetCounter}')


def handleEther(packet):
    global packetCounter
    Ether_Object = Ether_Packet(packet, packetCounter)
    packetDicitionary[Ether_Object.getId()] = Ether_Object
    packetCounter += 1
    print(Ether_Object.info())
    print(f'id: {packetCounter}')

#-----------------------------------------HANDLE-FUNCTIONS-END-----------------------------------------#

packetDicitionary = {} #initialize the packet dictionary
packetCounter = 1 # global counter for dictionary elements
stopCapture = False # for ctrl + c operation (stopping capture)

def signalHandler(signal, frame): # handle method for stopping the program
    global stopCapture
    print('\nStopping packet capturing...')
    stopCapture = True

signal.signal(signal.SIGINT, signalHandler) # signal the stopping operation

def PacketCapture(packet): # method that handles the packet capturing
    #dicionary for packet kinds and their methods for handling:
    CaptureDicitionary = {
    TCP: handleTCP,
    UDP: handleUDP,
    ICMP: handleICMP,
    ARP: handleARP,
    STP: handleSTP,
    Ether: handleEther
    }
    #for each packet we receive we send it to the dict to determine its identity and call the necessary handle method
    for packetType, handler in CaptureDicitionary.items():
        if packet.haslayer(packetType):
            handler(packet)
            break
    else:
        print(f'Unknown Packet Type --> {packet.summary()}') #print summary of the packet')
    if stopCapture:
        print('Packet capturing stopped.')
        sys.exit(0)  # exit the program 


# method to initalize the sniffer
def InitSniff(interface=None):
    try:
        if interface != None:
            scapy.sniff(iface = interface, prn = PacketCapture, filter='', store=0) #calling scapy sniff method
        else:
            scapy.sniff(prn = PacketCapture, filter='tcp', store=0)
    except KeyboardInterrupt:
        print('\nKeyboard interrupted program (possible exception)')

#--------------------------------------------Application----------------------------------------------#
class PacketSniffer(QMainWindow):
    def __init__(self):
        super(PacketSniffer, self).__init__()
        loadUi("PacketSniffer.ui",self)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Packet Sniffer')
        self.center()
        self.show()
		
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
    
 
        

#--------------------------------------------Application-END----------------------------------------------#

#--------------------------------------------MAIN----------------------------------------------#

if __name__ == '__main__':
    #----------------APP----------------#
    app = QApplication(sys.argv)
    sniffer = PacketSniffer()
    try:
        sys.exit(app.exec_())
    except:
        print("Exiting")
    #----------------APP----------------#
    GetAvailableNetworkInterfaces()
    InitSniff()

