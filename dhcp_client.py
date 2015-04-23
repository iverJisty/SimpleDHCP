#
#   DHCP Client
#
#   Author : iver Liu
#

import socket
import struct
from random import randint
from dhcp_base import *

class DHCPClient:

    def __init__(self):
        self.transactionID = b''
        self.mac = randomMacInBytes()
        self.packet = b''

    def discover(self):
        for i in range(4):       # random choose 4 bytes transaction ID
            t = randint(0,255)
            self.transactionID += struct.pack('!B', t)
        
        #buildPacket
        packet = b''
        packet += b'\x01'   # BOOTREQUEST
        packet += b'\x01'   # htype : Ethernet
        packet += b'\x06'   # hlen  : 6
        packet += b'\x00'   # hops  : 0
        packet += self.transactionID    # xid  ( random number )
        packet += b'\x00\x00'           # secs(Second elapsed)      : 0 <opt.>
        packet += b'\x80\x00'           # flag : BROADCAST + reserved flags
        packet += b'\x00\x00\x00\x00'   # ciaddr(Client IP)         : 0
        packet += b'\x00\x00\x00\x00'   # yiaddr(Your (client) IP)  : 0
        packet += b'\x00\x00\x00\x00'   # siaddr(Next Server IP)    : 0
        packet += b'\x00\x00\x00\x00'   # giaddr(Relay agent IP)    : 0
        #packet += getMacInBytes()       # chaddr(Client MAC) 6 bytes
        packet += self.mac
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # padding 10 bytes
        packet += b'\x00' * 64          # sname(Server Host Name)
        packet += b'\x00' * 128         # file(Boot file name not given)
        packet += b'\x63\x82\x53\x63'   # magic cookie : DHCP
        packet += b'\x35\x01\x01'       # DHCP Message Type : DHCPDISCOVER
        # packet += b'\x3d\x06' + getMacInBytes()   #Client identifier
        packet += b'\x37\x03\x03\x01\x06'  # Parameter Request List : Router, Mask, DNS
        packet += b'\xff'               # End Option
        return packet

    def request(self,data):
        packet = b''
        packet += b'\x01'   # BOOTREQUEST
        packet += b'\x01'   # htype : Ethernet
        packet += b'\x06'   # hlen  : 6
        packet += b'\x00'   # hops  : 0
        packet += self.transactionID    # xid  ( random number )
        packet += b'\x00\x00'           # secs(Second elapsed)      : 0 <opt.>
        packet += b'\x80\x00'           # flag : BROADCAST + reserved flags
        packet += data['yiaddr']        # ciaddr(Client IP)         : 0
        packet += b'\x00\x00\x00\x00'   # yiaddr(Your (client) IP)  : 0
        packet += data['siaddr']        # siaddr(Next Server IP)    : 0
        packet += b'\x00\x00\x00\x00'   # giaddr(Relay agent IP)    : 0
        #packet += getMacInBytes()       # chaddr(Client MAC) 6 bytes
        packet += self.mac
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # padding 10 bytes
        packet += b'\x00' * 64          # sname(Server Host Name)
        packet += b'\x00' * 128         # file(Boot file name not given)
        packet += b'\x63\x82\x53\x63'   # magic cookie : DHCP
        packet += b'\x35\x01\x03'       # DHCP Message Type : DHCPREQUEST
        # packet += b'\x3d\x06' + getMacInBytes()   #Client identifier
        packet += b'\x32\x04' + data['yiaddr']
        tmp = data['options'].index(b'\x36\x04')
        packet += data['options'][tmp:tmp+6]  # DHCP Server Identifier
        packet += b'\xff'               # End Option
        self.packet = packet
        return packet
    
    def handleACK(self,data):
        
        try:
            pos = data['options'].index(b'\x35\x01')    # Test Message Type
        except ValueError as e:
            print("No Message type found")

        if data['options'][pos+2] == 5:                 # ACK
            tmp = data['options'].index(b'\x36\x04')    # Server Identifier
            if self.packet.find(data['options'][tmp:tmp+6]) > 0:
                print("Identify the server")
                return 1
            else:
                print("Fake Server Detect")
                return 0

        elif data['options'][pos+2] == 6:               # NAK
            print("Get NAK from server")

    def printPacket(self,data):
        print("IP Address      : ",format( '.'.join(map(lambda x:str(x),data['yiaddr'][:]))))
        tmp = data['options'].index(b'\x01\x04')    # Option 1 : Subnet Mask
        print("Subnet Mask     : ",format( '.'.join(map(lambda x:str(x),data['options'][tmp+2:tmp+6] )))) 
        tmp = data['options'].index(b'\x03\x04')    # Option 3 : Router
        print("Default Gateway : ",format( '.'.join(map(lambda x:str(x),data['options'][tmp+2:tmp+6] ))))
        tmp = data['options'].index(b'\x06\x04')    # Option 6 : DNS Server  
        print("DNS Server      : ",format( '.'.join(map(lambda x:str(x),data['options'][tmp+2:tmp+6] ))))
        return None


if __name__ == '__main__':
    
    dhcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # set to use broadcast
    
    try:
        dhcp.bind(('',68)) # bind to receive from 68
    except Exception as e:
        print('port 68 in use ...')
        dhcp.close()
        input('press any key to quit...')
        exit()

    #   Send DHCP Discover
    client = DHCPClient()
    dhcp.sendto(client.discover(),('<broadcast>',67))
    
    print('DHCP Discover sent ... \n')

    #   Expect to receive DHCP Offer
    dhcp.settimeout(3)
    try:
        while True:
            data = dhcp.recv(1024)
    except socket.timeout as e:
        print(e)
        
    print('Get the Offer from Server ... ')
    value = packetUnpack(data)
    dhcp.sendto(client.request(value),('<broadcast>',67))
    print('Send the Request to Server ...')
    
    #   Expect to receive DHCP ACK or NAK
    dhcp.settimeout(3)
    try:
        while True:
            data = dhcp.recv(1024)
    except socket.timeout as e:
        print(e)

    data = packetUnpack(data)



    if client.handleACK(data) == 1:                    # Identify the Packet
        client.printPacket(value) 
        


    #print(value)

    

    
    
    dhcp.close()    
    exit()

