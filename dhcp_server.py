#
#   DHCP Server
#
#   Author : iver Liu
#

import socket
import struct
import random
import time
from random import randint

from dhcp_base import *

class DHCPServer:

    def __init__(self,ip):
        self.ip     = ip
        self.empty  = 0     # if pool is empty
        self.siaddr = b''
        self.lease_table = [['IP Address','Mac Address','Start Time']]
        
        self.pool   = []    # pool from 192.168.123.100 ~ 200
        for i in range(100,201):
            self.pool.append('192.168.123.' + str(i))


    def offer(self,data):

        self.op     = b'\x02'
        self.htype  = b'\x01'
        self.hlen   = b'\x06'
        self.hops   = b'\x00'
        self.xid    = data['xid']
        self.secs   = b'\x00\x00'
        self.ciaddr = b'\x00\x00\x00\x00'
        try:
            self.cli_ip = random.choice(self.pool)
        except IndexError as e:
            self.empty = 1
            self.cli_ip = '169.254.1.1'
            

        self.yiaddr = packIPInBytes(self.cli_ip)
        self.siaddr = packIPInBytes(self.ip)
        self.flags  = b'\x80\x00'                    # BROADCAST
        self.giaddr = b'\x00\x00\x00\x00'
        self.chaddr = data['chaddr']
        self.sname  = b'\x00' * 64
        self.file_  = b'\x00' * 129
        self.magic  = b'\x63\x82\x53\x63'            # Magic Cookie
        # Options
        self.message= b'\x35\x01\x02'                # DHCPOFFER
        self.netmask= b'\x01\x04\xff\xff\xff\x00'    # Subnet Mask 255.255.255.0
        self.lease  = b'\x33\x04\x00\x00\xa8\xc0'    # Lease  Time 43200s(12 hr)
        self.dns    = b'\x06\x04\x08\x08\x08\x08'    # DNS  Server 8.8.8.8
        self.dhcp_s = b'\x36\x04' + self.siaddr      # DHCP Server Identifier 
        self.router = b'\x03\x04' + self.siaddr      # Router  
        self.broadcast = b'\x1c\x04' + self.siaddr[0:-1] + b'\xff' # Broadcast Addr.
        
        packet = self.op + self.htype + self.hlen + self.hops + self.xid + self.secs + self.flags + self.ciaddr + self.yiaddr + self.siaddr  + self.giaddr + self.chaddr + self.sname  + self.file_ + self.magic + self.message + self.netmask + self.lease + self.dns    + self.dhcp_s + self.router  + self.broadcast + b'\xff'
        return packet
        
    def ack_nac(self,data):
        if self.empty == 1:
            self.message = b'\x35\x01\x06'                # DHCP NAK

            packet = self.op + self.htype + self.hlen + self.hops + self.xid + self.secs + self.flags + self.ciaddr + self.yiaddr + self.siaddr  + self.giaddr + self.chaddr + self.sname  + self.file_ + self.magic + self.message + self.dhcp_s + b'\xff'
            return packet

        else:
            self.message = b'\x35\x01\x05'                # DHCP ACK
            self.pool.remove(self.cli_ip)
            mac_address = ':'.join(map(lambda x:str(hex(x).split('x')[1]),self.chaddr[0:6]))
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            self.lease_table.append([self.cli_ip,mac_address,now])
            
            packet = self.op + self.htype + self.hlen + self.hops + self.xid + self.secs + self.flags + self.ciaddr + self.yiaddr + self.siaddr  + self.giaddr + self.chaddr + self.sname  + self.file_ + self.magic + self.message + self.netmask + self.lease + self.dns    + self.dhcp_s + self.router  + self.broadcast + b'\xff'
            return packet

    def printLeaseTable(self):
        print(self.lease_table)

    # val = time.strptime(now,'%Y-%m-%d %H:%M:%S')  => can transfer from timestamp to time tuple

    def checkRequest(self,data):
        if data['siaddr'] == self.siaddr:
            return True
        else:
            return False
    

if __name__ == '__main__':
    dhcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # set to use broadcast

    # ip = input("Which ip(interface) to listen ?")
    ip = '192.168.200.217'

    # Create the Server
    server = DHCPServer(ip)

    try:
        dhcp.bind(('',67)) # bind to receive from 68
    except Exception as e:
        print('port 67 in use ...')
        dhcp.close()
        input('press any key to quit...')
        exit()
    
    while True:
        data,(client,port) = dhcp.recvfrom(1024)
        print(" Connect Client {}".format(client,port))
        
        data = packetUnpack(data)

        try:
            pos = data['options'].index(b'\x35\x01')
        except ValueError as e:
            print("No Message type found")
       
        #print(str(pos) + " is the position")
        #print(data['options'][pos+2])


        # Determine whether this is a DISCOVER or REQUEST
        if data['options'][pos+2] == 1:
            print("Got the discover packet...")

            dhcp.sendto(server.offer(data),('<broadcast>',68))
            print("Send DHCP Offer...")
        elif data['options'][pos+2] == 3:
            print("Get the Request from Client...")
            if server.checkRequest(data):
                # print("Client Request me ... not another Router!!!")
                dhcp.sendto(server.ack_nac(data),('<broadcast>',68))
                print("Send the DHCP ACK ( or NAK )")
                print("----------------------------")
                server.printLeaseTable()
                print("----------------------------")
            else:
                print("Another Router got it ... damm it!")
                







#        dhcp.settimeout(3)
#        try:
#            while True:
#                data = dhcp.recv(1024)
#        except socket.timeout as e:
#            print("Didn't "),
        

        

            



    
    dhcp.close()
    exit()



