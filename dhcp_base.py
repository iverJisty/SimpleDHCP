#
#   DHCP Base Structure
#
#   @Author : iver Liu
#

import socket
import struct
from uuid import getnode as get_mac
from random import randint

def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    
    while len(mac) < 12:
        mac = '0' + mac
    
    macb = b''

    for i in range(0,12,2):
        tmp = int(mac[i:i+2], 16)
        macb += struct.pack('!B', tmp)
        # pack every two byte 
    return macb

def randomMacInBytes():

    randList = []
    for i in range(0,12):
        randList.append(hex(randint(0,16)).split('x')[1])

    fakeMac = ''.join( str(e) for e in randList )
    print(fakeMac)

    fake_macb = b''
    for i in range(0,12,2):
        tmp = int(fakeMac[i:i+2], 16)
        fake_macb += struct.pack('!B', tmp)

    return fake_macb

def packIPInBytes(ip):
    
    tmp = ip.split('.')
    ipb = b''
    for i in tmp:
        ipb += struct.pack('!B', int(i))

    return ipb


def packetUnpack( packet ):
    data = {}   # empty dictionary 
    data['op'] = packet[0]
    data['htype'] = packet[1]
    data['hlen'] = packet[2]
    data['hops'] = packet[3]
    data['xid'] = packet[4:8]
    data['secs'] = packet[8:10]
    data['flags'] = packet[10:12]
    data['ciaddr'] = packet[12:16]
    data['yiaddr'] = packet[16:20]
    data['siaddr'] = packet[20:24]
    data['giaddr'] = packet[24:28]
    data['chaddr'] = packet[28:43] #Client HW addr. with some useless(? padding
    data['sname'] = packet[43:107]
    data['file'] = packet[107:235]
    data['options'] = packet[235:547]

    return data





