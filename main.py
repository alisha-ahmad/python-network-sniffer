import socket
import struct
import binascii
import sys, ctypes
import numpy as np
from socket import *

def parse_TCP(header):
    thl = header[12] >> 4
    thl = thl * 4
    src_port = struct.unpack('!H', header[:2])[0] 
    dest_port = struct.unpack('!H', header[2:4])[0]
    ports = (src_port, dest_port) 
    print (f"Source port: {src_port} \t Destination port: {dest_port} \t THL: {thl}")
    return thl, ports
    
def parse_UDP(header):
    uhl = 8
    src_port = struct.unpack('!H', header[:2])[0] 
    dest_port = struct.unpack('!H', header[2:4])[0] 
    ports = (src_port, dest_port)
    print (f"Source port: {src_port} \t Destination port: {dest_port} \t UHL: {uhl}")
    return uhl, ports
    
def parse_ICMP(header):
    ichl = 8
    icmp_type = header[0]
    code = header[1]
    identifier = struct.unpack('!H', header[4:6])[0]
    sqn = struct.unpack('!H', header[6:8])[0]
    info = (icmp_type, code, identifier, sqn)
    print (f"Message type: {type} \t Code: {code} \t Identifier: {identifier} \t Sequence number: {sqn}")
    return ichl, info

def unpack(data):
    first_byte = data[0]
    version = first_byte >> 4
    ihl = first_byte & 0x0F
    ihl = ihl * 4  
    print(f"Version: {version} \t IHL: {ihl}")
    src_ip = inet_ntoa(data[12:16])
    dest_ip = inet_ntoa(data[16:20])
    print(f"Source IP: {src_ip} \t Destination IP: {dest_ip}")
    
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol = protocols.get(data[9], "unknown")
    print(f"Protocol: {protocol}")
    
    transport_header = data[ihl:]
    hdr_end, info = 0, []
    if protocol == "TCP":
        hdr_end, info = parse_TCP(transport_header)
    elif protocol == "UDP":
        hdr_end, info = parse_UDP(transport_header) 
    elif protocol == "ICMP":
        hdr_end, info = parse_ICMP(transport_header)
    else:
        return
    
    payload_start = ihl + hdr_end
    payload_len = len(data) - payload_start
    payload = data[payload_start:]
    print(f"Payload length: {payload_len}")
    print(f"Payload: {payload}")
    
    #port 80=http, 443=https
    if protocol in ("TCP", "UDP"):
        src_port, dest_port = info
        if src_port==80 or dest_port==80:
            print("Decoded payload:")
            print(payload.decode("utf-8", errors="ignore"))

try:
    #public network interface
    HOST = gethostbyname_ex(gethostname())
    print('IP: {}'.format(HOST))
    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    HOST = HOST[2][1]
    s.bind((HOST, 0))   #bind(host_ip, port))
    
    #include IP headers
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    s.ioctl(SIO_RCVALL, RCVALL_ON)    #enable promiscous mode
    for i in range(10):
        print()
        print(f"Packet number {i}:")
        packet = s.recvfrom(65565)
        print(format(packet))
        data = packet[0]
        address = packet[1]
        unpack(data)
    
except PermissionError:
    print('Error: Root access requires to use PF_PACKET raw sockets')
except Exception as e:
    print(f'Error: {e}')
