
import struct
import random
from protocols import PROTOCOLS
import socket
import zlib

# layer 7 - application
# get user data and encode to UTF-8

# data = input("Enter any data -> ")
data = "hello"
# print(f"{'Choose \n1. HTTPS\n2. DNS'}")
# protocol = input('Enter protocol name: ')

protocol = "HTTPS"

payload_text = data.encode('utf-8')

# layer 6 - presentation
# combine message length and original message

def construct_l6(payload):
    return struct.pack('!H',len(payload)) + payload

# 2 bytes of length 

l6_bytes = construct_l6(payload_text)

print("l6_bytes", l6_bytes)

# layer 5 - session
# maintain multiple sessions at same time using session ID

def capsulate_l5(data_bytes, session_id):
    return struct.pack('!I',session_id) + data_bytes

# 4 bytes of session ID

# generate random number act as a session id
ssn_id =  random.getrandbits(32)

l5_bytes = capsulate_l5(l6_bytes, ssn_id)

print("l5_bytes", l5_bytes)
# layer 4 - transport
# setup port number 

def construct_l4(data_bytes, dst_port):
    src_port = random.randint(49152, 65535)
    return struct.pack('!HHH', src_port, dst_port, len(data_bytes)) + data_bytes

# 6 bytes of port info

l4_bytes = construct_l4(l5_bytes, PROTOCOLS[protocol]["port"])

print("l4_bytes", l4_bytes)

# layer 3 - network
# adding src and dst ip address by l3 device

def capsulate_l3(data_bytes, src_ip, dst_ip):
    proto_num = PROTOCOLS[protocol]["protocol_number"]
    ttl= 64  # normally its value is 34,128,256
    return struct.pack('!BB4s4s',ttl, proto_num, socket.inet_aton(src_ip), socket.inet_aton(dst_ip)) + data_bytes

# 10 bytes of info

l3_bytes = capsulate_l3(l4_bytes, "192.168.10.10", "8.8.8.8")

print("l3_bytes", l3_bytes)
# layer 2 - data link
# switch adds destination MAC and source MAC 

# Header_types
# 0x0800 = IPv4 (Internet Protocol version 4 — the most common)
# 0x86DD = IPv6 (Internet Protocol version 6)
# 0x0806 = ARP (Address Resolution Protocol)

# Header = destination MAC + source MAC + header-type(IPv4/IPv6/ARP) 
# trailer is crc32 calculated from trailer + l3_bytes and "AND" with 0xFFFFFFFF(to make this always positive) 

def convert_mac(mac) -> bytes:
    return bytes.fromhex(mac.replace(":",""))

def capsulate_l2(data_bytes, src_mac, dest_mac):
    header = struct.pack("!6s6sH",convert_mac(src_mac) ,convert_mac(dest_mac) ,0x0800)
    trailer = zlib.crc32(header + data_bytes) & 0xFFFFFFFF
    return header + data_bytes + struct.pack("!I", trailer)

# 14 byte of header , 4 bytes of trailer
l2_bytes = capsulate_l2(l3_bytes, "00:12:34:56:78:90", "98:76:54:32:10:00")


print("l2_bytes", l2_bytes)
# layer 1 - physical layer
# everything is a byte here

def capsulate_l1(data_bytes):
    return " ".join(format(b, "08b") for b in data_bytes)

l1_bytes = capsulate_l1(l2_bytes)

print("l1_bytes", l1_bytes)


#===========================================================================================#
# receiving side decapsulation


# at layer 1 we received bits (0s 1s)
rec_data= l1_bytes

def decapsulate_l1(data_bytes):
    bytes_val = [int(chunk, 2) for chunk in data_bytes.split(" ")]
    return bytes(bytes_val)

rec_l2_bytes = decapsulate_l1(rec_data)


print("l2_bytes", rec_l2_bytes)

# layer 2 decapsualtion
# remove 14 bytes header and 4 bytes trailer , compare crc32 of (remaining data + header) with trailer


def decapsulate_l2(data_bytes):

    trail = struct.unpack("!I",data_bytes[-4:])[0]
    crc = zlib.crc32(data_bytes[0:-4]) & 0xFFFFFFFF

    if trail == crc :
        return data_bytes[14:-4]
    else:
        print("Failed CRC32 check","Dropping packet")
        return None

rec_l3_bytes = decapsulate_l2(rec_l2_bytes)


print("l3_bytes", rec_l3_bytes)
# layer 3 decapsulation
# remove 10 bytes of info header

def decapsulate_l3(data_bytes):
    if data_bytes == None:
        pass
    else:
        return data_bytes[10:]

rec_l4_bytes = decapsulate_l3(rec_l3_bytes)

print("l4_bytes", rec_l4_bytes)
# layer 4 decapsulation
# remove first 6 bytes of message 

def decapsualte_l4(data_bytes):
    return data_bytes[6:]

rec_l5_bytes = decapsualte_l4(rec_l4_bytes)

print("l5_bytes", rec_l5_bytes)
# layer 5 decapsulation
# remove session information ( first 4 bytes)

def decapsulate_l5(data_bytes):
    return data_bytes[4:]

rec_l6_bytes = decapsulate_l5(rec_l5_bytes)

print("l6_bytes", rec_l6_bytes)
# layer 6 decapsulation
# remove 2 bytes of header (length info)

def decapsulate_l6(data_bytes):
    return data_bytes[2:]

rec_l7_bytes = decapsulate_l6(rec_l6_bytes)

print("l7_bytes",rec_l7_bytes)
print("Your message:", rec_l7_bytes.decode("utf-8"))