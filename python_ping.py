import socket
import pack_headers
import unpack_headers
import sys
import os
import struct
import array
import binascii
import datetime
import time
import netifaces

#Create a Socket that able to access ICMP headers
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

interface_name = sys.argv[2]
interface_ip = netifaces.ifaddresses(interface_name)[2][0]['addr']

sock.bind((interface_ip, 0))

#for ICMP Checksum
def checksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res = res + (res >> 16)

    return ((~res) & 0xffff)


#Generate ICMP Packet
def build_icmp_header(checksum=0, data='', seq_number=0):
    icmp_type = 8 #8 bits
    icmp_code = 0 #8 bits
    icmp_chsum= checksum #16 bits
    icmp_pid  = os.getpid() #2bytes
    icmp_seq  = seq_number #2bytes

    packet = struct.pack("BBHHH", icmp_type, icmp_code, int(icmp_chsum), icmp_pid, icmp_seq)
    
    if(data):
        icmp_data = data 
        return (packet + icmp_data)

    return (packet)


#unpack ICMP Packet
def unpack_icmp_header(packet_buffer):
    icmp_data = ""
    icmp_data = struct.unpack("1s1s2s2s2s", packet_buffer)
    icmp_data_list = []
    #print(icmp_data)

    for x in icmp_data:
        icmp_data_list.append(binascii.hexlify(x).decode())
    
    #Append recved PID as raw data
    icmp_data_list.append(icmp_data[3])
    
    return icmp_data_list


#Send ICMP echo request packet
def send_icmp_packet(dst_ip, seq_number, socket_handler):

    #Generate a dummy packet for ICMP Header checksum
    icmp_packet_for_checksum  = build_icmp_header(0, '', seq_number)
    sample_data = ("----Hello World----").encode()
    
    icmp_checksum = checksum(icmp_packet_for_checksum + sample_data)
    
    #Generate a new packet with ICMP Checksum
    icmp_packet = build_icmp_header(icmp_checksum, sample_data, seq_number)
    
    
    #Send the ping request
    socket_handler.sendto(icmp_packet, (dst_ip, 1))
    

#Recv ICMP echo reply
def recv_icmp_ping(socket_handler):

    frame = socket_handler.recv(65535)
    ip_packet = unpack_headers.IP_Header(frame[:20])
    icmp_packet = unpack_icmp_header(frame[20:28])

    ttl = ip_packet.ttl_val
    src_ip = ip_packet.src_address
    
    return [icmp_packet, ttl, src_ip]
    


def ping_sender():
    
    target_ip = sys.argv[1]
    try:
        x = 1
        while (True):
        #for x in range(4):
            start_time = datetime.datetime.now()
            #Send one ping
            send_icmp_packet(target_ip, x , sock)
        
            #Recv one ping
            response = recv_icmp_ping(sock)
            #print(response)
            #print((os.getpid()))
            end_time = datetime.datetime.now()
            
            time.sleep(1)
            
            #Get time diff
            time_diff = ((end_time - start_time).microseconds /1000)
             
            icmp_code = response[0][0]
            seq_num_in_hex = response[0][4][:2]
            
            #print("seq in hex", seq_num_in_hex)
        
            seq_num_in_dec = int(("0x"+seq_num_in_hex), 16)
            #print(seq_num_in_dec)
            
            ttl = response[1]
            src_ip = response[2]
            process_pid = os.getpid()
            
            #Get receved packed process ID
            packet_pid = struct.unpack("<H", response[0][5])[0]
            
            output = ""
            #print("x value", x)
            #print("icmp code", icmp_code)
            #print("seq_num", seq_num_in_dec)
            
            
            if(process_pid == packet_pid):
            
                if(icmp_code=='00'):
                    #if(int(seq_num_in_dec) == x):
                    output = (f"64 bytes from {src_ip}: icmp_seq={seq_num_in_dec} ttl={ttl} time={time_diff} ms")
                    print(output)
                    x+=1
            else:
                
                if(icmp_code=='03'):
                    output = "Destination Unreachable"
                    print(output)
                    x+=1

            #print("\n")
            #time.sleep(1)
        
    except KeyboardInterrupt as key_intrrupt:
        print(f"--- {src_ip} ping statistics ---")
        #//
        sys.exit(1)

ping_sender()


