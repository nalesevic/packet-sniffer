# author: Nizam Alesevic
import socket
import struct
import textwrap
from packet import packet
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '   '

NUM_PACKETS = 100
# ntohs make sure that is compatible with all machines
# {} placeholders
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    capture = open('capture.txt', 'w')
    capture.write('')
    capture.close()
    i = 0
    packets = []
    while i < NUM_PACKETS:
        i += 1
        raw_data, addr = conn.recvfrom(65536);
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
        # making sure that it's a ip version 4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_1, data))
                packets.append(packet('ICMP', src, target, data))
                capture = open('capture.txt', 'a')
                capture.write('\n\nICMP Packet:\n Type: {}, Code: {}, Checksum: {} \n  ICMP Data:\n{}'.format(icmp_type, code, checksum, format_multi_line(DATA_TAB_3, data)))
                capture.close()
            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, ack))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'TCP Data:')
                print(format_multi_line(DATA_TAB_1, data))
                packets.append(packet('TCP', src, target, data))
                capture = open('capture.txt', 'a')
                capture.write('\n\nTCP Packet:\n Source Address: {}\n Destination Address: {} \n  Source Port: {}\n  Destination Port: {} \n  ACK: {}, SYN: {}, TCP Data: \n{}'.format(src, target, src_port, dest_port, flag_ack, flag_syn, format_multi_line(DATA_TAB_3, data)))
                capture.close()
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(TAB_2 + 'UDP Data:')
                print(format_multi_line(DATA_TAB_1, data))
                packets.append(packet('UDP', src, target, data))
                capture = open('capture.txt', 'a')
                capture.write('\n\nUDP Packet:\n Source Address: {}\n Destination Address: {} \n  Source Port: {}\n  Destination Port: {} \n   UDP Data: \n{}'.format(src, target, src_port, dest_port, format_multi_line(DATA_TAB_3, data)))
                capture.close()
            else:
                print(TAB_1 + 'Data')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print('Data')
            print(format_multi_line(DATA_TAB_1, data))

    while True:
        getInput = input('Enter ip address or protocol name (to exit .): ')
        if(getInput == '.'):
            print('goodbye')
            break;
        adr = 0
        for x in packets:
            if(getInput == x.src_ip or getInput == x.dest_ip):
                print('\n {} Packet:\n Source Address: {}\n Destination Address: {}\n  {} Data:\n  {}'.format(x.type, x.src_ip, x.dest_ip, x.type, format_multi_line(DATA_TAB_3, x.data)))
                adr = 1
            if(getInput.lower() == x.type.lower()):
                print('\n {} Packet:\n Source Address: {}\n Destination Address: {}\n  {} Data:\n  {}'.format(x.type, x.src_ip, x.dest_ip, x.type,format_multi_line(DATA_TAB_3, x.data)))
                adr = 1
        if adr == 0:
            print('No such packet')
# unpack ethernet frame
# ! make sure that is network data
# 12s receiver + sender
# H small int = 2 bits
# :14 start at beginning at get next 14
# it is still not readable by humans
# htons makes protocol readable
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]);
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# returns human readable MAC address(AA:12:B3:23:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr);
    return ':'.join(bytes_str).upper();

# unpacking IPv4 data line 11
def ipv4_packet(data):
    version_header_length = data[0]
    # we need to bit shift to get only the version
    version = version_header_length >> 4
    # do the bitwise and..to find out where data starts
    header_length = (version_header_length & 15)
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    # data[header_length:] is actual data
    return version, header_length, ttl, proto, get_ip_addr(src), get_ip_addr(target), data[header_length:]

# returns human readable IP address(192.168.1.1)
def get_ip_addr(addr):
    return '.'.join(map(str, addr))

# unpacking ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    # return also actual data
    return icmp_type, code, checksum, data[4:]
# unpacking TCP segment
# offset = hello&goodbye between server&user
def tcp_segment(data):
    (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 18) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# unpacking UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# formats multi line data, so i does not appear all in one line
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()
