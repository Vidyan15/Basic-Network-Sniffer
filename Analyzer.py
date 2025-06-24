#!/usr/bin/env python3
"""
Network Packet Sniffer
A basic network traffic analyzer for educational purposes.
"""

import socket
import struct
import textwrap
import sys
import argparse
from datetime import datetime

class PacketSniffer:
    def __init__(self, interface=None, count=None, protocol_filter=None):
        self.interface = interface
        self.count = count
        self.protocol_filter = protocol_filter
        self.packet_count = 0
        
    def create_socket(self):
        """Create a raw socket for packet capture"""
        try:
            # Create raw socket
            if sys.platform.startswith('win'):
                # Windows
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Linux/Unix
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            return sock
        except PermissionError:
            print("Error: Root/Administrator privileges required for packet capture!")
            sys.exit(1)
        except Exception as e:
            print(f"Error creating socket: {e}")
            sys.exit(1)

    def parse_ethernet_header(self, data):
        """Parse Ethernet header"""
        eth_header = struct.unpack('!6s6sH', data[:14])
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_type = eth_header[2]
        
        return {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'type': eth_type,
            'payload': data[14:]
        }

    def parse_ip_header(self, data):
        """Parse IP header"""
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        
        version = ip_header[0] >> 4
        header_length = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        
        return {
            'version': version,
            'header_length': header_length,
            'ttl': ttl,
            'protocol': protocol,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'payload': data[header_length:]
        }

    def parse_tcp_header(self, data):
        """Parse TCP header"""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence = tcp_header[2]
        acknowledgment = tcp_header[3]
        flags = tcp_header[5]
        
        # Extract flags
        flag_urg = (flags & 32) >> 5
        flag_ack = (flags & 16) >> 4
        flag_psh = (flags & 8) >> 3
        flag_rst = (flags & 4) >> 2
        flag_syn = (flags & 2) >> 1
        flag_fin = flags & 1
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'sequence': sequence,
            'acknowledgment': acknowledgment,
            'flags': {
                'URG': flag_urg,
                'ACK': flag_ack,
                'PSH': flag_psh,
                'RST': flag_rst,
                'SYN': flag_syn,
                'FIN': flag_fin
            },
            'payload': data[20:]
        }

    def parse_udp_header(self, data):
        """Parse UDP header"""
        udp_header = struct.unpack('!HHHH', data[:8])
        
        src_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'length': length,
            'payload': data[8:]
        }

    def parse_icmp_header(self, data):
        """Parse ICMP header"""
        icmp_header = struct.unpack('!BBH', data[:4])
        
        icmp_type = icmp_header[0]
        code = icmp_header[1]
        checksum = icmp_header[2]
        
        return {
            'type': icmp_type,
            'code': code,
            'checksum': checksum,
            'payload': data[4:]
        }

    def get_protocol_name(self, protocol_num):
        """Get protocol name from number"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        return protocols.get(protocol_num, f'Unknown({protocol_num})')

    def format_payload(self, data, max_lines=10):
        """Format payload data for display"""
        if not data:
            return "No payload"
        
        # Show hex and ASCII representation
        lines = []
        for i in range(0, min(len(data), max_lines * 16), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f'{i:08x}: {hex_part:<48} {ascii_part}')
        
        if len(data) > max_lines * 16:
            lines.append(f'... ({len(data) - max_lines * 16} more bytes)')
        
        return '\n'.join(lines)

    def display_packet_info(self, packet_data):
        """Display formatted packet information"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        print(f"\n{'='*80}")
        print(f"Packet #{self.packet_count} - {timestamp}")
        print(f"{'='*80}")
        
        # Parse based on platform
        if sys.platform.startswith('win'):
            # Windows - starts with IP header
            ip_info = self.parse_ip_header(packet_data)
        else:
            # Linux - starts with Ethernet header
            eth_info = self.parse_ethernet_header(packet_data)
            print(f"Ethernet Header:")
            print(f"  Source MAC: {eth_info['src_mac']}")
            print(f"  Dest MAC: {eth_info['dest_mac']}")
            print(f"  Type: 0x{eth_info['type']:04x}")
            
            if eth_info['type'] == 0x0800:  # IPv4
                ip_info = self.parse_ip_header(eth_info['payload'])
            else:
                print(f"  Non-IPv4 packet (Type: 0x{eth_info['type']:04x})")
                return

        # Display IP information
        print(f"\nIP Header:")
        print(f"  Version: {ip_info['version']}")
        print(f"  Source IP: {ip_info['src_ip']}")
        print(f"  Dest IP: {ip_info['dest_ip']}")
        print(f"  Protocol: {self.get_protocol_name(ip_info['protocol'])}")
        print(f"  TTL: {ip_info['ttl']}")

        # Parse transport layer based on protocol
        if ip_info['protocol'] == 6:  # TCP
            tcp_info = self.parse_tcp_header(ip_info['payload'])
            print(f"\nTCP Header:")
            print(f"  Source Port: {tcp_info['src_port']}")
            print(f"  Dest Port: {tcp_info['dest_port']}")
            print(f"  Sequence: {tcp_info['sequence']}")
            print(f"  Acknowledgment: {tcp_info['acknowledgment']}")
            
            # Display flags
            active_flags = [flag for flag, value in tcp_info['flags'].items() if value]
            print(f"  Flags: {', '.join(active_flags) if active_flags else 'None'}")
            
            # Show payload if exists
            if tcp_info['payload']:
                print(f"\nTCP Payload ({len(tcp_info['payload'])} bytes):")
                print(self.format_payload(tcp_info['payload']))

        elif ip_info['protocol'] == 17:  # UDP
            udp_info = self.parse_udp_header(ip_info['payload'])
            print(f"\nUDP Header:")
            print(f"  Source Port: {udp_info['src_port']}")
            print(f"  Dest Port: {udp_info['dest_port']}")
            print(f"  Length: {udp_info['length']}")
            
            # Show payload if exists
            if udp_info['payload']:
                print(f"\nUDP Payload ({len(udp_info['payload'])} bytes):")
                print(self.format_payload(udp_info['payload']))

        elif ip_info['protocol'] == 1:  # ICMP
            icmp_info = self.parse_icmp_header(ip_info['payload'])
            print(f"\nICMP Header:")
            print(f"  Type: {icmp_info['type']}")
            print(f"  Code: {icmp_info['code']}")
            print(f"  Checksum: 0x{icmp_info['checksum']:04x}")
            
            # Show payload if exists
            if icmp_info['payload']:
                print(f"\nICMP Payload ({len(icmp_info['payload'])} bytes):")
                print(self.format_payload(icmp_info['payload']))

    def should_capture_packet(self, packet_data):
        """Determine if packet should be captured based on filters"""
        if not self.protocol_filter:
            return True
        
        try:
            if sys.platform.startswith('win'):
                ip_info = self.parse_ip_header(packet_data)
            else:
                eth_info = self.parse_ethernet_header(packet_data)
                if eth_info['type'] != 0x0800:  # Not IPv4
                    return False
                ip_info = self.parse_ip_header(eth_info['payload'])
            
            protocol_name = self.get_protocol_name(ip_info['protocol']).lower()
            return protocol_name == self.protocol_filter.lower()
        except:
            return False

    def start_capture(self):
        """Start packet capture"""
        print(f"Starting packet capture...")
        print(f"Protocol filter: {self.protocol_filter or 'All'}")
        print(f"Packet count limit: {self.count or 'Unlimited'}")
        print("Press Ctrl+C to stop\n")
        
        sock = self.create_socket()
        
        try:
            while True:
                if self.count and self.packet_count >= self.count:
                    break
                
                # Receive packet
                packet_data, addr = sock.recvfrom(65535)
                
                # Apply filters
                if self.should_capture_packet(packet_data):
                    self.packet_count += 1
                    self.display_packet_info(packet_data)
                
        except KeyboardInterrupt:
            print(f"\n\nCapture stopped. Total packets captured: {self.packet_count}")
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            sock.close()

def main():
    parser = argparse.ArgumentParser(description='Network Packet Sniffer')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-p', '--protocol', choices=['tcp', 'udp', 'icmp'], 
                       help='Filter by protocol')
    parser.add_argument('-i', '--interface', help='Network interface (Linux only)')
    
    args = parser.parse_args()
    
    # Display warning
    print("WARNING: This tool is for educational purposes only.")
    print("Ensure you have permission to monitor network traffic.")
    print("Use responsibly and in accordance with local laws.\n")
    
    # Create and start sniffer
    sniffer = PacketSniffer(
        interface=args.interface,
        count=args.count,
        protocol_filter=args.protocol
    )
    
    sniffer.start_capture()

if __name__ == "__main__":
    main()
