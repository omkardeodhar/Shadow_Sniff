import scapy.all as scapy
from datetime import datetime
import os
from colorama import Fore, Back, Style, init

init()

background = Back.BLACK
text_style = Style.BRIGHT 

banner = f"""
{Fore.RED}{background}{text_style}
********************************************************
*             SHADOWSNIFF PACKET SNIFFER               *
*                                                      *
*    WARNING: THIS PACKET SNIFFER TOOL IS FOR          *
*    EDUCATIONAL AND AUTHORIZED USE ONLY.              *
*    UNAUTHORIZED ACCESS TO NETWORK TRAFFIC IS         *
*    ILLEGAL AND MAY VIOLATE PRIVACY LAWS.             *
*                                                      *
*    Developed by: Omkar Deodhar                       *  
*    Version : 2.0                                     * 
********************************************************
{Style.RESET_ALL}
"""
# \033[5m
print(banner)

packet_count = 0
log_file_path = 'log.txt'
os.chmod(log_file_path, 0o644)
log_file = open('log.txt', 'w')

def packet_callback(packet):
    global packet_count
    packet_count = packet_count+1
    
    print(f"\nNumber of Packets Captured: {packet_count}")
    print(f"Timestamp: {datetime.now().strftime('Date: %Y-%m-%d, Time: %H:%M:%S')}")
    log_file.write(f"\nNumber of Packets Captured: {packet_count}\n")
    log_file.write(f"Timestamp: {datetime.now().strftime('Date: %Y-%m-%d, Time: %H:%M:%S')}\n")
    
    if packet.haslayer(scapy.ICMP):
        icmp_type = packet[scapy.ICMP].type
        icmp_code = packet[scapy.ICMP].code
        packet_length = len(packet)
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"ICMP Type: {icmp_type}, ICMP Code: {icmp_code}")
        print(f"Packet Length: {packet_length} bytes")
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}")
        print("Protocol Name: ICMP")
        log_file.write(f"ICMP Type: {icmp_type}, ICMP Code: {icmp_code}\n")
        log_file.write(f"Packet Length: {packet_length} bytes\n")
        log_file.write(f"Source IP: {ip_src}, Destination IP: {ip_dst}\n")
        log_file.write("Protocol Name: ICMP\n")

    elif packet.haslayer(scapy.DNS):
        try:
            dns_query = packet[scapy.DNSQR].qname
            print(f"DNS Query: {dns_query}")
            log_file.write(f"DNS Query: {dns_query}\n")
        except IndexError:
            print("DNSQR layer not found in the packet.")
            log_file.write("DNSQR layer not found in the packet.\n")
        packet_length = len(packet)
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Packet Length: {packet_length} bytes")
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}")
        print("Protocol Name: DNS")
        log_file.write(f"Packet Length: {packet_length} bytes\n")
        log_file.write(f"Source IP: {ip_src}, Destination IP: {ip_dst}\n")
        log_file.write("Protocol Name: DNS\n")
            
    elif packet.haslayer(scapy.ARP):
        arp_src_ip = packet[scapy.ARP].psrc
        arp_dst_ip = packet[scapy.ARP].pdst
        arp_op = packet[scapy.ARP].op
        packet_length = len(packet)
        print(f"ARP Source IP: {arp_src_ip}, ARP Destination IP: {arp_dst_ip}, ARP Operations: {arp_op}")
        print(f"Packet Length: {packet_length} bytes")
        print("Protocol Name: ARP")
        log_file.write(f"ARP Source IP: {arp_src_ip}, ARP Destination IP: {arp_dst_ip}, ARP Operations: {arp_op}\n")
        log_file.write(f"Packet Length: {packet_length} bytes\n")
        log_file.write("Protocol Name: ARP\n")

    elif packet.haslayer(scapy.IP):
        ip_layer = packet.getlayer(scapy.IP)
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        packet_length = len(packet)
        
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
            print("Protocol Name: TCP")
            log_file.write(f"Source Port: {src_port}, Destination Port: {dst_port}\n")
            log_file.write("Protocol Name: TCP\n")
        
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
            print("Protocol Name: UDP")
            log_file.write(f"Source Port: {src_port}, Destination Port: {dst_port}\n")
            log_file.write("Protocol Name: UDP\n")
        
        else:
            print("Packets other than UDP or TCP.")
            log_file.write("Packets other than UDP or TCP.\n")
            
        print(f"Packet Length: {packet_length} bytes")
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        log_file.write(f"Packet Length: {packet_length} bytes\n")
        log_file.write(f"Source IP: {ip_src}, Destination IP: {ip_dst}\n")
        log_file.write(f"Protocol: {protocol}\n")
        
    else:
        print("Not a recognized packet type.")
        log_file.write("Not a recognized packet type.\n")

# Define the duration (in seconds) for capturing packets
capture_duration = int(input("Enter time in seconds to capture packets: "))

print(f"Capturing packets for {capture_duration} seconds...")
start_time = datetime.now()

# Start sniffing packets for the specified duration
scapy.sniff(prn=packet_callback, store=0, timeout=capture_duration, iface='wlan0')

end_time = datetime.now()
elapsed_time = (end_time - start_time).total_seconds()
print(f"\nCapture completed. Elapsed time: {elapsed_time} seconds.")
print(f"{Fore.GREEN}{background}{text_style}Captures stored in capture file log.txt{Style.RESET_ALL}")
os.chmod(log_file_path, 0o444)
log_file.close()
