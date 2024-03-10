# port scanning attempts
from scapy.all import *

def detect_port_scanning(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Dictionary to store destination IPs and their associated ports
    dest_ports = {}

    # Iterate through each packet in the pcap file
    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if TCP in packet:
                dst_port = packet[TCP].dport

                # If the destination IP is already in the dictionary, update its port list
                if ip_dst in dest_ports:
                    dest_ports[ip_dst].append(dst_port)
                else:
                    dest_ports[ip_dst] = [dst_port]

    # Analyze the destination IPs and their associated ports
    for ip, ports in dest_ports.items():
        if len(set(ports)) > 10:  # If more than 10 different ports are targeted, consider it as scanning
            print(f"Port scanning detected from IP: {ip}")

        else:
            print("No port scanning happen",ip,"port",ports)
# Example usage
pcap_file = "okok.pcap"
detect_port_scanning(pcap_file)
