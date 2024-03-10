from scapy.all import *

def display_insecure_packets(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Counter for row number
    row_number = 0

    # Counter for insecure packets
    insecure_packet_count = 0

    # Iterate through each packet in the pcap file
    for packet in packets:
        row_number += 1  # Increment row number for each packet

        if Ether in packet:
            # Check for IP packets
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst

                packet_type = packet[IP].get_field("proto").i2repr(packet[IP], packet[IP].proto)

                # Check for insecure protocols (e.g., HTTP)
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport

                    if dst_port == 80:  # HTTP
                        print(f"Row {row_number}: Insecure {packet_type} packet (HTTP) - Source IP: {ip_src}, Destination IP: {ip_dst}")
                        insecure_packet_count += 1

                # Check for plaintext passwords or sensitive data
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    sensitive_keywords = ["password", "user", "credit_card", "secret"]
                    for keyword in sensitive_keywords:
                        if keyword in payload.lower():
                            print(f"Row {row_number}: Insecure {packet_type} packet (Sensitive Data) - Source IP: {ip_src}, Destination IP: {ip_dst}")
                            insecure_packet_count += 1
                            break

    if insecure_packet_count == 0:
        print("No insecure packets found in the pcap file.")

# Example usage
pcap_file = "../pcap/5.pcap"
display_insecure_packets(pcap_file)
