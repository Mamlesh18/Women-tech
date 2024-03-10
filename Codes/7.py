#exfiltering in python
from scapy.all import *

def analyze_exfiltration(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Counter for exfiltration packets
    exfiltration_packet_count = 0

    # Iterate through each packet in the pcap file
    for packet in packets:
        # Your exfiltration detection logic goes here
        # For demonstration purposes, let's just count the packets with large payloads
        if IP in packet and Raw in packet:
            payload_size = len(packet[Raw].load)
            if payload_size > 1000:  # Adjust the threshold as needed
                exfiltration_packet_count += 1
                print(f"Exfiltration packet found - Payload size: {payload_size} bytes")

    if exfiltration_packet_count == 0:
        print("No exfiltration packets found in the pcap file.")
    else:
        print(f"Total exfiltration packets found: {exfiltration_packet_count}")

# Example usage
pcap_file = "../okok.pcap"
analyze_exfiltration(pcap_file)
