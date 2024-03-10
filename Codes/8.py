#dos attack
from scapy.all import *

def detect_dos(packet_count_threshold=1000, request_threshold=100):
    packet_count = 0
    source_requests = {}

    def analyze_packet(packet):
        nonlocal packet_count
        nonlocal source_requests

        packet_count += 1

        # Check if the packet has an IP layer
        if IP in packet:
            source_ip = packet[IP].src
            source_port = None

            # Check if the packet has a TCP or UDP layer
            if TCP in packet:
                source_port = packet[TCP].sport
            elif UDP in packet:
                source_port = packet[UDP].sport

            if source_port:
                # Update request count for the (source_ip, source_port) pair
                key = (source_ip, source_port)
                source_requests[key] = source_requests.get(key, 0) + 1

    sniff(prn=analyze_packet, store=0, timeout=10)  # Sniff packets for 10 seconds

    if packet_count > packet_count_threshold:
        print("Potential DoS attack detected. Packet count:", packet_count)
        for key, count in source_requests.items():
            if count > request_threshold:
                print(f"Dos attack happening from {key[0]}:{key[1]} - Packets captured: {count}")
        print("Status: No Dos attack happened")
    else:
        print("Status: No DoS attack detected. Packet count:", packet_count)

if __name__ == "__main__":
    detect_dos()