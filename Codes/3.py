from scapy.all import *

def search_pii(packet):
    # Check if the packet contains IP layer
    if IP in packet:
        ip_layer = packet[IP]

        # Check if the packet contains TCP or UDP layer
        if TCP in packet:
            transport_layer = packet[TCP]
        elif UDP in packet:
            transport_layer = packet[UDP]
        else:
            return False  # Skip packet if it doesn't contain TCP or UDP

        # Extract payload from the packet
        payload = bytes(transport_layer.payload)

        # List of keywords indicating potential PII
        pii_keywords = ['ssn', 'social security', 'credit card', 'password', 'address', 'phone', 'email']

        # Search for each keyword in the payload
        for keyword in pii_keywords:
            if keyword.encode() in payload:
                print(f"Potential PII leak found in packet {packet.summary()}: {keyword}")
                return True  # PII found

    return False  # No PII found in this packet

def analyze_pcap_for_pii(pcap_file):
    # Load PCAP file
    packets = rdpcap(pcap_file)

    # Flag to indicate if PII was found
    pii_found = False

    # Iterate through each packet in the capture
    for packet in packets:
        # Search for potential PII in the packet
        if search_pii(packet):
            pii_found = True

    # Display whether PII was found or not
    if pii_found:
        print("\nStatus: PII leak detected in the captured packets.")
    else:
        print("\nStatus: No PII leak detected in the captured packets.")

# Example usage
if __name__ == "__main__":
    pcap_file = "../okok.pcap"
    analyze_pcap_for_pii(pcap_file)
