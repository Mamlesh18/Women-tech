from scapy.all import *

# Function to analyze pcap file for TCP packets with unusual port usage
def detect_unusual_ports(pcap_file):
    # Open pcap file
    packets = rdpcap(pcap_file)

    # Dictionary to store count of occurrences for each port
    port_count = {}

    # Iterate through each packet in the pcap file
    for packet in packets:
        # Check if packet has TCP layer
        if packet.haslayer(TCP):
            # Extract source and destination ports
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Update count for source port
            if src_port in port_count:
                port_count[src_port] += 1
            else:
                port_count[src_port] = 1

            # Update count for destination port
            if dst_port in port_count:
                port_count[dst_port] += 1
            else:
                port_count[dst_port] = 1

    # Calculate threshold for unusual port occurrence
    threshold = len(packets) // 100  # Adjust the divisor as needed for your scenario

    # Extract suspicious ports
    suspicious_ports = [port for port, count in port_count.items() if count < threshold]

    # Print suspicious ports if any, otherwise print "No suspicious port"
    if suspicious_ports:
        print("Suspicious ports:")
        for port in suspicious_ports:
            print("Port:", port)
    else:
        print("No suspicious port")

# Example usage
if __name__ == "__main__":
    pcap_file = "okok.pcap"  # Replace with the path to your pcap file
    detect_unusual_ports(pcap_file)
