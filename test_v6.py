import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import scrolledtext  # Import scrolledtext module
from scapy.all import *
from scapy.all import sniff
import threading
import scapy.all as scapy
import argparse
from scapy.layers import http
from colorama import Fore
from urllib.parse import parse_qs
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import scapy.all as scapy
import argparse
from scapy.layers import http
from urllib.parse import parse_qs

file_path = ""
capture_packets = False  # Change to False initially

def button_click(text):
    global file_path, capture_packets
    selected_vulnerability = animal_combobox.get()
    select_ui = animal_type_combobox.get()

    if text == "Start Capture":
        if not capture_packets:
            capture_packets = True
            start_capture_button.config(state="disabled")
            capture_thread = threading.Thread(target=capture)
            capture_thread.start()
    elif text == "Analyse the Packets":
        box_text.delete(1.0, tk.END)

        if selected_vulnerability == "Protocol Abnormalities":
            detect_protocol_abnormalities("okok.pcap", output_text, box_text)

        elif selected_vulnerability == "Network Misconfigurations":
            display_insecure_packets("okok.pcap", box_text)

        elif selected_vulnerability == "Data Exfiltration":
            analyze_exfiltration("okok.pcap", box_text)

        elif selected_vulnerability == "Denial of Service (DoS)":
            detect_dos_from_pcap("okok.pcap", box_text)

        elif selected_vulnerability == "Malware Infections":
            detect_unusual_ports("okok.pcap", box_text)

        elif selected_vulnerability == "PII Leak":
            analyze_pcap_for_pii("okok.pcap", box_text)

        elif selected_vulnerability == "Intrusions and Breaches":
            detect_port_scanning("okok.pcap", box_text)

        if select_ui == "source ip":

            malicious_ips = ['malicious_ip1', 'malicious_ip2']
            suspicious_outbound_connections_analysis("okok.pcap", malicious_ips, box_text)

        elif select_ui == "dest ip":

            malicious_ips = ['malicious_ip1', 'malicious_ip2']

            suspicious_outbound_dest("okok.pcap", malicious_ips, box_text)

    # Clear existing content in box_text
    elif text == "Stop Capture":
        stop_capture()
    elif text == "clear":
        clear_output()

    else:
        print(f"{text} button clicked")



def suspicious_outbound_dest(pcap_file, malicious_ip_addresses,box_text):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Set to store unique destination IP addresses
    dest_ips = set()

    # Iterate through each packet in the pcap file
    for packet in packets:
        if IP in packet:
            dest_ip = packet[IP].dst  # Use destination IP instead of source IP

            # Check if the destination IP is in the list of known malicious IP addresses
            if dest_ip in malicious_ip_addresses:
                box_text.insert(tk.END,f"Suspicious outbound connection detected: {packet[IP].src} to {dest_ip}")

            dest_ips.add(dest_ip)

    # Print unique destination IP addresses for reference
    box_text.insert(tk.END,"\nUnique Destination IP Addresses:")
    for ip in dest_ips:
        box_text.insert(tk.END,f"{ip}\n")

def suspicious_outbound_connections_analysis(pcap_file, malicious_ip_addresses,box_text):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Set to store unique source IP addresses
    source_ips = set()

    # Iterate through each packet in the pcap file
    for packet in packets:
        if IP in packet:
            source_ip = packet[IP].src

            # Check if the source IP is in the list of known malicious IP addresses
            if source_ip in malicious_ip_addresses:
                box_text.insert(tk.END,f"Suspicious outbound connection detected: {source_ip} to {packet[IP].dst}")

            source_ips.add(source_ip)

    # Print unique source IP addresses for reference
    box_text.insert(tk.END,"\nUnique Source IP Addresses:")
    for ip in source_ips:
        box_text.insert(tk.END,f"{ip}\n")

def detect_port_scanning(pcap_file,box_text):
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
                    box_text.insert(tk.END,f"Port scanning detected from IP: {ip}\n")

                else:
                    box_text.insert(tk.END,f"No port scanning happen {ip}port {ports}\n")

        # PII LEAKS ARE 2 FUNCTION GIVEN BELOW
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
                box_text.insert(tk.END,f"Potential PII leak found in packet {packet.summary()}: {keyword}")
                return True  # PII found

    return False  # No PII found in this packet
#this is also pii function


def analyze_pcap_for_pii(pcap_file,box_text):
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
        box_text.insert(tk.END,"\nStatus: PII leak detected in the captured packets.")
    else:
        box_text.insert(tk.END,"\nStatus: No PII leak detected in the captured packets.")

def detect_unusual_ports(pcap_file, box_text):
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
        box_text.insert(tk.END, "Suspicious ports:\n")
        for port in suspicious_ports:
            box_text.insert(tk.END, f"Port: {port}\n")  # Corrected line
    else:
        box_text.insert(tk.END, "No suspicious port\n")

def detect_dos_from_pcap(pcap_file,box_text,packet_count_threshold=200, request_threshold=100):
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

    # Sniff packets from the pcap file
    sniff(prn=analyze_packet, store=0, timeout=10)  # Sniff packets for 10 seconds
    #
    # packets = rdpcap(pcap_file)
    # for packet in packets:
    #     analyze_packet(packet)

    if packet_count > packet_count_threshold :
        box_text.insert(tk.END,"Potential DoS attack detected. Packet count: \n", packet_count)
        for key, count in source_requests.items():
            if count > request_threshold:
                box_text.insert(tk.END,f"DoS attack happening from {key[0]}:{key[1]} - Packets captured: {count} \n")
        box_text.insert(tk.END,"Status: No DoS attack \n")
    else:
        box_text.insert(tk.END,"Status: No DoS attack detected. Packet count: \n", packet_count)

def analyze_exfiltration(pcap_file,box_text):
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
                box_text.insert(tk.END,f"Exfiltration packet found - Payload size: {payload_size} bytes \n")

    if exfiltration_packet_count == 0:
        box_text.insert(tk.END,"No exfiltration packets found in the pcap file.")
    else:
        box_text.insert(tk.END,f"Total exfiltration packets found: {exfiltration_packet_count}")

# Example usage
def display_insecure_packets(pcap_file, box_text):
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
                        insecure_packet_count += 1
                        box_text.insert(tk.END, f"Row {row_number}: Insecure {packet_type} packet (HTTP) - Source IP: {ip_src}, Destination IP: {ip_dst}\n")

                # Check for plaintext passwords or sensitive data
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', 'ignore')
                    sensitive_keywords = ["password", "user", "credit_card", "secret"]
                    for keyword in sensitive_keywords:
                        if keyword in payload.lower():
                            insecure_packet_count += 1
                            box_text.insert(tk.END, f"Row {row_number}: Insecure {packet_type} packet (Sensitive Data) - Source IP: {ip_src}, Destination IP: {ip_dst}\n")
                            break

    if insecure_packet_count == 0:
        box_text.insert(tk.END, "No insecure packets found in the pcap file.\n")

def detect_protocol_abnormalities(pcap_file, output_text, box_text):
    packets = rdpcap(pcap_file)
    protocol_count = {}

    for packet in packets:
        if IP in packet:
            protocol = packet[IP].proto

            if protocol in protocol_count:
                protocol_count[protocol] += 1
            else:
                protocol_count[protocol] = 1

    total_packets = len(packets)
    expected_count = total_packets / len(protocol_count)

    box_text.insert(tk.END, "Protocol abnormalities:\n")

    for protocol, count in protocol_count.items():
        deviation = abs(count - expected_count) / expected_count
        if deviation > 0.1:
            box_text.insert(tk.END, f"Protocol: {protocol} | Deviation: {deviation}\n")
def capture():
    global capture_packets
    while capture_packets:
        sniff(prn=packet_callback, count=1)
def stop_capture():
    global capture_packets
    capture_packets = False
    start_capture_button.config(state="normal")  # Enable the "Start Capture" button
# Callback function to process captured packets
packet_counter = 0  # Global counter for packet numbers

# Callback function to process captured packets

def packet_callback(packet):
    global packet_counter

    packet_counter += 1

    packet_details = (
        f"{packet_counter} ="
        f" Name: {packet.name}"
        f" Packet Format: {packet.__class__.__name__}"
        f" Source Address: {packet.src}"
        f" Destination Address: {packet.dst}"
    )
    if hasattr(packet, 'sport'):
        packet_details += f"    Source Port: {packet.sport}"
    if hasattr(packet, 'dport'):
        packet_details += f"    Destination Port: {packet.dport}"

    output_text.insert(tk.END, packet_details + "\n")
def clear_output():
    global packet_counter
    packet_counter = 0  # Reset packet counter
    output_text.delete(1.0, tk.END)


# Create the main window
root = tk.Tk()
root.title("Packet Capture and Analyzing Tool")

# Create a frame to contain the heading and set its border color
heading_frame = tk.Frame(root, bd=2, relief=tk.SOLID, bg="#64adce", highlightbackground="#64adce")
heading_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky=tk.W+tk.E)

# Add the heading label inside the heading frame
heading_label = tk.Label(heading_frame, text="Packet Analyzer Tool", font=("Arial", 16))
heading_label.pack(padx=10, pady=10)

# Configure columns to expand horizontally
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=2)  # Set column 1 to have more weight

# Create a frame to contain the buttons
button_frame = tk.Frame(root, bd=2, relief=tk.SOLID, bg="#64adc4", highlightbackground="#64adc4")  # Set background and border color
button_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 10), sticky=tk.W+tk.E)

# Define the names for the first 5 buttons
button_texts = ["Start Capture","Stop Capture", "clear","Analyse the Packets" ]

# Create five buttons with the specified names and add them to the button frame
for i, text in enumerate(button_texts):
    button = tk.Button(button_frame, text=text, command=lambda t=text: button_click(t), highlightbackground="#3d79e1")  # Set button border color
    button.grid(row=0, column=i, padx=5, pady=5, sticky=tk.W)
    if text == "Start Capture":
        start_capture_button = button  # Store reference to the start capture button
output_frame = tk.Frame(root, bd=2, relief=tk.SOLID, bg="#4887b7", highlightbackground="#4887b7")
output_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 10), sticky=tk.NSEW)

# Add Text widget for displaying output directly in the main GUI
output_text = scrolledtext.ScrolledText(output_frame, height=22, width=200, wrap=tk.NONE)  # Disable text wrapping
output_text.grid(row=0, column=0, sticky=tk.NSEW)

# Create a horizontal scrollbar
xscrollbar = tk.Scrollbar(output_frame, orient=tk.HORIZONTAL, command=output_text.xview)
xscrollbar.grid(row=1, column=0, sticky=tk.EW)

# Configure the text widget to use the horizontal scrollbar
output_text.config(xscrollcommand=xscrollbar.set)
# Left Frame for Text widget
box_frame = tk.Frame(root, bd=2, relief=tk.SOLID, bg="#4887b7", highlightbackground="#4887b7")
box_frame.grid(row=3, column=0, padx=10, pady=(10, 10), sticky=tk.NSEW)

# Add Text widget for the new box
box_text = scrolledtext.ScrolledText(box_frame, height=15, width=120)
box_text.pack(padx=10, pady=10)

# Create a label for the box heading
# Right Frame for Combobox
dropdown_frame = tk.Frame(root, bg="#4887b7", highlightbackground="#4887b7")
dropdown_frame.grid(row=3, column=1, padx=10, pady=(10, 10), sticky=tk.NSEW)

# Animal names for the first dropdown
animal_names = [
    "Intrusions and Breaches",
    "PII Leak",
    "Malware Infections",
    "Protocol Abnormalities",
    "Network Misconfigurations",
    "Data Exfiltration",
    "Denial of Service (DoS)"]

# Create the first Combobox
animal_combobox = ttk.Combobox(dropdown_frame, values=animal_names)
animal_combobox.set("Select Vulnerability")
animal_combobox.grid(row=0, column=0, padx=15, pady=(15, 0))
animal_combobox.bind("<<ComboboxSelected>>", lambda event: button_click(text))

# Animal types for the second dropdown
animal_types = [
    "source ip",
    "dest ip"
    ]

# Create the second Combobox
animal_type_combobox = ttk.Combobox(dropdown_frame, values=animal_types)
animal_type_combobox.set("Select IP fucntions")
animal_type_combobox.grid(row=0, column=1, padx=15, pady=(15, 0))
animal_type_combobox.bind("<<ComboboxSelected>>", lambda event: button_click(text))
# Configure row 3 to expand vertically to push both frames down
root.rowconfigure(3, weight=1)

# Configure row 4 to expand vertically to push frames to the bottom of the window
root.rowconfigure(4, weight=1000)

root.mainloop()


def start_sniffing(text_box):
    iface = get_interface()
    Thread(target=sniff_and_process, args=(iface, text_box), daemon=True).start()

def get_interface():
    parser = argparse.ArgumentParser(description="HTTP Traffic Sniffer")
    parser.add_argument("-i", "--interface", dest="interface", help="Specify the interface.")
    arguments = parser.parse_args()
    return arguments.interface

def process_packet(packet, text_box):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host.decode('utf-8') + packet[http.HTTPRequest].Path.decode('utf-8')

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = [b"username", b"password", b"pass", b"email"]

            for key in keys:
                if key in load:
                    decoded_data = parse_qs(load.decode('utf-8'))
                    result = f"\nUsername: {decoded_data['username'][0]}, Password: {decoded_data['password'][0]}\n"
                    update_text(text_box, result)
                    break

def sniff_and_process(iface, text_box):
    scapy.sniff(iface=iface, store=False, prn=lambda packet: process_packet(packet, text_box))

def update_text(text_box, text):
    text_box.insert(tk.END, text)
    text_box.yview(tk.END)

# Example usage:
if __name__ == "__main__":
    root = tk.Tk()
    root.title("HTTP Traffic Sniffer")

    text_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
    text_box.pack(padx=10, pady=10)

    start_button = tk.Button(root, text="Start Sniffing", command=lambda: start_sniffing(text_box))
    start_button.pack(pady=10)

    root.mainloop()