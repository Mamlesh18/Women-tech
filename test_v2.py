import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import scrolledtext  # Import scrolledtext module
from scapy.all import *

from scapy.all import sniff
import threading

file_path = ""
capture_packets = False  # Change to False initially

# Function to handle button clicks
# Function to handle button clicks
# Update the button_click function to pass the output_text widget to show_output_window
def button_click(text):
    global file_path, capture_packets

    if text == "Start Capture":
        if not capture_packets:
            capture_packets = True
            start_capture_button.config(state="disabled")
            capture_thread = threading.Thread(target=capture)
            capture_thread.start()
    elif text == "Analyse the Packets":
        # Pass the output_text widget to show_output_window
        detect_protocol_abnormalities("okok.pcap", output_text, box_text)
        display_insecure_packets("okok.pcap", box_text)
    elif text == "Stop Capture":
        stop_capture()

    else:
        print(f"{text} button clicked")

def show_output_window():
    root_output = tk.Toplevel(root)
    root_output.title("Captured Packet Summaries")

    text_area_output = scrolledtext.ScrolledText(root_output, width=40, height=20)
    text_area_output.pack(padx=10, pady=10)

    pcap_file = "okok.pcap"
    detect_protocol_abnormalities(pcap_file, text_area_output)
    root_output.mainloop()


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
    output_text.insert(tk.END, f"{packet_counter}. {packet.summary()}\n")
 # Insert captured packet summary into output text

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
button_texts = ["Start Capture", "Analyse the Packets","Stop Capture" ]

# Create five buttons with the specified names and add them to the button frame
for i, text in enumerate(button_texts):
    button = tk.Button(button_frame, text=text, command=lambda t=text: button_click(t), highlightbackground="#3d79e1")  # Set button border color
    button.grid(row=0, column=i, padx=5, pady=5, sticky=tk.W)
    if text == "Start Capture":
        start_capture_button = button  # Store reference to the start capture button

# Create a frame to contain the output text
output_frame = tk.Frame(root, bd=2, relief=tk.SOLID, bg="#4887b7", highlightbackground="#4887b7")
output_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 10), sticky=tk.NSEW)

# Add Text widget for displaying output directly in the main GUI
output_text = scrolledtext.ScrolledText(root, height=15, width=150)
output_text.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 10), sticky=tk.NSEW)

box_frame = tk.Frame(root, bd=2, relief=tk.SOLID, bg="#4887b7", highlightbackground="#4887b7")
box_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=(10, 10), sticky=tk.NSEW)

# Add Text widget for the new box
box_text = scrolledtext.ScrolledText(box_frame, height=10, width=150)
box_text.pack(padx=10, pady=10)

# Create a label for the box heading
box_heading_label = tk.Label(box_frame, text="Output", font=("Arial", 12))
box_heading_label.pack(padx=10, pady=5)
# Creat
# Configure row 3 to expand vertically to push both frames down
root.rowconfigure(3, weight=1)

# Configure row 4 to expand vertically to push frames to the bottom of the window
root.rowconfigure(4, weight=1000)

root.mainloop()
