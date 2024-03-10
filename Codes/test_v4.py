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
def on_enter(event):
    event.widget.config(bg="#000000", fg="white")  # Change background to blue and foreground (text color) to white on mouse enter

def on_leave(event):
    event.widget.config(bg="#E5E5E5", fg="black")  # Change background back to default and foreground back to black on mouse leave    

def button_click(text):
    global file_path, capture_packets
    selected_vulnerability = animal_combobox.get()

    if text == "Start Capture":
        if not capture_packets:
            capture_packets = True
            start_capture_button.config(state="disabled")
            capture_thread = threading.Thread(target=capture)
            capture_thread.start()
    elif text == "Analyse the Packets" and selected_vulnerability == "Protocol Abnormalities":
        box_text.delete(1.0, tk.END)  # Clear existing content in box_text

        # Pass the output_text widget to show_output_window
        detect_protocol_abnormalities("okok.pcap", output_text, box_text)

    elif text == "Analyse the Packets" and selected_vulnerability == "Network Misconfigurations":

        box_text.delete(1.0, tk.END)  # Clear existing content in box_text

        # Pass the output_text widget to show_output_window
        # detect_protocol_abnormalities("okok.pcap", output_text, box_text)
        display_insecure_packets("okok.pcap", box_text)

    elif text == "Analyse the Packets" and selected_vulnerability == "Data Exfiltration":

        box_text.delete(1.0, tk.END)  # Clear existing content in box_text

        # Pass the output_text widget to show_output_window
        # detect_protocol_abnormalities("okok.pcap", output_text, box_text)
        analyze_exfiltration("okok.pcap", box_text)

    elif text == "Analyse the Packets" and selected_vulnerability ==  "Denial of Service (DoS)":

        box_text.delete(1.0, tk.END)  # Clear existing content in box_text

        # Pass the output_text widget to show_output_window
        # detect_protocol_abnormalities("okok.pcap", output_text, box_text)
        detect_dos_from_pcap("okok.pcap", box_text)
    elif text == "Stop Capture":
        stop_capture()
    elif text == "Clear":
        clear_output()



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
        f"{packet_counter}. Packet Details ="
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

heading_label = tk.Label(root, text="Packet Analyzer Tool", font=("Arial", 16), bg="#64adce")
heading_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky=tk.W+tk.E)

# Configure columns to expand horizontally
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=2)  # Set column 1 to have more weight

# Create a frame to contain the buttons
button_frame = tk.Frame(root, bd=2, relief=tk.SOLID, bg="#64adc4", highlightbackground="#64adc4")  # Set background and border color
button_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 10), sticky=tk.W+tk.E)

# Define the names for the first 5 buttons
button_texts = ["Start Capture","Stop Capture", "Clear","Analyse the Packets" ]

# Create five buttons with the specified names and add them to the button frame
for i, text in enumerate(button_texts):
    button = tk.Button(button_frame, text=text, command=lambda t=text: button_click(t), highlightbackground="#3d79e1")  # Set button border color
    button.grid(row=0, column=i, padx=5, pady=5, sticky=tk.W)
    button.bind("<Enter>", on_enter)  # Bind mouse enter event to on_enter function
    button.bind("<Leave>", on_leave)  # Bind mouse leave event to on_leave function
    if text == "Start Capture":
        start_capture_button = button  # Store reference to the start capture button
output_frame = tk.Frame(root, bd=2, relief=tk.SOLID, bg="#4887b7", highlightbackground="#4887b7")
output_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 10), sticky=tk.NSEW)

# Add Text widget for displaying output directly in the main GUI
output_text = scrolledtext.ScrolledText(output_frame, height=15, width=150, wrap=tk.NONE)  # Disable text wrapping
output_text.grid(row=0, column=0, sticky=tk.NSEW)

# Create a horizontal scrollbar
xscrollbar = tk.Scrollbar(output_frame, orient=tk.HORIZONTAL, command=output_text.xview)
xscrollbar.grid(row=1, column=0, sticky=tk.EW)

# Configure the text widget to use the horizontal scrollbar
output_text.config(xscrollcommand=xscrollbar.set)
# Left Frame for Text widget
box_frame = tk.Frame(root, bd=2, relief=tk.SOLID, bg="#4887b7", highlightbackground="#4887b7")
box_frame.grid(row=3, column=0, padx=10, pady=(10, 10), sticky=tk.NSEW)

label_frame = tk.Frame(box_frame, bg="white")
label_frame.pack()

# Add a label inside the label frame
infected_label = tk.Label(label_frame, text="Infected Packets", font=("Arial", 12), bg="white")
infected_label.pack(pady=(10, 5))

# Add Text widget for the new box
box_text = scrolledtext.ScrolledText(box_frame, height=10, width=100)
box_text.pack(padx=10, pady=10)




# Right Frame for Combobox
dropdown_frame = tk.Frame(root, bg="#4887b7", highlightbackground="#4887b7")
dropdown_frame.grid(row=3, column=1, padx=10, pady=(10, 10), sticky=tk.NSEW)

# Animal names for the dropdown
animal_names = ["Plaintext Passwords",
    "Intrusions and Breaches",
    "PII Leak",
    "Malware Infections",
    "Protocol Abnormalities",
    "Network Misconfigurations",
    "Data Exfiltration",
    "Denial of Service (DoS)"]

# Create a Combobox
animal_combobox = ttk.Combobox(dropdown_frame, values=animal_names)
animal_combobox.set("Select Vulnerability")
animal_combobox.pack(padx=10, pady=(5, 0))
animal_combobox.bind("<<ComboboxSelected>>", lambda event: button_click(text))

# Configure row 3 to expand vertically to push both frames down
root.rowconfigure(3, weight=1)

# Configure row 4 to expand vertically to push frames to the bottom of the window
root.rowconfigure(4, weight=1000)

root.mainloop()