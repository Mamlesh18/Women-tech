from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext

def detect_protocol_abnormalities(pcap_file, output_text):
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

    output_text.insert(tk.END, "Protocol abnormalities:\n")

    for protocol, count in protocol_count.items():
        deviation = abs(count - expected_count) / expected_count
        if deviation > 0.1:
            output_text.insert(tk.END, f"Protocol: {protocol} | Deviation: {deviation}\n")

def show_gui():
    root = tk.Tk()
    root.title("Protocol Abnormalities Detector")

    text_area = scrolledtext.ScrolledText(root, width=40, height=20)
    text_area.pack(padx=10, pady=10)

    pcap_file = "../okok.pcap"
    detect_protocol_abnormalities(pcap_file, text_area)

    root.mainloop()

if __name__ == "__main__":
    show_gui()
