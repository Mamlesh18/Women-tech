from scapy.all import *

def extract_smtp_payload(pcap_file):
    packets = rdpcap(pcap_file)
    smtp_payload = ""
    in_smtp_session = False
    in_data_section = False

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors='ignore')

            if "AUTH LOGIN" in payload:
                in_smtp_session = True

            if in_smtp_session:
                smtp_payload += payload

                if "DATA" in payload:
                    in_data_section = True

            if in_data_section:
                if "." in payload:  # end of DATA section
                    break
                else:
                    smtp_payload += payload

    return smtp_payload

if __name__ == "__main__":
    pcap_file = "okok.pcap"
    smtp_data = extract_smtp_payload(pcap_file)
    if smtp_data:
        print(smtp_data)
    else:
        print("No SMTP payload data found in the pcap file.")