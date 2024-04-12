import subprocess
from scapy.all import *
import datetime

def capture_packets(interface, count=10):
    pcap_file = "captured_packets.pcap"
    cmd = f"sudo tcpdump -i {interface} -c {count} -w {pcap_file}"
    try:
        subprocess.run(cmd, shell=True, check=True)
        return pcap_file
    except subprocess.CalledProcessError:
        print("Error capturing packets.")

def analyze_packets(pcap_file, filter_option):
    analysis_result = {
        "ip_addresses": [],
        "protocols": [],
        "payload_data": []
    }

    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if filter_option == "1":
                if IP in packet:
                    analysis_result["ip_addresses"].append((packet[IP].src, packet[IP].dst))
            elif filter_option == "2":
                if IP in packet:
                    analysis_result["protocols"].append(packet[IP].proto)
            elif filter_option == "3":
                if Raw in packet:
                    analysis_result["payload_data"].append(packet[Raw].load.decode("utf-8", "ignore"))

        return analysis_result
    except FileNotFoundError:
        print(f"Error: '{pcap_file}' not found.")

def generate_text_report(captured_packets, analysis_result):
    report = f"*** Packet Sniffer Tool Report ***\n\n"
    report += f"Date and Time of Capture: {datetime.datetime.now()}\n"
    report += f"Interface Used: {captured_packets['interface']}\n"
    report += f"Number of Packets Captured: {captured_packets['count']}\n\n"

    report += "*** Captured Packets Analysis ***\n\n"

    if analysis_result:
        report += "1. IP Addresses Analysis:\n"
        for src_ip, dst_ip in analysis_result["ip_addresses"]:
            report += f"- Source IP: {src_ip}, Destination IP: {dst_ip}\n"
        report += "\n"

        report += "2. Protocols Analysis:\n"
        for proto in analysis_result["protocols"]:
            report += f"- Protocol: {proto}\n"
        report += "\n"

        report += "3. Payload Data Analysis:\n"
        for payload_data in analysis_result["payload_data"]:
            report += f"- Payload Data: {payload_data}\n"
        report += "\n"
    else:
        report += "No packets captured for analysis.\n"

    return report

def main():
    interface = "eth0"
    count = 10
    pcap_file = capture_packets(interface, count)

    while True:
        filter_option = input("Select analysis option:\n"
                              "1. IP Addresses\n"
                              "2. Protocols\n"
                              "3. Payload Data\n"
                              "4. Exit analysis\n"
                              "Please enter your choice (1, 2, 3, or 4): ")
        if filter_option == "4":
            break

        analysis_result = analyze_packets(pcap_file, filter_option)
        report = generate_text_report({'interface': interface, 'count': count}, analysis_result)
        print(report)

if __name__ == "__main__":
    main()