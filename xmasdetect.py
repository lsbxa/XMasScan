from scapy.all import *

def log_alert(message):
    with open("xmas_scan_alerts.log", "a") as log_file:
        log_file.write(message + "\n")

def suspect_packet(packet):
    if TCP in packet:
        flags = packet.sprintf("%TCP.flags%")
        if flags == "FPU":
            src_ip = packet[IP].src
            alertMessage = f"Alert: Possible Xmas scan from {src_ip}"
            print(alertMessage)
            print(packet.summary())
            log_alert(alertMessage)

sniff(iface="eth1", filter="tcp", prn=suspect_packet, store=0)

