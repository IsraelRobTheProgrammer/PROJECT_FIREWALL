from scapy.all import sniff, Raw, IP
from dpi.pattern_matcher import is_payload_malicious
from datetime import datetime


def inspect_packet(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        print("[Raw]", payload)
        if is_payload_malicious(payload):
            print("[!] DPI ALERT: Suspicious content detected!")
            log_threat(threat_type=payload)
            print(f"[ALERT] Threat detected from {packet[IP].src}")
            # Optionally: call function to log/block/alert


def start_dpi_capture(interface="wlp3s0"):
    print("[~] Starting DPI capture on", interface)
    sniff(iface=interface, prn=inspect_packet, store=0)


def log_threat(payload):
    with open("dpi_logs.txt", "a") as f:
        f.write(f"[{datetime.now()}] THREAT DETECTED:\n{payload}\n\n")

