# from django.utils import timezone
# from fw_manager.dashboard.models import ThreatLog, BlockedIP
from scapy.all import sniff, Raw
from scapy.layers.inet import IP
from dpi.pattern_matcher import is_payload_malicious, is_ip_malicious
from datetime import datetime


def inspect_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        print(f"[IP] Source: {src_ip}, Destination: {packet[IP].dst}")

        # Check if the source IP is malicious
        if is_ip_malicious(src_ip):
            print(f"[!] BLOCKED: Known malicious IP {src_ip}")
            log_threat(f"[IP] {src_ip}")
            # block_ip(src_ip)
            return

    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        print("[Raw]", payload)
        if is_payload_malicious(payload):
            print("[!] DPI ALERT: Suspicious content detected!")
            print(f"[ALERT] Threat detected from {packet[IP].src}")
            # log_threat(threat_type=payload)
            log_threat(payload)
            # Optionally: call function to log/block/alert


def start_dpi_capture(interface="wlp3s0"):
    print("[~] Starting DPI capture on", interface)
    sniff(iface=interface, prn=inspect_packet, store=0)


def log_threat(payload):
    with open("dpi_logs.txt", "a") as f:
        f.write(f"[{datetime.now()}] THREAT DETECTED:\n{payload}\n\n")


# def log_threat(threat_type, src_ip, method="DPI"):
#     ThreatLog.objects.create(source_ip=src_ip, threat_type=threat_type, method=method)


# def block_ip(src_ip, source="ThreatIntel"):
#     if not BlockedIP.objects.filter(ip_address=src_ip).exists():
#         BlockedIP.objects.create(
#             ip_address=src_ip, source=source, blocked_at=timezone.now()
#         )
