from scapy.all import sniff, Raw
from scapy.layers.inet import IP
from datetime import datetime
from dashboard.models import ThreatLog, BlockedIP
from dpi.pattern_matcher import is_payload_malicious, is_ip_malicious
from dpi.logs import add_log
import subprocess

# Django setup (so models can be used outside manage.py runserver)
# import os
# import django

# os.environ.setdefault("DJANGO_SETTINGS_MODULE", "fwmanager.settings")
# django.setup()


def inspect_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        msg = f"[{datetime.now()}] [IP] Source: {src_ip}, Destination: {dest_ip}"
        print(msg)
        add_log(msg)
        print(f"[IP] Source: {src_ip}, Destination: {dest_ip}")

        # Check if the source IP is malicious
        if is_ip_malicious(src_ip):
            alert = f"[!] BLOCKED: Known malicious IP {src_ip}"
            print(alert)
            add_log(alert)

            reason = "Known malicious IP"
            log_threat(
                src_ip=src_ip,
                dest_ip=dest_ip,
                threat_type="Malicious IP",
                protocol=packet[IP].proto,
            )
            block_ip(src_ip, source="ThreatIntel", reason=reason)
            return

    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
        except Exception:
            payload = "[Unreadable Payload]"
        print("[Raw Payload]", payload)

        if is_payload_malicious(payload):
            alert = f"[!] DPI ALERT: Suspicious content detected from {packet[IP].src}"
            print(alert)
            add_log(alert)

            src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
            dest_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
            print(f"[!] DPI ALERT: Suspicious content detected from {src_ip}")

            reason = "Suspicious Payload"
            log_threat(
                src_ip=src_ip,
                dest_ip=dest_ip,
                threat_type="Malicious Payload",
                protocol=packet[IP].proto if packet.haslayer(IP) else "tcp",
            )
            block_ip(src_ip, source="DPI", reason=reason)


def start_dpi_capture(interface="wlp3s0"):
    print("[~] Starting DPI capture on", interface)
    sniff(iface=interface, prn=inspect_packet, store=0)


def log_threat(src_ip, dest_ip, threat_type, protocol):
    # File logging
    with open("dpi_logs.txt", "a") as f:
        f.write(f"[{datetime.now()}] {threat_type} from {src_ip} to {dest_ip}\n\n")

    # DB logging
    ThreatLog.objects.create(
        source_ip=src_ip,
        destination_ip=dest_ip,
        threat_type=threat_type,
        protcol="tcp" if str(protocol) == "6" else "udp",  # IP proto 6 = TCP, 17 = UDP
    )
    print(f"[DB] ThreatLog saved for {src_ip} -> {dest_ip} ({threat_type})")


def block_ip(src_ip, source="Firewall", reason="Suspicious Activity"):
    if not BlockedIP.objects.filter(ip_address=src_ip).exists():
        BlockedIP.objects.create(ip_address=src_ip, source=source, reason=reason)
        print(f"[DB] Added {src_ip} to BlockedIP ({reason})")

    subprocess.run(
        ["sudo", "/usr/sbin/iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"]
    )
    print(f"[!] Auto-blocked {src_ip} in iptables")


# # from django.utils import timezone
# # from fw_manager.dashboard.models import ThreatLog, BlockedIP
# from scapy.all import sniff, Raw
# import subprocess
# from scapy.layers.inet import IP
# from dpi.pattern_matcher import is_payload_malicious, is_ip_malicious
# from datetime import datetime


# def inspect_packet(packet):
#     if packet.haslayer(IP):
#         src_ip = packet[IP].src if not None else "random IP"
#         dest_ip = packet[IP].dst if not None else "random IP DEST"

#         print(f"[IP] Source: {src_ip}, Destination: {dest_ip}")

#         # Check if the source IP is malicious
#         if is_ip_malicious(src_ip):
#             payload = f"Known malicious IP: {src_ip} to {dest_ip} "
#             print(f"[!] BLOCKED: Known malicious IP {src_ip}")
#             log_threat(payload)
#             auto_block_ip(src_ip)
#             print(f"[ALERT] Threat detected from {src_ip} to {dest_ip}")
#             # GETTING THREAT TYPE

#             # log_threat(src_ip=src_ip, threat_type="Malicious IP", dest_ip=dest_ip)
#             # block_ip(src_ip, source="ThreatIntel", reason="Known Malicious IP")
#             return

#     if packet.haslayer(Raw):
#         payload = packet[Raw].load.decode(errors="ignore")
#         # print("[Raw]", payload)
#         if is_payload_malicious(payload):
#             print("[!] DPI ALERT: Suspicious content detected!")
#             print(f"[ALERT] Threat detected from {packet[IP].src}")
#             log_threat(payload, src_ip=packet[IP].src, dest_ip=packet[IP].dst)
#             auto_block_ip(packet[IP].src)
#             # GETTING THREAT TYPE

#             # Optionally: call function to log/block/alert
#             # block_ip(src_ip, source="DPI", reason="Malicious Payload")

#             # log_threat(threat_type="Malicious Payload", src_ip=src_ip, dest_ip=dest_ip)


# def start_dpi_capture(interface="wlp3s0"):
#     print("[~] Starting DPI capture on", interface)
#     sniff(iface=interface, prn=inspect_packet, store=0)


# def log_threat(payload, src_ip=None, dest_ip=None):
#     with open("dpi_logs.txt", "a") as f:
#         f.write(
#             f"[{datetime.now()}] THREAT DETECTED:\n{payload}\n\n"
#             + f"from {src_ip} to {dest_ip}\n\n"
#         )


# # def log_threat(threat_type, src_ip, dest_ip):
# #     ThreatLog.objects.create(source_ip, threat_type, dest_ip)


# # def block_ip(src_ip, source="ThreatIntel", reason="Malicious Activity"):
# #     if not BlockedIP.objects.filter(ip_address=src_ip).exists():
# #         BlockedIP.objects.create(
# #             ip_address=src_ip, source=source, reason=reason
# #         )


# def auto_block_ip(ip):
#     subprocess.run(
#         ["sudo", "/usr/sbin/iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
#     )
#     print(f"[!] Auto-blocked {ip} due to malicious payload")
