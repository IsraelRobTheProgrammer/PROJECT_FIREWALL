import json
import re

# Load patterns once at import
with open("threat_intel/threat_signatures.json") as f:
    data = json.load(f)
    exact_patterns = data.get("exact", [])
    regex_patterns = [re.compile(p) for p in data.get("regex", [])]


def load_malicious_ips():
    try:
        with open("threat_intel/ip_threats.json") as f:
            data = json.load(f)
            return set(data.get("malicious_ips", []))
    except FileNotFoundError:
        print("[!] No malicious IPs file found. Returning empty set.")
        return set()


malicious_ips = load_malicious_ips()


def is_ip_malicious(ip: str) -> bool:
    """
    Check if the given IP address is in the list of known malicious IPs.

    :param ip: The IP address to check.
    :return: True if the IP is malicious, False otherwise.
    """
    return ip in malicious_ips


def is_payload_malicious(payload) -> bool:
    """
    Check if the payload contains any malicious patterns.

    :param payload: The payload string to check.
    :return: True if malicious patterns are found, False otherwise.
    """
    if not payload:
        return False

    # Check for exact matches
    for pattern in exact_patterns:
        if pattern.lower() in payload.lower():
            return True

    # Check for regex matches
    for pattern in regex_patterns:
        if pattern.search(payload):
            return True

    return False
