import json
import re

# Load patterns once at import
with open("dpi/threat_signatures.json") as f:
    data = json.load(f)
    exact_patterns = data.get("exact", [])
    regex_patterns = [re.compile(p) for p in data.get("regex", [])]


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
