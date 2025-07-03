import requests
import json


def fetch_signatures():
    print("[~] Fetching remote threat signatures...")
    url = "https://example.com/threat-signatures.json"  # Replace with real or test URL
    response = requests.get(url)
    if response.status_code == 200:
        with open("dpi/threat_signatures.json", "w") as f:
            f.write(response.text)
        print("[✓] Updated threat_signatures.json")
    else:
        print("[!] Failed to fetch threat signatures.")
        print(f"Status code: {response.status_code}")
