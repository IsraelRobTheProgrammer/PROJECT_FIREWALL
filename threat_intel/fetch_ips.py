import requests
import json

import environ
import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env()
environ.Env.read_env(os.path.join(BASE_DIR, ".env"))

# print(env("ABUSE_IP_DB_KEY"), "SECRET_KEY")
# print(BASE_DIR)


def fetch_abuseipdb():
    print("[~] Fetching malicious IPs from AbuseIPDB...")
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    querystring = {"confidenceMinimum": "70", "limit": "10"}
    headers = {"Key": env("ABUSE_IP_DB_KEY"), "Accept": "application/json"}

    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        result = response.json()["data"]
        ip_list = [entry["ipAddress"] for entry in result]
        with open("threat_intel/ip_threats.json", "w") as f:
            json.dump({"malicious_ips": ip_list}, f)
        print(f"[✓] Saved {len(ip_list)} IPs to ip_threats.json")
    else:
        print("[!] Failed to fetch IPs:", response.status_code)


fetch_abuseipdb()
