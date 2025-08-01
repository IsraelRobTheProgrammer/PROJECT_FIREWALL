import sqlite3
import subprocess


def apply_rules_from_db():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()

    cursor.execute("SELECT port, protocol, action FROM firewall_rules")
    rules = cursor.fetchall()

    for port, protocol, action in rules:
        cmd = [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-p",
            protocol,
            "--dport",
            str(port),
            "-j",
            action,
        ]
        subprocess.run(cmd)
        print(f"[{action}] Rule applied for {protocol.upper()} on port {port}")

    conn.close()


if __name__ == "__main__":
    apply_rules_from_db()
