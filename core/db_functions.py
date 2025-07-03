import sqlite3
import subprocess

DB_PATH = "firewall.db"


def connect_db():
    return sqlite3.connect(DB_PATH)


def rule_exists(cursor, port, protocol, action, src_ip, mac_address):
    cursor.execute(
        """
        SELECT 1 FROM firewall_rules
        WHERE port=? AND protocol=? AND action=? AND src_ip=? AND mac_address=?
    """,
        (port, protocol.lower(), action.upper(), src_ip, mac_address),
    )
    return cursor.fetchone() is not None

def threat_log_exists():
    pass


def add_threat_log_to_db(threat_type, src_ip, method):
    pass

def add_rule_to_db(port, protocol, action, src_ip, mac_address):
    conn = connect_db()
    cursor = conn.cursor()
    if rule_exists(cursor, port, protocol, action, src_ip, mac_address):
        print("[!] Rule already exists in database.")
    else:
        cursor.execute(
            """
            INSERT INTO firewall_rules (port, protocol, action, src_ip, mac_address)
            VALUES (?, ?, ?, ?, ?)
        """,
            (port, protocol.lower(), action.upper(), src_ip, mac_address),
        )
        conn.commit()
        print(
            f"[+] Rule added to database: {action.upper()} port {port}/{protocol.upper()} on {src_ip} with mac {mac_address}"
        )
    conn.close()


def list_rules_from_db():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, port, protocol, action, src_ip, mac_address FROM firewall_rules"
    )
    rules = cursor.fetchall()
    # print(rules)
    conn.close()

    print("\n[Current Rules]")
    for rule in rules:
        print(
            f"ID: {rule[0]} | Port: {rule[1]} | Protocol: {rule[2].upper()} | Action: {rule[3].upper()} | IP: {rule[4]} | MAC: {rule[5]}"
        )


def delete_rule_from_db(rule_id):
    conn = connect_db()
    cursor = conn.cursor()

    # Fetch rule before deleting it
    cursor.execute(
        "SELECT port, protocol, action, src_ip, mac_address FROM firewall_rules WHERE id = ?",
        (rule_id,),
    )
    rule = cursor.fetchone()
    print(rule, "rule found")

    if rule is None:
        print("[!] Rule with that ID not found.")
    else:
        port, protocol, action, src_ip, mac_address = rule
        cmd = ["sudo", "iptables", "-D", "INPUT", "-p", protocol]

        if port:
            cmd += ["--dport", str(port)]

        if src_ip:
            cmd += ["-s", src_ip]

        if mac_address:
            cmd += ["-m", "mac", "--mac-source", mac_address]

        cmd += ["-j", action]

        print(cmd, "final cmd")
        result = subprocess.run(cmd)
        print(result)
        if result.returncode == 0:
            src_ip = src_ip if src_ip else "All IP"
            port = port if port else "All Ports"
            mac_address = mac_address if mac_address else "No MAC Address specified"
            print(
                f"[-] Rule removed from iptables: {action} {protocol.upper()} port {port} on {src_ip} with ({mac_address})"
            )
        else:
            print("[~] Rule not found in iptables (might already be gone)")

        # Remove from DB
        cursor.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
        conn.commit()
        print(f"[-] Rule ID {rule_id} deleted from database.")

    conn.close()


def fetch_rules_from_db():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT port, protocol, action, src_ip, mac_address FROM firewall_rules"
    )
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "port": row[0],
            "protocol": row[1],
            "action": row[2],
            "src_ip": row[3],
            "mac_address": row[4],
        }
        for row in rows
    ]


# fetch_rules_from_db()
