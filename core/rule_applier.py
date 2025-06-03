import subprocess

# def apply_rule(rule):
#     cmd = ["sudo", "iptables", "-A", "INPUT", "-p", rule["protocol"], "--dport", str(rule["port"]), "-j", rule["action"]]
#     subprocess.run(cmd)


def apply_default_rules():
    print("[+] Applying default base firewall rules...")

    # 1. Set default policies
    subprocess.run(["sudo", "iptables", "-P", "INPUT", "DROP"])
    subprocess.run(["sudo", "iptables", "-P", "FORWARD", "DROP"])
    subprocess.run(
        ["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"]
    )  # allow outbound traffic

    # 2. Allow loopback (localhost)
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])

    # 3. Allow established/related traffic
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ]
    )
    # 4. Drop invalid packets
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "INVALID",
            "-j",
            "DROP",
        ]
    )
    # 5. Allow ICMP (ping for testing)
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "icmp",
            "--icmp-type",
            "echo-request",
            "-j",
            "ACCEPT",
        ]
    )

    # 6. Allow HTTPS
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "ACCEPT",
        ]
    )

    # 7. Allow SSH (optional if remote access needed)
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            "22",
            "-j",
            "ACCEPT",
        ]
    )

    # 7. Allow HTTP (optional if remote access needed)
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "ACCEPT",
        ]
    )

    print("[✓] Default rules applied successfully")


def apply_rule(rule):
    flag_cmd = ["-C", "-A"]
    cmd = ["sudo", "iptables", flag_cmd[0], "INPUT", "-p", rule["protocol"]]

    if rule["port"]:
        cmd += ["--dport", str(rule["port"])]

    if rule["src_ip"]:
        cmd += ["-s", rule["src_ip"]]

    if rule["mac_address"]:
        cmd += ["-m", "mac", "--mac-source", rule["mac_address"]]

    cmd += ["-j", rule["action"]]
    print(cmd, "before check")
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(result, "result")
    if result.returncode != 0:  # Rule does not exist
        cmd[2] = flag_cmd[1]
        print(cmd, "after check")
        subprocess.run(cmd)
        print(f"[+] Applied rule: {rule}")
    else:
        print(f"[=] Already applied: {rule}")


def delete_rule(rule):
    cmd = [
        "sudo",
        "iptables",
        "-D",
        "INPUT",
        "-p",
        rule["protocol"],
        "--dport",
        str(rule["port"]),
        "-j",
        rule["action"],
    ]
    subprocess.run(cmd)






# def apply_stateful_rules():
#     print("[+] Applying SPI (Stateful Packet Inspection) rules...")

#     # Allow valid sessions
#     subprocess.run(
#         [
#             "sudo",
#             "iptables",
#             "-A",
#             "INPUT",
#             "-m",
#             "state",
#             "--state",
#             "ESTABLISHED,RELATED",
#             "-j",
#             "ACCEPT",
#         ]
#     )
#     # Drop broken/unmatched packets
#     subprocess.run(
#         [
#             "sudo",
#             "iptables",
#             "-A",
#             "INPUT",
#             "-m",
#             "state",
#             "--state",
#             "INVALID",
#             "-j",
#             "DROP",
#         ]
#     )
#     subprocess.run(
#         [
#             "sudo",
#             "iptables",
#             "-A",
#             "INPUT",
#             "-m",
#             "state",
#             "--state",
#             "INVALID",
#             "-j",
#             "LOG",
#             "--log-prefix"
#             "INVALID_PKT"
#         ]
#     )


#     print("[✓] SPI rules applied.")