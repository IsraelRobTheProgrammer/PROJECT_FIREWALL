import subprocess

# def apply_rule(rule):
#     cmd = ["sudo", "iptables", "-A", "INPUT", "-p", rule["protocol"], "--dport", str(rule["port"]), "-j", rule["action"]]
#     subprocess.run(cmd)


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
