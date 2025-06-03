import subprocess
from core.logger import log_action

# from core.apply_firewall_rules import apply_rules_from_db
def block_ip(ip):
    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(cmd)
    print(f"[X] Blocked IP: {ip}")
    log_action("BLOCK_IP", ip)


def unblock_ip(ip):
    cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(cmd)
    print(f"[✓] Unblocked IP: {ip}")
    log_action("UNBLOCK_IP", ip)


def add_rule(port):
    cmd = [
        "sudo",
        "iptables",
        "-A",
        "INPUT",
        "-p",
        "tcp",
        "--dport",
        str(port),
        "-j",
        "ACCEPT",
    ]
    subprocess.run(cmd)
    print(f"[+] Rule added: Allow TCP traffic on port {port}")
    log_action("ADD_RULE", f"Port{port}")


def remove_rule(port):
    cmd = [
        "sudo",
        "iptables",
        "-D",
        "INPUT",
        "-p",
        "tcp",
        "--dport",
        str(port),
        "-j",
        "ACCEPT",
    ]
    subprocess.run(cmd)
    print(f"[-] Rule removed: Block TCP traffic on port {port}")
    log_action("REMOVE_RULE", f"Port{port}")


def list_rules():
    cmd = ["sudo", "iptables", "-L", "-n", "-v"]
    subprocess.run(cmd)


def save_rules():
    subprocess.run(["sudo", "netfilter-persistent", "save"])
    print("[✓] Current rules saved permanently.")
    log_action("SAVE_RULES", "Saved rules using iptables-persistent")


def main_menu():
    while True:
        print("\nFirewall Rule Manager")
        print("1. Add Rule")
        print("2. Remove Rule")
        print("3. Show Rules")
        print("4. Exit")
        print("5. Block IP")
        print("6. Unblock IP")
        print("7. Save Rules")

        choice = input("Enter your choice: ")

        if choice == "1":
            port = input("Enter port number to allow: ")
            add_rule(port)
        elif choice == "2":
            port = input("Enter port number to block: ")
            remove_rule(port)
        elif choice == "3":
            list_rules()
        elif choice == "4":
            print("Exiting... Goodbye!")
            break
        elif choice == "5":
            ip = input("Enter IP address to block: ")
            block_ip(ip)
        elif choice == "6":
            ip = input("Enter IP address to unblock: ")
            unblock_ip(ip)
        elif choice == "7":
            save_rules()
        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main_menu()
