import subprocess

from .db_functions import (
    add_rule_to_db,
    list_rules_from_db,
    delete_rule_from_db,
    fetch_rules_from_db,
)
from .rule_applier import apply_rule


def list_rules():
    cmd = ["sudo", "iptables", "-L", "-n", "-v", "--line-numbers"]
    subprocess.run(cmd)


def apply_all_rules():
    apply_stateful_rules()

    rules = fetch_rules_from_db()
    for rule in rules:
        apply_rule(rule)


def apply_stateful_rules():
    print("[+] Applying SPI (Stateful Packet Inspection) rules...")

    # Allow valid sessions
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-m",
            "state",
            "--state",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ]
    )
    # Drop broken/unmatched packets
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-m",
            "state",
            "--state",
            "INVALID",
            "-j",
            "DROP",
        ]
    )
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-A",
            "INPUT",
            "-m",
            "state",
            "--state",
            "INVALID",
            "-j",
            "LOG",
            "--log-prefix"
            "INVALID_PKT"
        ]
    )


    print("[✓] SPI rules applied.")


def main_menu():
    while True:
        print("\nFirewall DB Manager")
        print("1. Add Rule")
        print("2. Delete Rule")
        print("3. List Rules from DB")
        print("4. List Applied Rules ")
        print("5. Apply Rules to iptables")
        print("6. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            port = input("Enter port number (or leave blank for all): ")
            port = int(port) if port else None

            protocol = input("Enter protocol (tcp/udp): ").lower()
            action = input("Enter action (ACCEPT/DROP): ").upper()

            src_ip = input("Enter source IP (leave blank for any): ")
            src_ip = src_ip if src_ip else None

            mac_address = input("Enter MAC address (leave blank for any): ")
            mac_address = mac_address if mac_address else None

            add_rule_to_db(port, protocol, action, src_ip, mac_address)
        elif choice == "2":
            rule_id = int(input("Enter rule ID to delete: "))
            delete_rule_from_db(rule_id)
        elif choice == "3":
            list_rules_from_db()
        elif choice == "4":
            list_rules()
        elif choice == "5":
            apply_all_rules()
        elif choice == "6":
            print("GoodBye ")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main_menu()
