from datetime import datetime


def log_action(action, detail):
    with open("firewall_log.txt", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {action}: {detail}\n")
