from dpi.inspector import start_dpi_capture


def run_dpi_layer(interface="wlp3s0"):
    print("[+] DPI Engine active...")
    start_dpi_capture(interface)
