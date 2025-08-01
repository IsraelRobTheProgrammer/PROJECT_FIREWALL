import threading
from scapy.all import sniff

# from dpi.inspector import start_dpi_capture
from dpi.inspector import inspect_packet

dpi_thread = None
stop_sniffing = threading.Event()


def run_dpi(interface="wlp3s0"):
    global dpi_thread, stop_sniffing
    if dpi_thread and dpi_thread.is_alive():
        return False  # already running

    stop_sniffing.clear()
    dpi_thread = threading.Thread(target=_sniff_packets, args=(interface,), daemon=True)
    dpi_thread.start()

    return True
    # if dpi_thread is None or not dpi_thread.is_alive():
    #     dpi_thread = threading.Thread(target=start_dpi_capture)
    #     dpi_thread.start()
    # else:
    #     print("DPI capture is already running.")


def _sniff_packets(interface):
    try:
        sniff(
            iface=interface,
            prn=inspect_packet,
            store=0,
            stop_filter=lambda p: stop_sniffing.is_set(),
        )
    except PermissionError:
        print("[!] DPI Engine requires root or CAP_NET_RAW privileges.")
        # stop_sniffing.set()


def stop_dpi():
    stop_sniffing.set()
    return True


def is_running():
    return (
        dpi_thread is not None and dpi_thread.is_alive() and not stop_sniffing.is_set()
    )


# import threading
# from dpi.inspector import start_dpi_capture

# dpi_thread = None


# def run_dpi():
#     global dpi_thread
#     if dpi_thread and dpi_thread.is_alive():
#         return False  # already running
#     dpi_thread = threading.Thread(target=start_dpi_capture, daemon=True)
#     dpi_thread.start()
#     return True
#     # if dpi_thread is None or not dpi_thread.is_alive():
#     #     dpi_thread = threading.Thread(target=start_dpi_capture)
#     #     dpi_thread.start()
#     # else:
#     #     print("DPI capture is already running.")

# def is_running():
#     return dpi_thread is not None and dpi_thread.is_alive()
