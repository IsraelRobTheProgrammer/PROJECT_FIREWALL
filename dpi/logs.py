import threading

log_buffer = []
log_lock = threading.Lock()


def add_log(message):
    with log_lock:
        log_buffer.append(message)
        if len(log_buffer) > 50:
            log_buffer.pop(0)


def get_logs():
    with log_lock:
        return list(log_buffer)


def clear_logs():
    with log_lock:
        log_buffer.clear()
