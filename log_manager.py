import json
import os
import socket
from firebase_uploader import upload_log
import threading
import time

PENDING_LOGS_FILE = "pending_logs.json"
last_upload_time = time.time()

def is_connected():
    """Check internet connectivity"""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def buffer_log(log_data: dict):
    """Temporarily store the log in a local JSON file"""
    logs = []
    if os.path.exists(PENDING_LOGS_FILE):
        with open(PENDING_LOGS_FILE, "r") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
    logs.append(log_data)
    with open(PENDING_LOGS_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def log_to_cloud_or_buffer(log_data: dict):
    """Upload the log to Firebase or buffer it locally if offline"""
    if is_connected():
        try:
            upload_log(log_data)
        except Exception as e:
            print(f"⚠️ Upload failed, buffering instead: {e}")
            buffer_log(log_data)
    else:
        print("📡 No internet connection — buffering the log")
        buffer_log(log_data)

def upload_pending_logs():
    """Upload all buffered logs if internet is available"""
    global last_upload_time
    if not is_connected():
        return

    if not os.path.exists(PENDING_LOGS_FILE):
        return

    with open(PENDING_LOGS_FILE, "r") as f:
        try:
            logs = json.load(f)
        except json.JSONDecodeError:
            logs = []

    if not logs:
        return

    print(f"☁️ Uploading {len(logs)} buffered logs to Firebase...")

    for log in logs:
        try:
            upload_log(log)
        except Exception as e:
            print(f"❌ Failed to upload log: {e}")

    # Clear buffer file after uploading
    with open(PENDING_LOGS_FILE, "w") as f:
        json.dump([], f)
    last_upload_time = time.time()

def start_periodic_upload(min_interval_seconds=10, max_buffer_size=50):
    """Start a loop that periodically uploads buffered logs based on time or buffer size"""
    def loop():
        global last_upload_time
        logs = []
        if os.path.exists(PENDING_LOGS_FILE):
            with open(PENDING_LOGS_FILE, "r") as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []

        time_since_last_upload = time.time() - last_upload_time

        if len(logs) >= max_buffer_size or time_since_last_upload >= min_interval_seconds:
            upload_pending_logs()

        threading.Timer(1, loop).start()

    loop()


