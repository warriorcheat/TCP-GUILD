# bot_monitor.py
# Usage: python bot_monitor.py
import time, json
from pathlib import Path
import subprocess
import sys
import psutil

HEARTBEAT_FILE = Path("bot_heartbeat.json")
HEARTBEAT_TIMEOUT = 12.0   # seconds -> যদি শেষ আপডেট 12 সেকেন্ডের বেশি পুরোনো, treat as dead
FALCON_CMD = ["python", "FALCON.py"]  # পরিবর্তন করে দাও যদি অন্যভাবে চালাও
FALCON_CWD = "."  # FALCON.py যেখানে থাকে সেই ডিরেক্টরি

def read_heartbeat():
    if not HEARTBEAT_FILE.exists():
        return None
    try:
        with HEARTBEAT_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def is_process_running_by_cmd(cmd_substr):
    # check if any running process contains the command substring
    for p in psutil.process_iter(['pid','cmdline']):
        try:
            cmdline = " ".join(p.info.get('cmdline') or [])
            if cmd_substr in cmdline:
                return True
        except Exception:
            continue
    return False

def start_falcon():
    print("Starting FALCON.py ...")
    p = subprocess.Popen(FALCON_CMD, cwd=FALCON_CWD)
    time.sleep(1)
    print("Started PID:", p.pid)

def main_loop():
    print("Bot Monitor started. Press Ctrl+C to exit.")
    try:
        while True:
            hb = read_heartbeat()
            now = time.time()
            status = "UNKNOWN"
            last = None
            if hb and isinstance(hb, dict) and hb.get("timestamp"):
                last = float(hb["timestamp"])
                age = now - last
                if age <= HEARTBEAT_TIMEOUT:
                    status = "ALIVE"
                else:
                    status = "STALE"
            else:
                status = "NO_HEARTBEAT"

            # also check process by command substring "FALCON.py"
            proc_running = is_process_running_by_cmd("FALCON.py")

            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Status: {status}"
                  + (f" | last update {age:.1f}s ago" if last else ""))
            print(f"    Process running (by cmd)?: {proc_running}")
            print("    Options: (r)estart if dead, (s)kip, (q)uit")

            choice = input("Choose [r/s/q] (default s): ").strip().lower() or "s"
            if choice == "r":
                # restart only if not running or heartbeat stale
                if not proc_running or status != "ALIVE":
                    start_falcon()
                else:
                    print("Process is running and heartbeat OK — not restarting.")
            elif choice == "q":
                print("Exiting monitor.")
                break

            print("-" * 60)
            # wait before next check
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nMonitor stopped by user.")

if __name__ == "__main__":
    # check psutil
    try:
        import psutil  # already used above
    except Exception:
        print("Please install psutil: pip install psutil")
        sys.exit(1)
    main_loop()
