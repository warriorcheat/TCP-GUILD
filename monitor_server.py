# monitor_server.py
from flask import Flask, jsonify, render_template_string
from pathlib import Path
import json, time

app = Flask(__name__)
HEARTBEAT_FILE = Path("bot_heartbeat.json")
HEARTBEAT_TIMEOUT = 12.0

TEMPLATE = """
<!doctype html>
<title>Bot Monitor</title>
<h1>Bot Monitor</h1>
<p>Status: <strong style="color:{{color}}">{{status}}</strong></p>
<p>Last update: {{last_update}}</p>
<p>Age (s): {{age}}</p>
"""

def read_heartbeat():
    if not HEARTBEAT_FILE.exists(): return None
    try:
        with HEARTBEAT_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

@app.route("/status")
def status_api():
    hb = read_heartbeat()
    now = time.time()
    if not hb or "timestamp" not in hb:
        return jsonify({"status":"NO_HEARTBEAT"}), 200
    age = now - float(hb["timestamp"])
    ok = age <= HEARTBEAT_TIMEOUT
    return jsonify({
        "status": "ALIVE" if ok else "STALE",
        "last_ts": hb["timestamp"],
        "age_seconds": age
    }), 200

@app.route("/")
def home():
    hb = read_heartbeat()
    now = time.time()
    if not hb or "timestamp" not in hb:
        status = "NO_HEARTBEAT"
        color = "gray"
        last = "N/A"
        age = "N/A"
    else:
        age = now - float(hb["timestamp"])
        status = "ALIVE" if age <= HEARTBEAT_TIMEOUT else "STALE"
        color = "green" if status=="ALIVE" else "orange"
        last = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(hb["timestamp"]))
    return render_template_string(TEMPLATE, status=status, color=color, last_update=last, age=age)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
