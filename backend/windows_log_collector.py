import argparse
import json
import os
import socket
import time
from datetime import datetime
from pathlib import Path
import requests
from dotenv import load_dotenv
load_dotenv()

# --- ADDED: API KEY CONFIG ---
# This looks for the key in your environment variables. 
# If not found, it defaults to the key you set in your server's .env
COLLECTOR_API_KEY = os.getenv("COLLECTOR_API_KEY")
# -----------------------------

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

AGENT_VERSION = "2.0"
DEFAULT_INTERVAL = int(os.getenv("COLLECTOR_INTERVAL", "15"))
DEFAULT_LIMIT = int(os.getenv("COLLECTOR_BATCH_SIZE", "50"))
DEFAULT_SERVER_URL = os.getenv(
    "COLLECTOR_SERVER_URL",
    "http://127.0.0.1:5000/api/logs",
)
STATE_FILE = Path(
    os.getenv(
        "COLLECTOR_STATE_FILE",
        Path(__file__).with_name("collector_state.json"),
    )
)

def normalize_server_url(url):
    clean_url = url.rstrip("/")
    if clean_url.endswith("/api/logs"):
        return clean_url
    return f"{clean_url}/api/logs"

# Added helper to get base URL
def get_base_url(url):
    return url.rsplit('/api/', 1)[0]

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def load_state():
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")

def get_insert(inserts, index, default=""):
    try: value = inserts[index]
    except Exception: return default
    if value in (None, "-", ""): return default
    return str(value)

def parse_event_details(event_id, inserts):
    details = {"event_type": "windows_event", "username": get_insert(inserts, 1, "windows_user"), "source_ip": "", "workstation": ""}
    if event_id == 4624:
        details.update({"event_type": "successful_login", "username": get_insert(inserts, 5, get_insert(inserts, 1, "windows_user")), "source_ip": get_insert(inserts, 18), "workstation": get_insert(inserts, 11), "logon_type": get_insert(inserts, 8)})
    elif event_id == 4625:
        details.update({"event_type": "failed_login", "username": get_insert(inserts, 5, get_insert(inserts, 1, "windows_user")), "source_ip": get_insert(inserts, 19), "workstation": get_insert(inserts, 13), "logon_type": get_insert(inserts, 10), "failure_reason": get_insert(inserts, 8)})
    elif event_id == 4672:
        details.update({"event_type": "privilege_escalation", "username": get_insert(inserts, 1, "windows_user")})
    return details

def get_recent_security_events(last_record_number=0, limit=50, log_type="Security"):
    if win32evtlog is None: raise RuntimeError("pywin32 is required.")
    hostname = socket.gethostname()
    collector_ip = get_local_ip()
    collector_id = f"{hostname}-{collector_ip}"
    handle = win32evtlog.OpenEventLog("localhost", log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = []
    highest_record = last_record_number

    while len(events) < limit:
        records = win32evtlog.ReadEventLog(handle, flags, 0)
        if not records: break
        for event in records:
            if len(events) >= limit: break
            if event.RecordNumber <= last_record_number: continue
            event_id = event.EventID & 0xFFFF
            inserts = list(event.StringInserts or [])
            details = parse_event_details(event_id, inserts)
            events.append({
                "record_number": event.RecordNumber, "event_id": event_id, "event_type": details.get("event_type", "windows_event"),
                "timestamp": event.TimeGenerated.isoformat(), "username": details.get("username", "windows_user"),
                "source_ip": details.get("source_ip") or collector_ip, "collector_ip": collector_ip,
                "collector_id": collector_id, "hostname": hostname, "log_type": log_type,
                "source": event.SourceName, "workstation": details.get("workstation", ""),
                "logon_type": details.get("logon_type", ""), "failure_reason": details.get("failure_reason", ""),
                "message": " | ".join(str(item) for item in inserts if item),
                "agent_version": AGENT_VERSION, "collected_at": datetime.utcnow().replace(microsecond=0).isoformat(),
            })
            highest_record = max(highest_record, event.RecordNumber)
    return events, highest_record

# --- MODIFIED: Added Headers ---
def send_logs(server_url, logs):
    if not logs: return True
    response = requests.post(
        normalize_server_url(server_url),
        json=logs,
        headers={"X-API-Key": COLLECTOR_API_KEY}, # The Handshake
        verify='certs/cert.pem'
        timeout=10,
    )
    response.raise_for_status()
    return True
# -------------------------------

def run_collector(server_url, interval, limit, log_type, once=False):
    state = load_state()
    state_key = f"{socket.gethostname()}:{log_type}"
    last_record_number = int(state.get(state_key, 0))
    endpoint = normalize_server_url(server_url)
    base_url = get_base_url(endpoint)

    print("Windows LAN Log Collector Started")
    print(f"Server endpoint: {endpoint}")
    
    current_interval = interval
    while True:
        try:
            logs, highest_record = get_recent_security_events(last_record_number=last_record_number, limit=limit, log_type=log_type)
            if logs:
                send_logs(endpoint, logs)
                last_record_number = highest_record
                state[state_key] = last_record_number
                save_state(state)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Sent {len(logs)} event(s).")
            
            # --- MODIFIED: Added Headers to Heartbeat ---
            try:
                requests.post(
                    f"{base_url}/api/heartbeat", 
                    headers={"X-API-Key": COLLECTOR_API_KEY}, 
                    timeout=5
                )
            except Exception: pass
            # --------------------------------------------
            
            current_interval = interval
        except requests.exceptions.RequestException as req_err:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Network Error: {req_err}")
            current_interval = min(current_interval * 2, 300)
            time.sleep(current_interval)
            continue
        except Exception as exc:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Collector error: {exc}")
            time.sleep(interval)
        
        if once: break
        time.sleep(interval)

def build_parser():
    parser = argparse.ArgumentParser(description="Collect Windows Security logs.")
    parser.add_argument("--server-url", default=DEFAULT_SERVER_URL)
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--log-type", default="Security")
    parser.add_argument("--once", action="store_true")
    return parser

if __name__ == "__main__":
    args = build_parser().parse_args()
    run_collector(args.server_url, args.interval, args.limit, args.log_type, args.once)