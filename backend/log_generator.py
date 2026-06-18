import json
import random
import requests
import uuid
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()

EVENTS = [
    "failed_login",
    "successful_login",
    "privilege_escalation",
    "port_scan"
]

USERS = [
    "admin",
    "john",
    "alice",
    "bob"
]

# Random malicious payloads to trigger your new Regex rules
MALICIOUS_PAYLOADS = [
    "' OR 1=1 --",
    "admin' --",
    "<script>alert('xss')</script>",
    "../../../etc/passwd",
    "UNION SELECT username, password FROM users"
]

def fire_live_rounds(count=50, target_url="http://127.0.0.1:5000/api/logs"):
    logs = []
    print(f"[*] Assembling {count} malicious packets...")
    
    for _ in range(count):
        event = random.choice(EVENTS)
        
        log = {
            # INJECTING A UNIQUE ID SO ELASTICSEARCH DOESN'T OVERWRITE THEM
            "id": str(uuid.uuid4()), 
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "event_type": event,
            "username": random.choice(USERS),
            "source_ip": f"192.168.1.{random.randint(1,254)}",
            "hostname": "test-victim-pc",
        }
        
        # Sneak in some SQLi or XSS payloads randomly to test the detector
        if random.random() > 0.7:
            log["message"] = random.choice(MALICIOUS_PAYLOADS)
            
        logs.append(log)

    print(f"[*] Firing payload at {target_url}...")
    my_key = os.getenv("COLLECTOR_API_KEY")
    try:
        response = requests.post(
            target_url, 
            json=logs, 
            headers={"X-API-Key": my_key}, 
            timeout=30
        )
        if response.status_code == 200:
            print("[+] Direct hit! Logs successfully injected into the SOC.")
            print("[+] Go check your Logs Explorer. You should see all of them now.")
        else:
            print(f"[-] Server deflected the attack. Code {response.status_code}: {response.text}")
    except requests.exceptions.ConnectionError:
        print("[-] Connection failed. Is your Flask app.py actually running in another terminal?")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

if __name__ == "__main__":
    # Fire 100 fake logs at the server
    fire_live_rounds(100)