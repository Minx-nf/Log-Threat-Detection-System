import os
import requests
from datetime import datetime, timedelta
import re

from rules import *

failed_logins = {}
last_cleanup = datetime.utcnow()
WHITELIST_IPS = os.getenv("WHITELIST_IPS", "").split(",")
# Compiled Regex Patterns (Case-insensitive and handles spacing variations)
SQL_INJECTION_REGEX = re.compile(r"(?i)(union\s+select|'\s*or\s+.*|\"\s*or\s+.*|drop\s+table|--)")
XSS_REGEX = re.compile(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=)")
PATH_TRAVERSAL_REGEX = re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|boot\.ini)")

def _parse_time(value):
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return datetime.utcnow()

def _base_alert(log, threat, severity):
    return {
        "record_number": log.get("record_number"),
        "event_id": log.get("event_id"),
        "threat": threat,
        "severity": severity,
        "username": log.get("username", ""),
        "source_ip": log.get("source_ip", ""),
        "collector_ip": log.get("collector_ip", ""),
        "collector_id": log.get("collector_id", ""),
        "hostname": log.get("hostname", ""),
        "timestamp": log.get("timestamp"),
    }

def _text_fields(log):
    fields = [
        "message",
        "raw_message",
        "request",
        "url",
        "path",
        "query",
        "command_line",
        "process_name",
    ]
    return " ".join(
        str(log.get(field, ""))
        for field in fields
    )

def _cleanup_stale_logins(now, window_start):
    """Memory Leak Fix: Prunes IPs that haven't attacked recently."""
    global last_cleanup, failed_logins
    
    # Only run cleanup every 5 minutes to save CPU
    if (now - last_cleanup).total_seconds() > 300:
        stale_keys = []
        for k, attempts in failed_logins.items():
            valid_attempts = [a for a in attempts if a >= window_start]
            if not valid_attempts:
                stale_keys.append(k)
            else:
                failed_logins[k] = valid_attempts
                
        for k in stale_keys:
            del failed_logins[k]
            
        last_cleanup = now

def _track_failed_login(username, ip, timestamp):
    key = f"{username or 'unknown'}|{ip or 'unknown'}"
    window_start = timestamp - timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)

    _cleanup_stale_logins(timestamp, window_start)

    attempts = [
        attempt
        for attempt in failed_logins.get(key, [])
        if attempt >= window_start
    ]

    attempts.append(timestamp)
    failed_logins[key] = attempts

    return key, len(attempts)


# Stores: { "ip": (score, timestamp) }
ip_reputation_cache = {}

def check_ip_reputation(ip):
    # 1. WHITELIST CHECK
    if ip in WHITELIST_IPS: 
        return 0

    # 2. CACHE CHECK
    now = datetime.utcnow()
    if ip in ip_reputation_cache:
        score, timestamp = ip_reputation_cache[ip]
        if (now - timestamp).total_seconds() < 3600:
            return score
    
    # 3. API CHECK
    if ip == "127.0.0.1" or ip == "unknown": return 0
    
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key: return 0
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Key': api_key, 'Accept': 'application/json'}
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=2)
        if response.status_code == 200:
            score = response.json()['data']['abuseConfidenceScore']
            # Save score AND current time
            ip_reputation_cache[ip] = (score, now)
            return score
    except: 
        pass 
    return 0

def analyze_log(log):
    event_type = log.get("event_type", "")
    username = log.get("username", "")
    ip = log.get("source_ip", "")
    timestamp_value = log.get("timestamp", "")
    timestamp = _parse_time(timestamp_value)

    if event_type == "failed_login":
        _, attempts = _track_failed_login(username, ip, timestamp)
        if attempts >= FAILED_LOGIN_THRESHOLD:
            return _base_alert(log, THREAT_TYPES["BRUTE_FORCE"], "HIGH")

    if event_type == "successful_login":
        key = f"{username or 'unknown'}|{ip or 'unknown'}"
        if len(failed_logins.get(key, [])) >= FAILED_LOGIN_THRESHOLD:
            failed_logins[key] = []
            return _base_alert(log, THREAT_TYPES["AFTER_FAILURE_LOGIN"], "MEDIUM")

        try:
            hour = timestamp.hour
            if hour < BUSINESS_HOURS_START or hour > BUSINESS_HOURS_END:
                return _base_alert(log, THREAT_TYPES["OFF_HOURS_LOGIN"], "MEDIUM")
        except Exception:
            pass

    if event_type == "privilege_escalation":
        return _base_alert(log, THREAT_TYPES["PRIVILEGE_ESCALATION"], "HIGH")

    if event_type == "port_scan":
        return _base_alert(log, THREAT_TYPES["PORT_SCAN"], "CRITICAL")

    text = _text_fields(log)

    # Replaced _match_any with Regex searches
    if SQL_INJECTION_REGEX.search(text):
        return _base_alert(log, THREAT_TYPES["SQL_INJECTION"], "CRITICAL")

    if XSS_REGEX.search(text):
        return _base_alert(log, THREAT_TYPES["XSS_ATTEMPT"], "HIGH")

    if PATH_TRAVERSAL_REGEX.search(text):
        return _base_alert(log, THREAT_TYPES["PATH_TRAVERSAL"], "HIGH")

    # AbuseIPDB Check
    ip = log.get("source_ip")
    if ip and check_ip_reputation(ip) > 50:
         return _base_alert(log, "MALICIOUS_IP_DETECTED", "CRITICAL")

    return None