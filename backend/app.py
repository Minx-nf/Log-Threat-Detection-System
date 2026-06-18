from collections import defaultdict
from datetime import datetime, timedelta
import time
import os
import json
from functools import wraps
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from flask import Flask, jsonify, render_template, request, send_file, session, redirect, url_for
import requests

from dashboard_stats import get_dashboard_stats
from detector import analyze_log
from elasticsearch_handler import (
    elasticsearch_online,
    get_all_alerts,
    get_all_logs,
    save_alert,
    save_log,
)
from report_generator import generate_pdf

load_dotenv()

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
)

# --- Security Config ---
bcrypt = Bcrypt(app)
app.secret_key = os.getenv("SECRET_KEY", "fallback_dev_key_if_env_fails")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) 

ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
COLLECTOR_API_KEY = os.getenv("COLLECTOR_API_KEY", "change-me-in-env")
KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601")

# ==========================================
# SECURITY DECORATORS
# ==========================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.headers.get('X-API-Key') != COLLECTOR_API_KEY:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# AUTHENTICATION ROUTES
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Now checks against the hashed password
        if ADMIN_PASSWORD_HASH and bcrypt.check_password_hash(ADMIN_PASSWORD_HASH, request.form.get('password')):
            session.permanent = True
            session['logged_in'] = True
            return redirect(request.args.get('next') or url_for('dashboard'))
        error = "Invalid password. Access denied."
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _utc_now(): return datetime.utcnow().replace(microsecond=0).isoformat()

def _parse_timestamp(value):
    try: return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception: return None

def _normalize_log(log_data):
    log = dict(log_data)
    log.setdefault("timestamp", _utc_now())
    log.setdefault("event_type", "unknown")
    log.setdefault("source_ip", request.remote_addr or "unknown")
    log.setdefault("collector_ip", request.remote_addr or "unknown")
    log.setdefault("hostname", "unknown-host")
    log.setdefault("collector_id", log.get("hostname") or log.get("collector_ip"))
    return log

# ==========================================
# DASHBOARD ROUTES (Protected)
# ==========================================

@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", logs=get_all_logs(), stats=get_dashboard_stats(), alerts=get_all_alerts(limit=8))

@app.route("/settings")
@login_required
def settings(): return render_template("settings.html")

@app.route("/operations")
@login_required
def operations(): return render_template("operations.html")

@app.route("/analytics")
@login_required
def analytics(): return render_template("analytics.html")

@app.route("/logs")
@login_required
def logs(): return render_template("logs.html")

@app.route("/alerts")
@login_required
def alerts(): return render_template("alerts.html", alerts=get_all_alerts())

@app.route("/reports")
@login_required
def reports(): return render_template("reports.html")

# ==========================================
# PROTECTED API ROUTES
# ==========================================

@app.route("/api/logs", methods=["POST"])
@require_api_key  # Locked down!
def receive_log():
    payload = request.get_json(silent=True)
    if not payload: return jsonify({"status": "error"}), 400
    incoming_logs = payload if isinstance(payload, list) else [payload]
    saved = 0
    for incoming in incoming_logs:
        log = _normalize_log(incoming)
        save_log(log)
        saved += 1
        alert = analyze_log(log)
        if alert: save_alert(alert)
    return jsonify({"status": "success", "received": saved}), 200

@app.route("/api/logs", methods=["GET"])
@login_required
def get_logs(): return jsonify(get_all_logs())

@app.route("/api/threats")
@login_required
def api_threats(): return jsonify(get_all_alerts(limit=500))

@app.route("/api/agents")
@login_required
def api_agents():
    logs = get_all_logs(limit=1000)
    agents = defaultdict(lambda: {
        "collector_id": "",
        "hostname": "",
        "collector_ip": "",
        "total_logs": 0,
        "last_seen": "",
        "latest_event": "",
        "status": "offline",
    })

    for log in logs:
        key = (
            log.get("collector_id")
            or log.get("hostname")
            or log.get("collector_ip")
            or "unknown-agent"
        )
        agent = agents[key]
        agent["collector_id"] = key
        agent["hostname"] = log.get("hostname", agent["hostname"])
        agent["collector_ip"] = log.get("collector_ip", agent["collector_ip"])
        agent["total_logs"] += 1

        timestamp = log.get("timestamp", "")

        if not agent["last_seen"] or timestamp > agent["last_seen"]:
            agent["last_seen"] = timestamp
            agent["latest_event"] = log.get("event_type", "unknown")

    online_after = datetime.utcnow() - timedelta(minutes=2)

    for agent in agents.values():
        last_seen = _parse_timestamp(agent["last_seen"])

        if last_seen and last_seen >= online_after:
            agent["status"] = "online"

    return jsonify(
        sorted(
            agents.values(),
            key=lambda item: item["last_seen"],
            reverse=True,
        )
    )
@app.route("/api/stats")
@login_required
def api_stats(): return jsonify(get_dashboard_stats())

# ==========================================
# SYSTEM STATUS ROUTE
# ==========================================

@app.route("/api/system-status")
@login_required
def system_status():
    status = {
        "elasticsearch": elasticsearch_online(),
        "kibana": False,
        "flask": True,
    }

    try:
        response = requests.get(KIBANA_URL, timeout=2)
        status["kibana"] = response.status_code < 500
    except Exception:
        status["kibana"] = False

    return jsonify(status)


# ==========================================
# ANALYTICS ROUTE (Charts Data)
# ==========================================

@app.route("/api/analytics")
@login_required
def api_analytics():
    alerts = get_all_alerts()
    logs = get_all_logs()

    critical = len([alert for alert in alerts if alert.get("severity") == "CRITICAL"])
    high = len([alert for alert in alerts if alert.get("severity") == "HIGH"])
    medium = len([alert for alert in alerts if alert.get("severity") == "MEDIUM"])
    low = len([alert for alert in alerts if alert.get("severity") == "LOW"])

    event_counts = {}
    ip_counts = {}
    daily_counts = {}

    for log in logs:
        event = log.get("event_type", "unknown")
        event_counts[event] = event_counts.get(event, 0) + 1

        ip = log.get("source_ip", "unknown")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

        date = log.get("timestamp", "")[:10]
        if date:
            daily_counts[date] = daily_counts.get(date, 0) + 1

    return jsonify({
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "event_types": event_counts,
        "top_ips": ip_counts,
        "daily_events": daily_counts,
    })


# ==========================================
# HEARTBEAT & STATUS ROUTES (Collector Monitoring)
# ==========================================

# Global variable to track the last "ping" from the collector
last_heartbeat = 0

@app.route("/api/heartbeat", methods=["POST"])
@require_api_key
def api_heartbeat():
    global last_heartbeat
    last_heartbeat = time.time()
    return jsonify({"status": "received"})

@app.route("/api/status")
def api_status():
    global last_heartbeat
    is_alive = (time.time() - last_heartbeat) < 30
    return jsonify({"collector_status": "online" if is_alive else "offline"})


# ==========================================
# REPORT GENERATION ROUTE
# ==========================================

@app.route("/generate-report/<period>")
@login_required
def generate_report(period):
    stats = get_dashboard_stats()
    alerts = get_all_alerts()
    logs = get_all_logs()

    event_counts = {}
    for log in logs:
        event = log.get("event_type", "unknown")
        event_counts[event] = event_counts.get(event, 0) + 1

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for alert in alerts:
        severity = alert.get("severity", "LOW")
        if severity in severity_counts:
            severity_counts[severity] += 1

    analytics = {
        "event_types": event_counts,
        "severity_counts": severity_counts,
    }

    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename = os.path.join(reports_dir, f"{period}_report.pdf")
    generate_pdf(stats, alerts, analytics, filename)

    return send_file(filename, as_attachment=True)


# ==========================================
# SETTINGS CONFIGURATION ROUTE
# ==========================================

CONFIG_FILE = "soc_config.json"

def load_settings():
    if not os.path.exists(CONFIG_FILE):
        defaults = {"refresh_rate": "30", "strict_mode": True, "email_alerts": False}
        with open(CONFIG_FILE, "w") as f:
            json.dump(defaults, f, indent=4)
        return defaults
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    if request.method == "POST":
        new_settings = request.json
        with open(CONFIG_FILE, "w") as f:
            json.dump(new_settings, f, indent=4)
        return jsonify({"status": "success", "message": "Configuration saved."})
    return jsonify(load_settings())


# ==========================================
# DEBUG ROUTE (Optional - Remove in Production)
# ==========================================

@app.route("/debug")
@login_required
def debug():
    logs = get_all_logs()
    return jsonify(logs[:5])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("FLASK_PORT", 5000)), debug=True)