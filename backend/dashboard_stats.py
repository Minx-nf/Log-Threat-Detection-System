from datetime import datetime, timedelta

from elasticsearch_handler import get_all_alerts, get_all_logs

def _parse_timestamp(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None

def get_dashboard_stats():
    logs = get_all_logs()
    alerts = get_all_alerts()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    # NEW: Establish the 24-hour rolling window for the auto-healing score
    score_cutoff = datetime.utcnow() - timedelta(hours=24)
    score = 100

    for alert in alerts:
        severity = alert.get("severity", "LOW")

        # 1. Update the all-time UI counters so your charts stay accurate
        if severity in severity_counts:
            severity_counts[severity] += 1

        # 2. Apply penalties to the score ONLY if the attack is less than 24 hours old
        timestamp = _parse_timestamp(alert.get("timestamp", ""))
        if timestamp and timestamp >= score_cutoff:
            if severity == "CRITICAL":
                score -= 8
            elif severity == "HIGH":
                score -= 4
            elif severity == "MEDIUM":
                score -= 2
            elif severity == "LOW":
                score -= 1

    score = max(score, 0)

    # (Preserved) Check for online agents in the last 2 minutes
    recent_cutoff = datetime.utcnow() - timedelta(minutes=2)
    online_agents = set()

    for log in logs:
        timestamp = _parse_timestamp(log.get("timestamp", ""))

        if timestamp and timestamp >= recent_cutoff:
            online_agents.add(
                log.get("collector_id")
                or log.get("hostname")
                or log.get("collector_ip")
            )

    return {
        "total_logs": len(logs),
        "total_alerts": len(alerts),
        "critical_alerts": severity_counts["CRITICAL"],
        "high_alerts": severity_counts["HIGH"],
        "medium_alerts": severity_counts["MEDIUM"],
        "low_alerts": severity_counts["LOW"],
        "online_agents": len([agent for agent in online_agents if agent]),
        "security_score": int(score),
    }