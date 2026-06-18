FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 10

BUSINESS_HOURS_START = 6
BUSINESS_HOURS_END = 22

SEVERITY = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5
}

THREAT_TYPES = {
    "BRUTE_FORCE": "Brute Force Attack",
    "AFTER_FAILURE_LOGIN": "Login After Failures",
    "OFF_HOURS_LOGIN": "Off Hours Login",
    "PRIVILEGE_ESCALATION": "Privilege Escalation Attempt",
    "PORT_SCAN": "Port Scanning Activity",
    "SUSPICIOUS_IP": "Suspicious IP Activity",
    "SQL_INJECTION": "SQL Injection Attempt",
    "XSS_ATTEMPT": "Cross-Site Scripting Attempt",
    "PATH_TRAVERSAL": "Path Traversal Attempt"
}
