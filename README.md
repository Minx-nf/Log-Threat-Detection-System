# 🛡️ SOC Threat Detection & SIEM System

An enterprise-grade Security Information and Event Management (SIEM) system designed for centralized LAN log monitoring, real-time threat intelligence, and automated incident response.

## 🚀 Key Features

* **Centralized SOC Dashboard**: Real-time web interface powered by Flask, providing high-level analytics and low-level log exploration.
* **Intelligent Threat Detection**: Heuristic detection for SQL Injection, XSS, Path Traversal, Brute-Force, and Port Scans.
* **Threat Intelligence**: Integrated **AbuseIPDB** API with in-memory caching and configurable IP whitelisting for accurate, performance-optimized reputation checks.
* **Distributed Telemetry**: Lightweight Python-based Windows Event Log collector agent with automated PowerShell deployment.
* **Automated Documentation**: Instant generation of vector-based PDF security reports using `ReportLab`.
* **Resilient Infrastructure**: Centralized storage using Elasticsearch with a 24-hour rolling security scoring algorithm.

## 🛠 Tech Stack

* **Backend**: Python 3.x, Flask (RESTful API), `pywin32`
* **Data Storage**: Elasticsearch (NoSQL), Kibana (Visualization)
* **Frontend**: HTML5, CSS3, JavaScript (ApexCharts)
* **Security**: `bcrypt` (Auth), HMAC-style API Key validation

---

## ⚙️ Setup & Installation

### 1. Central Server Setup
1. **Initialize the Stack**:
   ```bash
   docker-compose up -d
   ```
2. **Environment Configuration**:
   Create a `.env` file in the root directory (ensure it is added to `.gitignore`):
   ```text
   SECRET_KEY=generate_a_long_random_string
   ADMIN_PASSWORD_HASH=generate_bcrypt_hash
   COLLECTOR_API_KEY=your_64_character_hex_key
   ABUSEIPDB_API_KEY=your_abuseipdb_key
   WHITELIST_IPS=127.0.0.1,192.168.1.
   ```
3. **Launch the SOC**:
   ```bash
   pip install -r requirements.txt
   python backend/app.py
   ```
   *Dashboard access: `http://localhost:5000`*

### 2. LAN Collector Deployment
To monitor endpoints on your network:
1. Ensure the Client and Server are on the same subnet.
2. Run the deployment script on the Client (as Administrator):
   ```powershell
   .\backend\install_collector_task.ps1 -ServerUrl http://SERVER_IP:5000
   ```

---

## 🔒 Security Implementation

| Layer | Implementation Detail |
|-------|-----------------------|
| **Admin Auth** | `bcrypt` hashing (12 rounds) |
| **Ingestion Security** | Authorized `X-API-Key` handshakes |
| **Threat Analysis** | Pre-compiled regex engine for speed |
| **Reputation Check** | AbuseIPDB API with hourly caching |
| **False Positives** | Configurable `WHITELIST_IPS` |
| **Secrets Management** | .env excluded from Git via .gitignore |

---

## 📂 Project Structure
```text
soc-threat-detector/
├── backend/            # Flask API, Detector engine, Elasticsearch handlers
├── frontend/           # Jinja2 templates, static CSS/JS
├── reports/            # Auto-generated PDF incident reports
├── docker-compose.yml  # Elastic Stack infrastructure
└── requirements.txt    # Python dependencies
```

## Deployment & Security Notes

### 1. SSL/TLS Certificate Requirement
**CRITICAL NOTE FOR DEPLOYMENT:** If you are running your collector on a different PC than the server, you must copy the `certs/cert.pem` file onto that client PC. Put it in the same directory as your `windows_log_collector.py` file. Without this file, the agent will fail to verify the connection and the service will crash.

### 2. Scalability for Production Environments
This SOC Monitor is optimized for local LAN/SMB environments. If you intend to scale this to an enterprise level (50+ agents or high log volume):
* **Elasticsearch:** Move from a single-node instance to a clustered setup for redundancy.
* **Backend:** Swap the `Flask-Limiter` storage from `memory://` to a persistent Redis instance.
* **Network:** Use a dedicated Reverse Proxy (like Nginx) with a Web Application Firewall (WAF) to handle external traffic instead of exposing the Flask app directly.

### 3. Log Retention & Storage (ILM)
To prevent disk exhaustion, this system utilizes Elasticsearch Index Lifecycle Management (ILM).
* **Policy:** A 30-day retention policy is enforced.
* **Rollover:** New indices are created every 7 days or upon reaching 50GB.
* **Cleanup:** Logs older than 30 days are automatically deleted by the system.

**Initialization:**
If you are setting up a fresh environment, run the following infrastructure scripts to apply the retention policies:
```bash
python backend/setup_ilm.py
python backend/setup_template.py

## 🔮 Future Enhancements
* SMTP/Email integration for critical alert notifications.
* Role-Based Access Control (RBAC) for multi-analyst workflows.
* Expansion to Syslog collectors for Linux environment monitoring.