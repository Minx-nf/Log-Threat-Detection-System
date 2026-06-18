import json
import requests

URL = "http://localhost:5000/api/logs"

with open("sample_logs.json", "r") as f:
    logs = json.load(f)

for log in logs:
    requests.post(URL, json=log)

print("Logs sent successfully")