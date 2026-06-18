import requests

# Adjust this if your Elasticsearch is on a different port/IP
ES_URL = "http://localhost:9200"

def nuke_database():
    print("Initiating database wipe...")
    
    # Updated to match your exact index names
    res_logs = requests.delete(f"{ES_URL}/system_logs")
    if res_logs.status_code in [200, 404]:
        print("[-] system_logs index cleared.")
    
    res_alerts = requests.delete(f"{ES_URL}/security_alerts")
    if res_alerts.status_code in [200, 404]:
        print("[-] security_alerts index cleared.")
        
    print("Database is completely clean! You are ready for testing.")

if __name__ == "__main__":
    nuke_database()