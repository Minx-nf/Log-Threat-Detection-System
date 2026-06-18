from elasticsearch import Elasticsearch

# Connect to your ES instance
es = Elasticsearch(["http://localhost:9200"])

# Define the policy: Delete logs after 30 days
policy_body = {
    "policy": {
        "phases": {
            "hot": {
                "actions": {
                    "rollover": {
                        "max_age": "7d",   # Start a new index every 7 days
                        "max_size": "50gb" # Or if index hits 50GB
                    }
                }
            },
            "delete": {
                "min_age": "30d", # Delete everything older than 30 days
                "actions": {
                    "delete": {}
                }
            }
        }
    }
}

# Push the policy to Elasticsearch
try:
    es.ilm.put_lifecycle(name="logs-policy", body=policy_body)
    print("ILM Policy 'logs-policy' registered successfully.")
except Exception as e:
    print(f"Error registering policy: {e}")