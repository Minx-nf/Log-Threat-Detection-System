from elasticsearch import Elasticsearch

es = Elasticsearch(["http://localhost:9200"])

# This template says: "Hey Elasticsearch, if any new index starts with 'logs-', 
# attach the 'logs-policy' to it automatically."
template_body = {
    "index_patterns": ["logs-*"], # The "Hiring" criteria
    "template": {
        "settings": {
            "index.lifecycle.name": "logs-policy", # The handbook to follow
            "index.lifecycle.rollover_alias": "logs-write" # Alias for writing new data
        }
    }
}

# Apply the template
es.indices.put_index_template(name="logs-template", body=template_body)
print("Binding complete. New logs will now follow the 30-day policy.")