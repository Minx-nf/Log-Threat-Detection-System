import hashlib
import os
from uuid import uuid4

from elasticsearch import Elasticsearch

# Environment Variables for Configuration
ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "changeme") # Default for dev, change in prod

LOG_INDEX = os.getenv("LOG_INDEX", "system_logs")
ALERT_INDEX = os.getenv("ALERT_INDEX", "security_alerts")

# Secured Client Initialization
es = Elasticsearch(
    ELASTIC_URL,
    basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
    verify_certs=False, # Leaving False for local LAN dev to avoid SSL headaches, but auth is enforced
    request_timeout=5,
)

LOG_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "event_type": {"type": "keyword"},
            "source_ip": {"type": "ip", "ignore_malformed": True},
            "collector_ip": {"type": "ip", "ignore_malformed": True},
            "collector_id": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "username": {"type": "keyword"},
            "record_number": {"type": "keyword"},
        }
    }
}

ALERT_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "threat": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "source_ip": {"type": "ip", "ignore_malformed": True},
            "collector_ip": {"type": "ip", "ignore_malformed": True},
            "collector_id": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "username": {"type": "keyword"},
            "record_number": {"type": "keyword"},
        }
    }
}

def create_indices():
    try:
        if not es.indices.exists(index=LOG_INDEX):
            es.indices.create(index=LOG_INDEX, body=LOG_MAPPING)

        if not es.indices.exists(index=ALERT_INDEX):
            es.indices.create(index=ALERT_INDEX, body=ALERT_MAPPING)
    except Exception:
        return False
    return True

def elasticsearch_online():
    try:
        return bool(es.ping())
    except Exception:
        return False

def _stable_document_id(data, prefix):
    explicit_id = data.get(f"{prefix}_id") or data.get("id")

    if explicit_id:
        return str(explicit_id)

    identity_parts = [
        data.get("collector_id"),
        data.get("hostname"),
        data.get("log_type"),
        data.get("source"),
        data.get("record_number"),
        data.get("event_id"),
        data.get("timestamp"),
        data.get("threat") if prefix == "alert" else None,
    ]

    identity = "|".join(
        str(part)
        for part in identity_parts
        if part not in (None, "")
    )

    if not identity:
        identity = str(uuid4())

    return hashlib.sha256(identity.encode("utf-8")).hexdigest()

def save_log(log_data):
    create_indices()
    document = dict(log_data)
    es.index(
        index=LOG_INDEX,
        id=_stable_document_id(document, "log"),
        document=document,
    )

def save_alert(alert_data):
    create_indices()
    document = dict(alert_data)
    es.index(
        index=ALERT_INDEX,
        id=_stable_document_id(document, "alert"),
        document=document,
    )

def _search_index(index, limit=500, sort=None):
    if not es.indices.exists(index=index):
        return []

    params = {
        "index": index,
        "size": limit,
        "query": {"match_all": {}},
    }

    if sort:
        params["sort"] = sort

    result = es.search(**params)

    return [
        hit["_source"]
        for hit in result["hits"]["hits"]
    ]

def get_all_logs(limit=500):
    try:
        logs = _search_index(
            LOG_INDEX,
            limit=limit,
            sort=[{"timestamp": {"order": "desc"}}],
        )
    except Exception:
        try:
            logs = _search_index(LOG_INDEX, limit=limit)
        except Exception:
            logs = []
            
    # Brute-force Python sort to guarantee newest-first for the UI
    return sorted(logs, key=lambda k: k.get("timestamp", ""), reverse=True)

def get_all_alerts(limit=500):
    try:
        alerts = _search_index(
            ALERT_INDEX,
            limit=limit,
            sort=[{"timestamp": {"order": "desc"}}],
        )
    except Exception:
        try:
            alerts = _search_index(ALERT_INDEX, limit=limit)
        except Exception:
            alerts = []
            
    # Brute-force Python sort to guarantee newest-first for the UI
    return sorted(alerts, key=lambda k: k.get("timestamp", ""), reverse=True)

def search_logs(field, value):
    try:
        if not es.indices.exists(index=LOG_INDEX):
            return []

        result = es.search(
            index=LOG_INDEX,
            query={
                "match": {
                    field: value
                }
            },
        )
        return [
            hit["_source"]
            for hit in result["hits"]["hits"]
        ]
    except Exception:
        return []

create_indices()