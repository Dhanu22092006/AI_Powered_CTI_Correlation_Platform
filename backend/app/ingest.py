import csv, io, hashlib
from datetime import datetime, timezone
from .db import db
from .extract import extract_iocs
from .scoring import calculate_risk
from .graph import add_indicator_graph

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def process_record(text: str, source: str, title: str, demo: bool = False):
    iocs = extract_iocs(text)
    source_ref = {"name": source, "title": title, "observed_at": utcnow(), "demo": demo}
    saved = []
    for ioc in iocs:
        value = ioc["value"]
        fingerprint = hashlib.sha256(f"{ioc['type']}:{value.lower()}".encode()).hexdigest()
        doc = {
            **ioc, "fingerprint": fingerprint, "sources": [source_ref],
            "created_at": utcnow(), "demo": demo
        }
        db.indicators.update_one(
            {"fingerprint": fingerprint},
            {"$setOnInsert": doc, "$addToSet": {"source_names": source, "sources": source_ref}},
            upsert=True
        )
        saved.append(ioc)
    # Co-mentioned links are explicitly inferred, never labelled as confirmed.
    for item in saved:
        add_indicator_graph(item, source, [x for x in saved if x != item])
    if len(saved) >= 2:
        risk = calculate_risk(len(saved), 1, any(x["type"] == "cve" for x in saved), 10)
        alert_key = hashlib.sha256((source + "|" + "|".join(sorted(x["value"] for x in saved))).encode()).hexdigest()
        db.alerts.update_one(
            {"dedupe_key": alert_key},
            {"$setOnInsert": {
                "dedupe_key": alert_key,
                "title": f"Related indicators identified in {title}",
                "description": "Multiple indicators were extracted from one source record. This is a lead for analyst review, not proof of a common attack.",
                "status": "new", "risk": risk, "indicators": saved,
                "evidence": [source_ref],
                "explanation": "Indicators were co-mentioned in the same source record. The relationship is inferred and requires analyst validation.",
                "created_at": utcnow(), "demo": demo
            }},
            upsert=True
        )
    db.audit_logs.insert_one({"action": "ingest_record", "source": source, "title": title, "ioc_count": len(saved), "created_at": utcnow(), "demo": demo})
    return {"extracted": len(saved), "indicators": saved}

def parse_csv(raw: bytes):
    text = raw.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for row in reader:
        content = row.get("text") or row.get("description") or row.get("indicator") or row.get("value") or " ".join(str(v) for v in row.values() if v)
        rows.append({"text": content, "title": row.get("title") or "CSV record"})
    return rows

def parse_json(raw: bytes):
    import json
    obj = json.loads(raw.decode("utf-8"))
    if isinstance(obj, dict):
        obj = obj.get("records", [obj])
    if not isinstance(obj, list):
        raise ValueError("JSON must be an array or an object containing records")
    rows = []
    for item in obj:
        if not isinstance(item, dict):
            continue
        content = item.get("text") or item.get("description") or item.get("content") or " ".join(str(v) for v in item.values() if v is not None)
        rows.append({"text": str(content), "title": str(item.get("title") or "JSON record")})
    return rows

def load_demo():
    records = [
        ("demo-campaign", "Demo report: suspicious domain threat-example.test and IP 198.51.100.23 were observed with SHA256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa. Related CVE-2021-44228 is mentioned for analyst review."),
        ("demo-advisory", "Demo advisory: domain threat-example.test appeared in a public threat report with URL https://threat-example.test/login and CVE-2021-44228."),
        ("demo-malware-report", "Demo malware report: suspicious IP 198.51.100.23 and MD5 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb were listed for investigation.")
    ]
    total = 0
    for title, text in records:
        total += process_record(text, "SIMULATED_DEMO_DATA", title, True)["extracted"]
    return {"records": len(records), "indicators_processed": total, "label": "SIMULATED DEMO DATA"}
