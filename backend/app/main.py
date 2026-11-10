from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse
from bson import ObjectId
import io, csv
from .config import settings
from .db import db, init_db, close_db, neo_driver
from .security import hash_password, verify_password, create_token, current_user, admin_user
from .schemas import UserCreate, AlertUpdate, FeedbackIn, IngestText
from .ingest import process_record, parse_csv, parse_json, load_demo
from .sources import fetch_nvd, fetch_otx
from .graph import get_graph

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if db.users.count_documents({}) == 0:
        db.users.insert_one({"email": settings.admin_email.lower(), "password_hash": hash_password(settings.admin_password), "role": "admin", "active": True, "created_at": datetime.now(timezone.utc).isoformat()})
    yield
    close_db()

app = FastAPI(title="AI-Powered CTI Correlation Platform", version="1.0.0", lifespan=lifespan)
origins = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["GET","POST","PATCH"], allow_headers=["Authorization","Content-Type"])

def clean(doc):
    if not doc: return doc
    doc = dict(doc); doc.pop("_id", None); return doc

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "cti-api"}

@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = db.users.find_one({"email": form.username.lower(), "active": True})
    if not user or not verify_password(form.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return {"access_token": create_token(user), "token_type": "bearer", "user": {"email": user["email"], "role": user["role"]}}

@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return user

@app.post("/api/users", status_code=201)
def create_user(payload: UserCreate, admin=Depends(admin_user)):
    if payload.role not in ("admin", "analyst"):
        raise HTTPException(400, "Role must be admin or analyst")
    email = payload.email.lower().strip()
    if db.users.find_one({"email": email}):
        raise HTTPException(409, "User already exists")
    db.users.insert_one({"email": email, "password_hash": hash_password(payload.password), "role": payload.role, "active": True, "created_at": datetime.now(timezone.utc).isoformat()})
    db.audit_logs.insert_one({"action": "create_user", "actor": admin["email"], "target": email, "created_at": datetime.now(timezone.utc).isoformat()})
    return {"message": "User created", "email": email, "role": payload.role}

@app.get("/api/dashboard")
def dashboard(user=Depends(current_user)):
    return {
        "indicators": db.indicators.count_documents({}),
        "cves": db.indicators.count_documents({"type":"cve"}),
        "alerts": db.alerts.count_documents({}),
        "critical_alerts": db.alerts.count_documents({"risk.severity":"critical", "status":{"$ne":"resolved"}}),
        "open_alerts": db.alerts.count_documents({"status":{"$ne":"resolved"}}),
        "sources": len(db.indicators.distinct("source_names")),
        "recent_alerts": [clean(x) for x in db.alerts.find({}, {"_id":0}).sort("created_at",-1).limit(5)]
    }

@app.get("/api/indicators")
def indicators(limit: int = 100, skip: int = 0, user=Depends(current_user)):
    limit = min(max(limit,1),250)
    items = [clean(x) for x in db.indicators.find({}, {"_id":0}).sort("created_at",-1).skip(skip).limit(limit)]
    return {"items": items, "total": db.indicators.count_documents({})}

@app.get("/api/alerts")
def alerts(status: str = "", user=Depends(current_user)):
    query = {"status": status} if status else {}
    return {"items": [clean(x) for x in db.alerts.find(query, {"_id":0}).sort("created_at",-1).limit(250)]}

@app.get("/api/alerts/{dedupe_key}")
def alert_detail(dedupe_key: str, user=Depends(current_user)):
    item = db.alerts.find_one({"dedupe_key": dedupe_key}, {"_id":0})
    if not item: raise HTTPException(404, "Alert not found")
    return item

@app.patch("/api/alerts/{dedupe_key}")
def update_alert(dedupe_key: str, payload: AlertUpdate, user=Depends(current_user)):
    if payload.status not in ("new","investigating","resolved","false_positive"):
        raise HTTPException(400, "Invalid status")
    result = db.alerts.update_one({"dedupe_key":dedupe_key},{"$set":{"status":payload.status,"updated_at":datetime.now(timezone.utc).isoformat(),"updated_by":user["email"]}})
    if not result.matched_count: raise HTTPException(404,"Alert not found")
    if payload.note:
        db.investigation_notes.insert_one({"dedupe_key":dedupe_key,"author":user["email"],"note":payload.note[:4000],"created_at":datetime.now(timezone.utc).isoformat()})
    db.audit_logs.insert_one({"action":"update_alert","actor":user["email"],"target":dedupe_key,"status":payload.status,"created_at":datetime.now(timezone.utc).isoformat()})
    return {"message":"Alert updated"}

@app.post("/api/alerts/{dedupe_key}/feedback")
def feedback(dedupe_key: str, payload: FeedbackIn, user=Depends(current_user)):
    if payload.verdict not in ("true_positive","false_positive","needs_review"):
        raise HTTPException(400,"Invalid verdict")
    if not db.alerts.find_one({"dedupe_key":dedupe_key}): raise HTTPException(404,"Alert not found")
    db.analyst_feedback.insert_one({"dedupe_key":dedupe_key,"verdict":payload.verdict,"comment":payload.comment[:2000],"analyst":user["email"],"created_at":datetime.now(timezone.utc).isoformat()})
    db.audit_logs.insert_one({"action":"alert_feedback","actor":user["email"],"target":dedupe_key,"created_at":datetime.now(timezone.utc).isoformat()})
    return {"message":"Feedback saved"}

@app.post("/api/ingest/text")
def ingest_text(payload: IngestText, user=Depends(current_user)):
    result = process_record(payload.text, payload.source[:100], payload.title[:200])
    return {"message":"Record processed","result":result}

@app.post("/api/ingest/upload")
async def upload(file: UploadFile = File(...), user=Depends(current_user)):
    max_bytes = settings.max_upload_mb * 1024 * 1024
    raw = await file.read(max_bytes + 1)
    if len(raw) > max_bytes: raise HTTPException(413, "File too large")
    name = (file.filename or "").lower()
    try:
        if name.endswith(".csv"):
            records = parse_csv(raw)
        elif name.endswith(".json"):
            records = parse_json(raw)
        else:
            raise HTTPException(415, "Only CSV and JSON files are supported")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Could not parse file. Check CSV/JSON format.")
    if not records: raise HTTPException(400, "No usable records found")
    total = 0
    for row in records[:500]:
        total += process_record(row["text"], "manual-upload", row["title"])["extracted"]
    return {"message":"Upload processed","records":min(len(records),500),"indicators_processed":total}

@app.post("/api/demo/load")
def demo(user=Depends(current_user)):
    return load_demo()

@app.post("/api/sources/nvd/sync")
async def nvd_sync(user=Depends(current_user)):
    try:
        records = await fetch_nvd()
        count = 0
        for record in records:
            doc = {**record, "type":"cve", "value":record["cve_id"], "source_names":["NVD"], "created_at":datetime.now(timezone.utc).isoformat(), "demo":False}
            db.indicators.update_one({"value":record["cve_id"]},{"$set":doc},upsert=True)
            count += 1
        db.audit_logs.insert_one({"action":"nvd_sync","actor":user["email"],"count":count,"created_at":datetime.now(timezone.utc).isoformat()})
        return {"message":"NVD synchronization completed","count":count}
    except Exception as exc:
        raise HTTPException(502, f"NVD synchronization failed: {type(exc).__name__}. Check connectivity and API limits.")

@app.post("/api/sources/otx/sync")
async def otx_sync(user=Depends(current_user)):
    try:
        payload = await fetch_otx()
        pulses = payload.get("results", [])
        count = 0
        for pulse in pulses:
            for indicator in pulse.get("indicators", []):
                value = indicator.get("indicator")
                if value:
                    process_record(str(value), "AlienVault OTX", pulse.get("name","OTX pulse"))
                    count += 1
        return {"message":"OTX synchronization completed","count":count}
    except ValueError as exc:
        raise HTTPException(400,str(exc))
    except Exception as exc:
        raise HTTPException(502, f"OTX synchronization failed: {type(exc).__name__}. Check configuration and connectivity.")

@app.get("/api/graph")
def graph(user=Depends(current_user)):
    try:
        return get_graph()
    except Exception:
        raise HTTPException(503,"Graph database is temporarily unavailable")

@app.get("/api/reports/indicators.csv")
def export_indicators(user=Depends(current_user)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type","value","sources","demo","created_at"])
    for item in db.indicators.find({},{"_id":0}):
        row = [item.get("type"), item.get("value"), ";".join(item.get("source_names",[])), item.get("demo",False), item.get("created_at")]
        writer.writerow([("'" + str(v)) if isinstance(v, str) and v.startswith(("=", "+", "-", "@", "\t", "\r")) else v for v in row])
    output.seek(0)
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition":"attachment; filename=indicators.csv"})

@app.get("/api/audit")
def audit(user=Depends(admin_user)):
    return {"items":[clean(x) for x in db.audit_logs.find({},{"_id":0}).sort("created_at",-1).limit(200)]}
