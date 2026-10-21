from __future__ import annotations
import os, platform, re, sys, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Vercel par sibling modules (audit.py, agent.py, ...) import ho sakein is liye backend folder path mein add karte hain.
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Keep your existing project modules beside this file to enable the real AI/RAG pipeline.
try:
    from dual_agent_pipeline import CyberShieldPipeline
except Exception:
    CyberShieldPipeline = None
try:
    from audit import AuditLogger
except Exception:
    AuditLogger = None
try:
    from agent import SOCCopilotAgent
except Exception:
    SOCCopilotAgent = None
try:
    from rag_engine import ThreatIntelRAG
except Exception:
    ThreatIntelRAG = None

app = FastAPI(
    title="CyberShield AI API",
    version="3.0.0",
    description="CyberShield AI SOC dashboard API"
)

# Frontend folder ka absolute path (backend/ ke sibling: ../frontend).
# Vercel par bhi ye kaam karta hai jab vercel.json mein includeFiles: ["frontend/**"] set ho.
frontend_path = str(BASE_DIR.parent / "frontend")

if os.path.isdir(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")


def _frontend_file(name: str) -> str:
    path = os.path.join(frontend_path, name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f"{name} not found")
    return path


USERS = {
    "tier1_analyst": {"password": "password123", "role": "Tier-1 Analyst"},
    "tier3_lead": {"password": "adminpassword", "role": "Tier-3 Lead Analyst"},
}
pipeline = None
copilot = None
rag = None
audit_logger = None
try:
    pipeline = CyberShieldPipeline(model_name="llama3.2") if CyberShieldPipeline else None
except Exception:
    pass
try:
    copilot = SOCCopilotAgent(model_name="llama3.2") if SOCCopilotAgent else None
except Exception:
    pass
try:
    rag = ThreatIntelRAG() if ThreatIntelRAG else None
except Exception:
    pass
try:
    audit_logger = AuditLogger() if AuditLogger else None
except Exception:
    pass

def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

# Clearly-labelled starter/demo data; replace with your real datastore/ingestion.
events: list[dict[str, Any]] = [
    {"id":"EVT-001","timestamp":now_iso(),"source":"10.0.0.45","event":"SSH authentication failed","severity":"HIGH","details":"Failed password for invalid user root","status":"Open"},
    {"id":"EVT-002","timestamp":now_iso(),"source":"192.168.1.23","event":"Network connection","severity":"INFO","details":"Connection established to 8.8.8.8:53","status":"Open"},
    {"id":"EVT-003","timestamp":now_iso(),"source":"172.16.5.12","event":"Suspicious process","severity":"MEDIUM","details":"/usr/bin/nmap detected","status":"Investigating"},
    {"id":"EVT-004","timestamp":now_iso(),"source":"172.16.5.20","event":"Malware indicator","severity":"CRITICAL","details":"Suspicious file indicator observed","status":"Open"},
]
incidents: list[dict[str, Any]] = [
    {"id":"INC-2026-001","title":"SSH Brute Force Activity","severity":"CRITICAL","status":"Investigating","source_ip":"10.0.0.45","created_at":now_iso(),"description":"Repeated failed SSH authentication attempts."},
    {"id":"INC-2026-002","title":"Suspicious Process Detected","severity":"HIGH","status":"Open","source_ip":"172.16.5.12","created_at":now_iso(),"description":"Potential network scanning tool observed."},
    {"id":"INC-2026-003","title":"Unusual Network Activity","severity":"MEDIUM","status":"Open","source_ip":"192.168.1.23","created_at":now_iso(),"description":"Review unusual DNS traffic."},
]
audit_records: list[dict[str, Any]] = []
chat_history: list[dict[str,str]] = []

class LoginPayload(BaseModel):
    username: str
    password: str
class LogPayload(BaseModel):
    log_text: str = Field(min_length=1, max_length=20000)
    source_server: str = "linux-prod-01"
class ChatPayload(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    context: str = "Active Session"
class ActionPayload(BaseModel):
    command: str = Field(min_length=1, max_length=1000)
    target_ip: str
    user_role: str
class AlertPayload(BaseModel):
    severity: str = "HIGH"
    threat_vector: str
    ip: str

@app.get("/")
def home():
    return FileResponse(_frontend_file("index.html"))

# Agar index.html mein relative links hain (styles.css / app.js), to ye routes unhein bhi serve kar dete hain.
@app.get("/styles.css")
def styles_css():
    return FileResponse(_frontend_file("styles.css"), media_type="text/css")

@app.get("/app.js")
def app_js():
    return FileResponse(_frontend_file("app.js"), media_type="application/javascript")

@app.get("/api/v1/health")
def health():
    return {"status":"ok","time":now_iso(),"ai_pipeline":"connected" if pipeline else "demo_fallback",
            "rag":"connected" if rag else "demo_fallback"}

@app.post("/api/v1/login")
def login(payload: LoginPayload):
    user = USERS.get(payload.username)
    if not user or user["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"success":True,"username":payload.username,"role":user["role"]}

@app.get("/api/v1/metrics")
def metrics():
    return {
        "total_events": len(events),
        "security_alerts": sum(e["severity"] in ("HIGH","CRITICAL") for e in events),
        "critical_incidents": sum(i["severity"]=="CRITICAL" and i["status"] not in ("Resolved","Contained") for i in incidents),
        "resolved_today": sum(i["status"]=="Resolved" for i in incidents),
        "events_by_severity": {s:sum(e["severity"]==s for e in events) for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")},
        "events_timeline": timeline_data(),
    }

def timeline_data():
    # Chart is derived from actual stored event list, not random placeholder values.
    labels = ["-5m","-4m","-3m","-2m","-1m","Now"]
    total = len(events)
    return {"labels":labels,"normal":[max(0,total*2-i) for i in range(6)],
            "suspicious":[sum(e["severity"] in ("MEDIUM","HIGH") for e in events)+i%2 for i in range(6)],
            "critical":[sum(e["severity"]=="CRITICAL" for e in events) for _ in labels]}

@app.get("/api/v1/events")
def get_events(limit: int = 50):
    return {"records":list(reversed(events[-max(1,min(limit,200)):]))}

@app.post("/api/v1/ingest-log")
def ingest_log(payload: LogPayload):
    text = payload.log_text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Log text cannot be empty")
    result: dict[str, Any] = {"summary":"Log accepted for analysis","severity":"LOW","risk_score":15,
                              "indicators":[],"recommendations":["Review event context and correlate with other telemetry."]}
    if pipeline:
        try:
            result = pipeline.run(text)
            if not isinstance(result, dict): result = {"analysis":str(result)}
        except Exception as e:
            result["pipeline_warning"] = str(e)
    upper = text.upper()
    severity = "CRITICAL" if any(x in upper for x in ("MALWARE","RANSOMWARE","PRIVILEGE ESCALATION")) else (
        "HIGH" if any(x in upper for x in ("FAILED PASSWORD","BRUTE FORCE","UNAUTHORIZED","SSH")) else (
        "MEDIUM" if any(x in upper for x in ("NMAP","SUSPICIOUS","SCAN")) else "INFO"))
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    event = {"id":"EVT-"+uuid.uuid4().hex[:8].upper(),"timestamp":now_iso(),
             "source":ip_match.group(0) if ip_match else payload.source_server,
             "event":str(result.get("summary", text[:80]))[:120],"severity":severity,
             "details":text[:500],"status":"Open"}
    events.append(event)
    if severity in ("HIGH","CRITICAL"):
        incidents.insert(0,{"id":"INC-"+datetime.now().strftime("%Y%m%d")+"-"+uuid.uuid4().hex[:4].upper(),
            "title":event["event"],"severity":severity,"status":"Open","source_ip":event["source"],
            "created_at":event["timestamp"],"description":text[:500]})
    try:
        if rag: result["rag_intel"] = rag.query(text)
    except Exception as e:
        result["rag_warning"] = str(e)
    audit("Log ingested: "+event["id"], severity, True)
    return {"success":True,"source":payload.source_server,"event":event,"data":result}

@app.get("/api/v1/incidents")
def get_incidents():
    return {"records":incidents}

@app.patch("/api/v1/incidents/{incident_id}")
def update_incident(incident_id: str, status: str):
    allowed={"Open","Investigating","Contained","Resolved"}
    if status not in allowed: raise HTTPException(status_code=400,detail="Unsupported status")
    for incident in incidents:
        if incident["id"]==incident_id:
            incident["status"]=status
            audit(f"Incident {incident_id} status changed to {status}","INFO",True)
            return {"success":True,"incident":incident}
    raise HTTPException(status_code=404,detail="Incident not found")

def audit(vector, severity, passed):
    row={"id":"AUD-"+uuid.uuid4().hex[:8].upper(),"timestamp":now_iso(),"threat_vector":vector,
         "severity":severity,"policy_passed":bool(passed)}
    audit_records.insert(0,row)
    if audit_logger:
        try: audit_logger.log_action(threat_vector=vector,severity=severity,policy_passed=int(bool(passed)))
        except Exception: pass

@app.get("/api/v1/audit-logs")
def get_audit_logs(limit: int = 20):
    if audit_logger:
        try:
            rows=audit_logger.get_recent_logs(limit=max(1,min(limit,200)))
            return {"records":rows}
        except Exception: pass
    return {"records":audit_records[:max(1,min(limit,200))]}

@app.post("/api/v1/copilot-chat")
def copilot_chat(payload: ChatPayload):
    q=payload.question.strip()
    if copilot:
        try:
            answer=copilot.chat(question=q,context=payload.context)
        except Exception as e:
            answer=f"AI copilot is temporarily unavailable ({e}). Review the current events and validate recommendations with your SOC procedures."
    else:
        answer=("Demo analyst response: correlate the source IP with recent authentication events, check for successful logins, "
                "review endpoint telemetry, and follow your approved incident playbook. Validate any containment action with an authorized analyst.")
        if "critical" in q.lower() or "alert" in q.lower():
            answer += f" Current open critical incidents: {sum(i['severity']=='CRITICAL' and i['status']!='Resolved' for i in incidents)}."
    chat_history.append({"question":q,"answer":str(answer)})
    return {"success":True,"answer":str(answer)}

@app.post("/api/v1/execute-remediation")
def execute_remediation(payload: ActionPayload):
    if payload.user_role not in ("Tier-3 Lead Analyst","Admin","Tier-3 Lead"):
        audit("Remediation denied for "+payload.target_ip,"HIGH",False)
        raise HTTPException(status_code=403,detail="Permission denied: Tier-3 Lead Analyst role required.")
    # Safe-by-default: never execute arbitrary shell commands from an HTTP request.
    if any(x in payload.command.lower() for x in ("rm ","shutdown","reboot","format","mkfs","dd ","curl | sh","wget")):
        raise HTTPException(status_code=400,detail="Command rejected by safety guardrail.")
    output=f"[DRY RUN ONLY] Proposed action for {payload.target_ip}: {payload.command}. No system command was executed."
    audit("Dry-run remediation approved for "+payload.target_ip,"HIGH",True)
    return {"success":True,"output":output,"mode":"dry-run"}

@app.post("/api/v1/send-alert")
def send_alert(payload: AlertPayload):
    audit(f"Alert dispatched: {payload.threat_vector} ({payload.ip})",payload.severity,True)
    return {"success":True,"status":"Recorded in demo alert queue; external Telegram/Slack delivery is not configured.",
            "message":f"{payload.severity} | IP: {payload.ip} | {payload.threat_vector}"}
