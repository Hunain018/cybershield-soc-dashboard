from __future__ import annotations
import os, platform, re, sys, uuid
from datetime import datetime, timedelta, timezone
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
 
def ago_iso(minutes: int):
    # Seed/demo events ko alag-alag waqt par rakhne ke liye (timeline chart real timestamps se banta hai).
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).astimezone().isoformat(timespec="seconds")
 
# Clearly-labelled starter/demo data; replace with your real datastore/ingestion.
events: list[dict[str, Any]] = [
    {"id":"EVT-001","timestamp":ago_iso(24),"source":"10.0.0.45","event":"SSH authentication failed","severity":"HIGH","details":"Failed password for invalid user root","status":"Open"},
    {"id":"EVT-002","timestamp":ago_iso(17),"source":"192.168.1.23","event":"Network connection","severity":"INFO","details":"Connection established to 8.8.8.8:53","status":"Open"},
    {"id":"EVT-003","timestamp":ago_iso(9),"source":"172.16.5.12","event":"Suspicious process","severity":"MEDIUM","details":"/usr/bin/nmap detected","status":"Investigating"},
    {"id":"EVT-004","timestamp":ago_iso(3),"source":"172.16.5.20","event":"Malware indicator","severity":"CRITICAL","details":"Suspicious file indicator observed","status":"Open"},
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
    # Chart events ke asli timestamps se banta hai: pichhle 30 minute, 5-5 minute ke 6 buckets.
    # normal = INFO/LOW, suspicious = MEDIUM/HIGH, critical = CRITICAL
    bucket_min = 5
    n_buckets = 6
    now = datetime.now(timezone.utc)
    labels = [f"-{(n_buckets - 1 - i) * bucket_min}m" for i in range(n_buckets - 1)] + ["Now"]
    normal = [0] * n_buckets
    suspicious = [0] * n_buckets
    critical = [0] * n_buckets
    for e in events:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            age_min = (now - ts).total_seconds() / 60
        except Exception:
            continue
        if age_min < 0:
            age_min = 0
        idx = n_buckets - 1 - int(age_min // bucket_min)
        if idx < 0:
            continue  # 30 minute se purana event chart mein nahi aata
        sev = e.get("severity")
        if sev == "CRITICAL":
            critical[idx] += 1
        elif sev in ("MEDIUM", "HIGH"):
            suspicious[idx] += 1
        else:
            normal[idx] += 1
    return {"labels": labels, "normal": normal, "suspicious": suspicious, "critical": critical}
 
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
 
def _soc_snapshot() -> str:
    """Current incidents/events ka chhota text summary (LLM context aur offline jawab dono ke liye)."""
    open_inc = [i for i in incidents if i["status"] not in ("Resolved",)]
    lines = [f"Total events: {len(events)}; incidents: {len(incidents)} (open/active: {len(open_inc)})."]
    for i in incidents[:8]:
        lines.append(f"- {i['id']} | {i['severity']} | {i['status']} | {i['source_ip']} | {i['title']}")
    return "\n".join(lines)
 
SOC_SYSTEM_PROMPT = ("You are CyberShield AI's senior SOC analyst assistant. Answer concisely and practically. "
                     "Use the live SOC snapshot when relevant. Suggest actions but never claim to have executed them.")
 
def _groq_answer(question: str):
    """GROQ_API_KEY env var set ho to Groq (free tier) se jawab."""
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        return None
    import json as _json, urllib.request
    body = _json.dumps({
        "model": os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
        "temperature": 0.2,
        "max_tokens": 500,
        "messages": [
            {"role": "system", "content": SOC_SYSTEM_PROMPT + "\n\nSOC snapshot:\n" + _soc_snapshot()},
            {"role": "user", "content": question},
        ],
    }).encode()
    req = urllib.request.Request("https://api.groq.com/openai/v1/chat/completions", data=body, headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json", "User-Agent": "cybershield-ai/1.0"})
    with urllib.request.urlopen(req, timeout=8) as r:
        data = _json.loads(r.read())
    return (data["choices"][0]["message"]["content"] or "").strip() or None
 
def _hosted_llm_answer(question: str):
    """Hosted LLM: pehle Groq (free), phir optional Anthropic. Dono key ke baghair None dete hain."""
    try:
        ans = _groq_answer(question)
        if ans:
            return ans
    except Exception:
        pass
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    import json as _json, urllib.request
    body = _json.dumps({
        "model": os.environ.get("COPILOT_MODEL", "claude-sonnet-5-5"),
        "max_tokens": 600,
        "system": ("You are CyberShield AI's senior SOC analyst assistant. Answer concisely and practically. "
                   "Use the live SOC snapshot when relevant. Suggest actions but never claim to have executed them.\n\n"
                   "SOC snapshot:\n" + _soc_snapshot()),
        "messages": [{"role": "user", "content": question}],
    }).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        data = _json.loads(r.read())
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip() or None
 
KNOWLEDGE = [
    (("hi", "hii", "hello", "hey", "salam", "assalam"),
     "Hello! I'm the CyberShield analyst copilot. I can summarize current incidents, explain threat types, and suggest investigation and containment steps."),
    (("severity", "risk type", "high risk", "risk level", "critical vs", "priorit"),
     "Severity levels used in this console:\n"
     "- CRITICAL: active compromise indicators (malware, ransomware, privilege escalation). Respond immediately.\n"
     "- HIGH: likely attack activity (SSH brute force, repeated failed logins, unauthorized access). Investigate now.\n"
     "- MEDIUM: suspicious tooling or scanning (nmap, port scans). Verify within the shift.\n"
     "- LOW / INFO: normal or informational activity. Review in bulk."),
    (("brute", "ssh", "failed password", "login", "credential"),
     "SSH brute force: many failed logins from one or more IPs.\nInvestigate: check for any successful login from the same IP, review the targeted accounts, and look for lockouts.\n"
     "Contain (after approval): block the source IP at the firewall, enforce key-based auth or MFA, and rate-limit SSH. Maps to MITRE T1110 (Brute Force)."),
    (("scan", "nmap", "port"),
     "Port/network scanning (e.g. nmap) is usually reconnaissance.\nInvestigate: identify the scanning host, which ports/hosts were probed, and whether it is an authorized scanner.\n"
     "Contain: block or isolate the source if unauthorized, and review exposed services. Often precedes exploitation (MITRE T1046)."),
    (("malware", "ransom", "virus", "file indicator"),
     "Malware indicator: treat as CRITICAL.\nInvestigate: isolate the host from the network, identify the file hash and parent process, and check for lateral movement.\n"
     "Contain: isolate the endpoint, preserve evidence (memory/disk), reset exposed credentials, and scan related hosts."),
    (("block", "firewall", "contain", "remediat", "mitigat", "isolate"),
     "Containment options (always dry-run and approved by a Tier-3 lead in this console):\n"
     "- Block the source IP at the perimeter firewall.\n- Isolate the affected host.\n- Disable or reset compromised accounts.\n"
     "Use the Response center to submit the action for authorized review."),
    (("mitre", "att&ck", "attack", "technique", "tactic"),
     "Relevant MITRE ATT&CK mappings: T1110 Brute Force (credential access), T1078 Valid Accounts (initial access), "
     "T1190 Exploit Public-Facing Application (initial access), T1046 Network Service Discovery (scanning). See the Threat intelligence page."),
]
 
def _offline_answer(question: str) -> str:
    ql = question.lower()
    words = set(re.findall(r"[a-z0-9&]+", ql))
    if any(w.startswith(("summar", "incident", "alert", "queue", "overview", "highest", "latest")) for w in words) or {"status", "current", "top"} & words:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        active = sorted([i for i in incidents if i["status"] != "Resolved"], key=lambda i: order.get(i["severity"], 9))
        if not active:
            return "There are no unresolved incidents in the queue right now."
        top = active[0]
        return (f"{len(active)} unresolved incident(s). Highest priority: {top['id']} ({top['severity']}) - {top['title']} from {top['source_ip']}, status {top['status']}.\n\n"
                "Current queue:\n" + "\n".join(f"- {i['id']} | {i['severity']} | {i['status']} | {i['source_ip']} | {i['title']}" for i in active[:6]) +
                f"\n\nSuggested next step for {top['id']}: correlate {top['source_ip']} with recent authentication and endpoint events, then submit a dry-run containment action in the Response center.")
    for keys, text in KNOWLEDGE:
        if any((k in words) if " " not in k and len(k) <= 3 else (k in ql) for k in keys):
            return text
    return ("I can help with: summarizing the incident queue, explaining severity levels, investigating brute force, scanning or malware activity, "
            "suggesting containment steps, and MITRE ATT&CK mapping. Try: \"Summarize the highest-risk incident\" or \"Explain high risk types\".")
 
@app.post("/api/v1/copilot-chat")
def copilot_chat(payload: ChatPayload):
    q=payload.question.strip()
    answer=None
    if copilot:
        try:
            answer=copilot.chat(question=q,context=payload.context+"\n"+_soc_snapshot())
        except Exception:
            answer=None
    if not answer:
        try:
            answer=_hosted_llm_answer(q)
        except Exception:
            answer=None
    if not answer:
        answer=_offline_answer(q)
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
