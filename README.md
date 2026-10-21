# CyberShield AI — FastAPI + HTML/CSS/JavaScript

A responsive web frontend replacing the Streamlit UI. Charts are rendered with Chart.js and are populated from FastAPI endpoints. The dashboard calls the API for metrics, events, incidents, audit records, log ingestion, copilot chat and response dry-runs.

## Project layout

```text
cybershield_web/
├── backend/
│   └── main.py
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js
└── requirements.txt
```

## Run locally

1. Use Python 3.10+ and create/activate a virtual environment.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
3. Copy your existing project modules into `backend/` if you want to use them:
   `dual_agent_pipeline.py`, `audit.py`, `agent.py`, `rag_engine.py`, plus any modules/assets they import. The app starts with labelled demo fallbacks if these optional modules cannot initialize.
4. From the `cybershield_web` folder run:

   ```bash
   cd backend
   uvicorn main:app --reload
   ```
5. Open http://127.0.0.1:8000

## Demo credentials

- Username: `tier3_lead`
- Password: `adminpassword`
- Analyst: `tier1_analyst` / `password123`

These credentials are for local demonstration only. Replace the in-memory authentication with hashed passwords, secure sessions/JWT, rate limiting and environment-managed secrets before deployment.

## What's wired up

- Login through `/api/v1/login`
- Metrics, event timeline and severity distribution charts
- Log ingestion and severity-based demo incident creation
- Incident status updates
- Copilot endpoint (uses your existing agent when it initializes; labelled fallback otherwise)
- Audit log viewer
- CSV exports
- Interactive SVG relationship graph
- Response Center with RBAC and a safe dry-run response only
- Health endpoint at `/api/v1/health`

## Important integration notes

- Demo events/incidents/audit records are stored in memory and reset when the server restarts. Use a database for durable data and concurrent production workloads.
- The frontend uses Chart.js from jsDelivr and Google Fonts. For offline use, vendor these assets locally.
- The RAG/MITRE panel is a starter reference view, not a live MITRE data feed. The backend attempts to initialize your existing RAG module when present.
- Remediation intentionally never runs shell commands. Add a carefully reviewed, isolated action service and approval controls only after threat modelling and testing.
- Do not expose the demo credentials or this development server to the public internet.
