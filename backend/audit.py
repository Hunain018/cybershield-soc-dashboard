import sqlite3
import json
import os
from datetime import datetime

class AuditLogger:
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Set path relative to the current file directory
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_path = os.path.join(base_dir, "audit_logs.db")
        else:
            self.db_path = db_path
            
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                threat_vector TEXT,
                severity TEXT,
                policy_passed BOOLEAN,
                triage_json TEXT,
                remediation_text TEXT,
                policy_json TEXT
            )
        """)
        conn.commit()
        conn.close()

    def log_incident(self, pipeline_result: dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        triage = pipeline_result.get("triage", {})
        policy = pipeline_result.get("policy", {})
        
        cursor.execute("""
            INSERT INTO audit_records 
            (timestamp, threat_vector, severity, policy_passed, triage_json, remediation_text, policy_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            triage.get("threat_vector", "Unknown"),
            triage.get("severity", "UNKNOWN"),
            policy.get("policy_passed", False),
            json.dumps(triage),
            pipeline_result.get("remediation", ""),
            json.dumps(policy)
        ))
        
        conn.commit()
        record_id = cursor.lastrowid
        conn.close()
        return record_id

    def get_recent_logs(self, limit: int = 10):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, threat_vector, severity, policy_passed FROM audit_records ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return rows