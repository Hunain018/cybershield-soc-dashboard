import sqlite3
import os

DB_PATH = os.path.join("db", "cybershield.db")


def setup_database():
    os.makedirs("db", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Raw / normalized events table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,        -- 'authentication_failure', 'network_connection', etc.
            source_ip TEXT,
            destination_ip TEXT,
            destination_port INTEGER,
            user_principal TEXT,
            asset_id TEXT,
            asset_criticality TEXT,          -- LOW / MEDIUM / HIGH / CRITICAL
            bytes_sent INTEGER,
            raw_payload TEXT                 -- original JSON, for reference
        )
    """)

    # Incidents table (Day 4 mein use hoga)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            created_at TEXT,
            entity_key TEXT,                 -- e.g. source_ip or asset_id used for grouping
            event_count INTEGER,
            risk_score REAL,
            risk_band TEXT,                  -- LOW / MEDIUM / HIGH / CRITICAL
            status TEXT DEFAULT 'new',       -- new / investigating / approved / rejected
            report_json TEXT                 -- agent-generated investigation report
        )
    """)

    # Audit log table (Day 8 mein use hoga)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            incident_id TEXT,
            action TEXT,                     -- e.g. 'incident_created', 'approved', 'rejected'
            details TEXT
        )
    """)

    conn.commit()
    conn.close()
    print(f"Database ready at: {DB_PATH}")
    print("Tables created: events, incidents, audit_log")


if __name__ == "__main__":
    setup_database()
