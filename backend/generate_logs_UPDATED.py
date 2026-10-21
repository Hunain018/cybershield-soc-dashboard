import sqlite3
import random
import uuid
import json
import os
from datetime import datetime, timedelta

DB_PATH = os.path.join("db", "cybershield.db")

# ---------- Config ----------
NUM_NORMAL_EVENTS = 800
NUM_BRUTE_FORCE_EVENTS = 60      # ek brute-force burst
NUM_PORT_SCAN_EVENTS = 40        # ek port-scan burst

NORMAL_USERS = ["u_ali", "u_sara", "u_ahmed", "u_fatima", "u_bilal", "u_zara"]
NORMAL_ASSETS = [
    ("WORKSTATION-01", "LOW"),
    ("WORKSTATION-02", "LOW"),
    ("WEB-SRV-01", "MEDIUM"),
    ("AUTH-SRV-01", "HIGH"),
    ("FINANCE-DB-01", "CRITICAL"),
]
INTERNAL_IP_POOL = [f"10.0.{random.randint(1,5)}.{i}" for i in range(10, 60)]


def rand_time(base_time, spread_minutes=1440):
    """Base time ke around random timestamp, spread_minutes ke andar."""
    offset = random.randint(0, spread_minutes)
    return base_time + timedelta(minutes=offset)


def make_event(event_type, ts, source_ip, destination_ip, dest_port,
               user, asset_id, asset_crit, bytes_sent):
    event_id = f"evt-{uuid.uuid4().hex[:12]}"
    payload = {
        "event_id": event_id,
        "timestamp": ts.isoformat(),
        "event_type": event_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": dest_port,
        "user_principal": user,
        "asset_id": asset_id,
        "asset_criticality": asset_crit,
        "bytes_sent": bytes_sent,
    }
    return (
        event_id, ts.isoformat(), event_type, source_ip, destination_ip,
        dest_port, user, asset_id, asset_crit, bytes_sent,
        json.dumps(payload)
    )


def generate_normal_events(base_time):
    events = []
    for _ in range(NUM_NORMAL_EVENTS):
        ts = rand_time(base_time)
        asset_id, asset_crit = random.choice(NORMAL_ASSETS)
        event_type = random.choice(
            ["authentication_success", "network_connection", "file_access"]
        )
        events.append(make_event(
            event_type=event_type,
            ts=ts,
            source_ip=random.choice(INTERNAL_IP_POOL),
            destination_ip=random.choice(INTERNAL_IP_POOL),
            dest_port=random.choice([443, 22, 3389, 8080]),
            user=random.choice(NORMAL_USERS),
            asset_id=asset_id,
            asset_crit=asset_crit,
            bytes_sent=random.randint(200, 5000),
        ))
    return events


def generate_brute_force_burst(base_time):
    """Ek external IP se AUTH-SRV-01 par bohat sari failed logins - short time window mein."""
    events = []
    attacker_ip = "203.0.113.44"   # suspicious external IP
    burst_start = rand_time(base_time, spread_minutes=1440)

    for i in range(NUM_BRUTE_FORCE_EVENTS):
        ts = burst_start + timedelta(seconds=i * 5)   # har 5 second mein ek attempt
        events.append(make_event(
            event_type="authentication_failure",
            ts=ts,
            source_ip=attacker_ip,
            destination_ip="10.0.4.12",
            dest_port=443,
            user=random.choice(["admin", "root", "administrator", "u_ahmed"]),
            asset_id="AUTH-SRV-01",
            asset_crit="HIGH",
            bytes_sent=random.randint(50, 150),
        ))
    return events


def generate_port_scan_burst(base_time):
    """Ek external IP se FINANCE-DB-01 ke bohat se ports scan hote hain - short window mein."""
    events = []
    scanner_ip = "198.51.100.23"
    burst_start = rand_time(base_time, spread_minutes=1440)

    ports = random.sample(range(1, 65000), NUM_PORT_SCAN_EVENTS)
    for i, port in enumerate(ports):
        ts = burst_start + timedelta(seconds=i * 2)
        events.append(make_event(
            event_type="network_connection",
            ts=ts,
            source_ip=scanner_ip,
            destination_ip="10.0.5.20",
            dest_port=port,
            user=None,
            asset_id="FINANCE-DB-01",
            asset_crit="CRITICAL",
            bytes_sent=random.randint(40, 100),
        ))
    return events


def insert_events(events):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Purana data clear karte hain - taake dobara script chalane par
    # purane aur naye attack bursts mix ho kar galat incidents na banayen
    cur.execute("DELETE FROM events")
    cur.executemany("""
        INSERT OR REPLACE INTO events
        (event_id, timestamp, event_type, source_ip, destination_ip,
         destination_port, user_principal, asset_id, asset_criticality,
         bytes_sent, raw_payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, events)
    conn.commit()
    conn.close()


def main():
    if not os.path.exists(DB_PATH):
        print("Database nahi mili. Pehle 'python setup_db.py' chalao.")
        return

    base_time = datetime.now() - timedelta(days=1)

    normal = generate_normal_events(base_time)
    brute_force = generate_brute_force_burst(base_time)
    port_scan = generate_port_scan_burst(base_time)

    all_events = normal + brute_force + port_scan
    random.shuffle(all_events)   # real logs mein order mixed hota hai

    insert_events(all_events)

    print(f"Total events generated: {len(all_events)}")
    print(f"  - Normal events:       {len(normal)}")
    print(f"  - Brute-force burst:   {len(brute_force)}  (source: 203.0.113.44 -> AUTH-SRV-01)")
    print(f"  - Port-scan burst:     {len(port_scan)}  (source: 198.51.100.23 -> FINANCE-DB-01)")
    print("\nAb Day 2 (normalizer) shuru kar sakte ho.")


if __name__ == "__main__":
    main()
