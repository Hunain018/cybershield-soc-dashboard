import sqlite3
import pandas as pd
import uuid
import os
from datetime import timedelta

DB_PATH = os.path.join("db", "cybershield.db")

ML_SCORE_THRESHOLD = 0.75      # is se upar ML score = "interesting"
GAP_MINUTES = 30               # itne minute ka gap = naya incident


def load_flagged_detections():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM detections", conn)
    conn.close()

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Sirf wo events lo jo rule match karte hain YA high ML score rakhte hain
    interesting = df[
        (df["rule_match"] == 1) | (df["ml_anomaly_score"] >= ML_SCORE_THRESHOLD)
    ].copy()

    return interesting


def group_into_incidents(df):
    """
    Har entity (source_ip) ke andar, time-gap ke hisab se events ko
    clusters mein todta hai. Ye simple version hai temporal correlation ka.
    """
    df = df.sort_values(["source_ip", "timestamp"]).reset_index(drop=True)

    incidents = []
    incident_events_map = []   # (incident_id, event_id) pairs

    for source_ip, group in df.groupby("source_ip"):
        group = group.sort_values("timestamp").reset_index(drop=True)

        cluster_start_idx = 0
        for i in range(1, len(group) + 1):
            is_last = i == len(group)
            gap_too_big = (
                not is_last and
                (group.loc[i, "timestamp"] - group.loc[i - 1, "timestamp"])
                > timedelta(minutes=GAP_MINUTES)
            )

            if is_last or gap_too_big:
                cluster = group.iloc[cluster_start_idx:i]
                incident_id = f"inc-{uuid.uuid4().hex[:10]}"

                # Dedup: rule names ikattha karo, asset criticality le lo max wali
                rule_names = cluster["rule_name"].dropna().unique().tolist()
                asset_ids = cluster["asset_id"].dropna().unique().tolist()
                max_ml_score = cluster["ml_anomaly_score"].max()

                incidents.append({
                    "incident_id": incident_id,
                    "created_at": cluster["timestamp"].min().isoformat(),
                    "entity_key": source_ip,
                    "event_count": len(cluster),
                    "first_seen": cluster["timestamp"].min().isoformat(),
                    "last_seen": cluster["timestamp"].max().isoformat(),
                    "rule_names": ",".join(rule_names) if rule_names else None,
                    "target_assets": ",".join(asset_ids) if asset_ids else None,
                    "max_ml_anomaly_score": round(max_ml_score, 4),
                    "risk_score": None,      # Day 5 mein fill hoga
                    "risk_band": None,       # Day 5 mein fill hoga
                    "status": "new",
                    "report_json": None,     # Day 7 mein fill hoga
                })

                for eid in cluster["event_id"]:
                    incident_events_map.append((incident_id, eid))

                cluster_start_idx = i

    return pd.DataFrame(incidents), incident_events_map


def save_incidents(incidents_df, incident_events_map):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # incidents table ko extend karte hain extra columns ke liye (agar nahi hain)
    existing_cols = [r[1] for r in cur.execute("PRAGMA table_info(incidents)").fetchall()]
    for col in ["first_seen", "last_seen", "rule_names", "target_assets", "max_ml_anomaly_score"]:
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE incidents ADD COLUMN {col} TEXT")

    # incident_events junction table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incident_events (
            incident_id TEXT,
            event_id TEXT,
            PRIMARY KEY (incident_id, event_id)
        )
    """)

    conn.commit()

    incidents_df.to_sql("incidents", conn, if_exists="replace", index=False)

    cur.executemany(
        "INSERT OR REPLACE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
        incident_events_map
    )
    conn.commit()
    conn.close()


def main():
    if not os.path.exists(DB_PATH):
        print("Database nahi mili. Pehle Day 1-3 chalao.")
        return

    print("Flagged detections load ho rahi hain...")
    flagged = load_flagged_detections()
    print(f"Interesting events (rule match ya high anomaly): {len(flagged)}")

    print("Correlation chal raha hai (grouping into incidents)...")
    incidents_df, incident_events_map = group_into_incidents(flagged)

    save_incidents(incidents_df, incident_events_map)

    print(f"\nTotal incidents banaye gaye: {len(incidents_df)}")
    print("\nIncident summary:")
    for _, row in incidents_df.iterrows():
        print(f"  {row['incident_id']}  "
              f"entity={row['entity_key']:<16} "
              f"events={row['event_count']:<4} "
              f"rules=[{row['rule_names']}]  "
              f"max_score={row['max_ml_anomaly_score']}")

    print(f"\nCompression: {len(flagged)} raw alerts -> {len(incidents_df)} incidents")
    print("\nAb Day 5 (Risk Engine) shuru kar sakte ho.")


if __name__ == "__main__":
    main()
