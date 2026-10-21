import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import os

DB_PATH = os.path.join("db", "cybershield.db")

FEATURE_COLUMNS = [
    "failed_auth_count_5m",
    "failed_auth_count_10m",
    "connection_count_5m",
    "unique_ports_10m",
    "unique_dest_ips_10m",
    "bytes_sent",
]

# ---- Rule thresholds (Sigma-style deterministic rules) ----
BRUTE_FORCE_THRESHOLD = 20     # failed_auth_count_5m se zyada -> brute force
PORT_SCAN_THRESHOLD = 15       # unique_ports_10m se zyada -> port scan


def load_features():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM features", conn)
    conn.close()
    return df


def run_isolation_forest(df):
    """
    Isolation Forest unsupervised anomaly detection.
    contamination=0.1 ka matlab hai model expect karta hai ke ~10% data
    anomalous ho sakta hai - ye ek starting assumption hai, tune ho sakta hai.
    """
    X = df[FEATURE_COLUMNS].fillna(0)

    model = IsolationForest(
        n_estimators=150,
        contamination=0.10,
        random_state=42,
    )
    model.fit(X)

    # decision_function: zyada negative = zyada anomalous
    raw_scores = model.decision_function(X)

    # Normalize to 0.00 - 1.00 range, jahan 1.00 = sabse zyada anomalous
    min_s, max_s = raw_scores.min(), raw_scores.max()
    anomaly_score = 1 - (raw_scores - min_s) / (max_s - min_s + 1e-9)

    df["ml_anomaly_score"] = anomaly_score.round(4)
    return df


def apply_rules(df):
    """Deterministic rules - binary match, high precision, koi training nahi chahiye."""
    df["rule_match"] = False
    df["rule_name"] = None

    brute_force_mask = df["failed_auth_count_5m"] > BRUTE_FORCE_THRESHOLD
    df.loc[brute_force_mask, "rule_match"] = True
    df.loc[brute_force_mask, "rule_name"] = "BRUTE_FORCE_AUTH_FAILURE"

    port_scan_mask = df["unique_ports_10m"] > PORT_SCAN_THRESHOLD
    df.loc[port_scan_mask, "rule_match"] = True
    df.loc[port_scan_mask, "rule_name"] = "PORT_SCAN_DETECTED"

    return df


def save_detections(df):
    conn = sqlite3.connect(DB_PATH)
    cols = [
        "event_id", "timestamp", "event_type", "source_ip", "destination_ip",
        "asset_id", "asset_criticality",
        "ml_anomaly_score", "rule_match", "rule_name",
    ] + FEATURE_COLUMNS
    df[cols].to_sql("detections", conn, if_exists="replace", index=False)
    conn.close()


def main():
    if not os.path.exists(DB_PATH):
        print("Database nahi mili. Pehle Day 1 aur Day 2 chalao.")
        return

    print("Features load ho rahe hain...")
    df = load_features()
    print(f"Total rows: {len(df)}")

    print("Isolation Forest chal raha hai...")
    df = run_isolation_forest(df)

    print("Deterministic rules apply ho rahi hain...")
    df = apply_rules(df)

    save_detections(df)
    print(f"'detections' table save ho gayi: {len(df)} rows\n")

    # ---- Summary ----
    high_anomaly = df[df["ml_anomaly_score"] >= 0.75]
    rule_hits = df[df["rule_match"] == True]

    print(f"High ML anomaly score (>= 0.75): {len(high_anomaly)} events")
    print(f"Rule matches: {len(rule_hits)} events")

    print("\nTop 5 highest anomaly scores:")
    top5 = df.sort_values("ml_anomaly_score", ascending=False).head(5)
    for _, row in top5.iterrows():
        print(f"  source_ip={row['source_ip']:<16} "
              f"score={row['ml_anomaly_score']:.2f}  "
              f"rule={row['rule_name']}")

    print("\nAb Day 4 (Correlation) shuru kar sakte ho.")


if __name__ == "__main__":
    main()
