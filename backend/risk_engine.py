import sqlite3
import pandas as pd
import os

DB_PATH = os.path.join("db", "cybershield.db")

# ---- Weights (available signals ke beech) ----
W_ML = 0.55
W_ASSET = 0.45

ASSET_CRITICALITY_MAP = {
    "LOW": 0.25,
    "MEDIUM": 0.50,
    "HIGH": 0.75,
    "CRITICAL": 1.00,
}

# ---- Rule override ----
RULE_MATCH_FLOOR = 0.90   # agar deterministic rule match hai, score kam se kam itna hoga


def load_incidents():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM incidents", conn)
    conn.close()
    return df


def resolve_asset_criticality(entity_key, conn):
    """Incident ke target_assets se sabse zyada critical asset ki criticality nikalo."""
    query = """
        SELECT DISTINCT asset_criticality FROM detections
        WHERE source_ip = ?
    """
    rows = conn.execute(query, (entity_key,)).fetchall()
    levels = [r[0] for r in rows if r[0]]
    if not levels:
        return None
    # sabse zyada critical wala lo
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    levels_sorted = sorted(levels, key=lambda x: order.index(x) if x in order else 0)
    return levels_sorted[-1]


def compute_risk(row, asset_crit):
    """
    Re-normalized weighted score: sirf un signals par average nikalta hai
    jo actually available hain, taake missing signal score ko artificially
    neeche na khींche.
    """
    available_weight = 0.0
    weighted_sum = 0.0

    ml_score = row["max_ml_anomaly_score"]
    if pd.notna(ml_score):
        weighted_sum += W_ML * float(ml_score)
        available_weight += W_ML

    asset_score = ASSET_CRITICALITY_MAP.get(asset_crit) if asset_crit else None
    if asset_score is not None:
        weighted_sum += W_ASSET * asset_score
        available_weight += W_ASSET

    if available_weight == 0:
        risk_raw = 0.0
    else:
        risk_raw = weighted_sum / available_weight

    coverage = available_weight  # 0.00 - 1.00, kitna weight "covered" hua

    # Rule-match override: deterministic detection hamesha floor set karta hai
    rule_matched = pd.notna(row["rule_names"]) and row["rule_names"] not in (None, "", "nan")
    if rule_matched:
        risk_final = max(risk_raw, RULE_MATCH_FLOOR)
    else:
        risk_final = risk_raw

    risk_final = round(min(max(risk_final, 0.0), 1.0), 4)

    # Confidence label - kitne signals mile
    if coverage >= 0.80:
        confidence = "HIGH"
    elif coverage >= 0.50:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return risk_final, coverage, confidence, rule_matched

def decision_band(risk_score, rule_matched, event_count):
    """
    Decision bands.

    Zaroori guardrail: agar koi deterministic rule match nahi hui AND
    sirf ek hi event hai (koi corroboration nahi), to band CRITICAL ya
    HIGH nahi ban sakta - chahe ML score kitna bhi high ho. Ek akela,
    غير-corroborated ML signal ek critical asset ko touch kar sakta hai
    bilkul benign reason se; isko turant CRITICAL maan lena hi wo alert
    fatigue hai jo ye poora platform khatam karna chahta hai.
    """
    corroborated = rule_matched or event_count >= 3

    if not corroborated:
        return "MEDIUM" if risk_score >= 0.70 else "LOW"

    if risk_score >= 0.85:
        return "CRITICAL"
    elif risk_score >= 0.70:
        return "HIGH"
    elif risk_score >= 0.40:
        return "MEDIUM"
    else:
        return "LOW"


def main():
    if not os.path.exists(DB_PATH):
        print("Database nahi mili. Pehle Day 1-4 chalao.")
        return

    conn = sqlite3.connect(DB_PATH)
    df = load_incidents()

    print(f"Total incidents: {len(df)}")
    print("Risk score calculate ho raha hai...\n")

    results = []
    for _, row in df.iterrows():
        asset_crit = resolve_asset_criticality(row["entity_key"], conn)
        risk_score, coverage, confidence, rule_matched = compute_risk(row, asset_crit)
        band = decision_band(risk_score, rule_matched, row["event_count"])

        results.append({
            "incident_id": row["incident_id"],
            "risk_score": risk_score,
            "coverage": round(coverage, 2),
            "confidence": confidence,
            "risk_band": band,
            "asset_criticality": asset_crit,
        })

    results_df = pd.DataFrame(results)

    # incidents table update karo
    cur = conn.cursor()
    existing_cols = [r[1] for r in cur.execute("PRAGMA table_info(incidents)").fetchall()]
    for col in ["coverage", "confidence"]:
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE incidents ADD COLUMN {col} TEXT")
    conn.commit()

    for _, r in results_df.iterrows():
        cur.execute("""
            UPDATE incidents
            SET risk_score = ?, risk_band = ?, coverage = ?, confidence = ?
            WHERE incident_id = ?
        """, (r["risk_score"], r["risk_band"], r["coverage"], r["confidence"], r["incident_id"]))
    conn.commit()
    conn.close()

    # ---- Print summary ----
    # df mein purani (khaali) risk_score/risk_band columns hain, unhe hata kar
    # results_df wali fresh values use karte hain
    df_clean = df.drop(
        columns=["risk_score", "risk_band", "coverage", "confidence", "asset_criticality"],
        errors="ignore"
    )
    merged = df_clean.merge(results_df, on="incident_id")
    merged = merged.sort_values("risk_score", ascending=False)

    print("Incident Risk Summary:")
    print("-" * 100)
    for _, r in merged.iterrows():
        print(f"  {r['incident_id']}  "
              f"entity={r['entity_key']:<16} "
              f"score={r['risk_score']:.2f}  "
              f"band={r['risk_band']:<9} "
              f"confidence={r['confidence']:<6} "
              f"asset_crit={r['asset_criticality']}")

    print("\nBand distribution:")
    print(merged["risk_band"].value_counts().to_string())

    print("\nAb Day 6 (Knowledge Base / Mini-RAG) shuru kar sakte ho.")


if __name__ == "__main__":
    main()
