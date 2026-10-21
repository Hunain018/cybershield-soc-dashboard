import sys
import time

STEPS = [
    ("setup_db", "Database Setup", "setup_database"),
    ("generate_logs", "Synthetic Log Generation", "main"),
    ("normalizer", "Normalization & Feature Engineering", "main"),
    ("detection", "Detection Engine (Isolation Forest + Rules)", "main"),
    ("correlation", "Correlation (Alerts -> Incidents)", "main"),
    ("risk_engine", "Risk Engine (Scoring + Bands)", "main"),
    ("agent", "Investigation Agent (LLM + Knowledge Base)", "main"),
]


def run_step(module_name, label, entry_fn):
    print("=" * 70)
    print(f"  STEP: {label}")
    print("=" * 70)
    start = time.time()
    try:
        module = __import__(module_name)
        getattr(module, entry_fn)()
    except Exception as e:
        print(f"\n[ERROR] '{module_name}' mein fail hua: {e}")
        print("Pipeline rok diya gaya. Upar wala error dekho aur fix karo.")
        sys.exit(1)
    elapsed = time.time() - start
    print(f"\n[OK] {label} complete ({elapsed:.1f}s)\n")


def main():
    skip_agent = "--skip-agent" in sys.argv

    print("\nCyberShield AI - Full Pipeline Run\n")

    for module_name, label, entry_fn in STEPS:
        if module_name == "agent" and skip_agent:
            print(f"[SKIP] {label} (--skip-agent flag diya gaya)\n")
            continue
        run_step(module_name, label, entry_fn)

    print("=" * 70)
    print("  PIPELINE COMPLETE")
    print("=" * 70)
    print("\nAb dashboard chalao:")
    print("    streamlit run app.py")
    print("\nDashboard mein incidents dekh sakte ho, reports review kar sakte ho,")
    print("aur Approve/Reject kar sakte ho (jo audit_log mein record hoga).")


if __name__ == "__main__":
    main()
