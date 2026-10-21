import sqlite3
import pandas as pd
import os

DB_PATH = os.path.join("db", "cybershield.db")


def load_events():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM events", conn)
    conn.close()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


def compute_features(df):
    """
    Har event ke liye, uske source_ip ka pichhle 5 min aur 10 min ka
    rolling window nikal kar features banate hain.

    Ye simple lekin real windowing hai - production mein isko Redis
    stream par continuously chalate, yahan hum poora dataset ek baar
    mein process kar rahe hain (batch mode - MVP ke liye kaafi hai).
    """
    df = df.set_index("timestamp")
    feature_rows = []

    for source_ip, group in df.groupby("source_ip"):
        group = group.sort_index()

        # Rolling counts - har event ke time par, uske pichhle N minutes mein
        # kitne events isi source_ip se aaye
        failed_auth_5m = (
            (group["event_type"] == "authentication_failure")
            .rolling("5min").sum()
        )
        failed_auth_10m = (
            (group["event_type"] == "authentication_failure")
            .rolling("10min").sum()
        )
        conn_count_5m = group["event_type"].rolling("5min").count()

        # Unique destination ports in rolling 10 min window
        unique_ports_10m = []
        for ts in group.index:
            window = group.loc[ts - pd.Timedelta("10min"): ts]
            unique_ports_10m.append(window["destination_port"].nunique())

        # Unique destination IPs in rolling 10 min window
        unique_dest_ips_10m = []
        for ts in group.index:
            window = group.loc[ts - pd.Timedelta("10min"): ts]
            unique_dest_ips_10m.append(window["destination_ip"].nunique())

        temp = group.reset_index()
        temp["failed_auth_count_5m"] = failed_auth_5m.values
        temp["failed_auth_count_10m"] = failed_auth_10m.values
        temp["connection_count_5m"] = conn_count_5m.values
        temp["unique_ports_10m"] = unique_ports_10m
        temp["unique_dest_ips_10m"] = unique_dest_ips_10m

        feature_rows.append(temp)

    result = pd.concat(feature_rows, ignore_index=True)
    result = result.sort_values("timestamp").reset_index(drop=True)
    return result


def save_features(df):
    conn = sqlite3.connect(DB_PATH)
    df.to_sql("features", conn, if_exists="replace", index=False)
    conn.close()


def main():
    if not os.path.exists(DB_PATH):
        print("Database nahi mili. Pehle setup_db.py aur generate_logs.py chalao.")
        return

    print("Events load ho rahe hain...")
    df = load_events()
    print(f"Total events: {len(df)}")

    print("Rolling-window features calculate ho rahe hain...")
    features_df = compute_features(df)

    save_features(features_df)
    print(f"'features' table save ho gayi: {len(features_df)} rows")

    # Quick sanity check - brute-force wale IP ka feature dikhana
    suspicious = features_df[features_df["source_ip"] == "203.0.113.44"]
    if len(suspicious) > 0:
        print("\nExample - brute-force source (203.0.113.44) ka peak feature snapshot:")
        peak = suspicious.loc[suspicious["failed_auth_count_5m"].idxmax()]
        print(f"  failed_auth_count_5m  = {peak['failed_auth_count_5m']}")
        print(f"  failed_auth_count_10m = {peak['failed_auth_count_10m']}")
        print(f"  connection_count_5m   = {peak['connection_count_5m']}")

    print("\nAb Day 3 (Isolation Forest detection) shuru kar sakte ho.")


if __name__ == "__main__":
    main()
