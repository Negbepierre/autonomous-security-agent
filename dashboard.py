import streamlit as st
import pandas as pd
import boto3
import gzip
import io
import json

# -----------------------------
# 🔧 CONFIGURATION
# -----------------------------
BUCKET_NAME = "security-logs-negbepierre"
REGION = "eu-west-2"
PREFIX = "2025/04/26/02/"  # update this when your folder/date changes

# -----------------------------
# 📥 LOAD DATA FROM S3
# -----------------------------
st.title("🔐 Security Anomaly Dashboard")
s3 = boto3.client("s3", region_name=REGION)

try:
    response = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=PREFIX)
    log_entries = []

    for obj in response.get("Contents", []):
        key = obj["Key"]
        if key.endswith(".json.gz"):
            obj_data = s3.get_object(Bucket=BUCKET_NAME, Key=key)
            bytestream = io.BytesIO(obj_data["Body"].read())

            with gzip.GzipFile(fileobj=bytestream, mode="rb") as f:
                lines = f.read().decode("utf-8").splitlines()
                for line in lines:
                    try:
                        log_entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        st.warning(f"⚠️ Skipped invalid JSON line in {key}")

    # Convert to DataFrame
    if log_entries:
        df = pd.DataFrame(log_entries)
    else:
        df = pd.DataFrame()

except Exception as e:
    st.error(f"❌ Failed to load logs: {e}")
    df = pd.DataFrame()

# -----------------------------
# 📊 DASHBOARD VIEW
# -----------------------------
if df.empty:
    st.warning("📂 No log data found in S3.")
else:
    st.subheader("📜 All Logs")
    st.dataframe(df)

    if "event" in df.columns:
        # Define suspicious events
        suspicious_keywords = [
            "unauthorized_access_attempt",
            "privilege_escalation",
            "malware_detected",
            "data_exfiltration",
            "ddos_attack"
        ]
        # Filter anomalies
        anomalous_events = df[df["event"].isin(suspicious_keywords)]

        st.subheader("🚨 Detected Anomalies")
        if not anomalous_events.empty:
            st.dataframe(anomalous_events)
        else:
            st.success("✅ No anomalies detected based on known patterns.")
    else:
        st.error("❌ 'event' column not found in the log data.")
