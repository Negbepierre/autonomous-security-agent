import boto3
import pandas as pd
import json
from transformers import AutoTokenizer, AutoModel
import torch
from sklearn.ensemble import IsolationForest
import gzip
import io

# AWS Settings
BUCKET_NAME = "security-logs-negbepierre"
REGION = "eu-west-2"
PREFIX = ""  # Keep empty if logs are at root

# Setup AWS S3 client
s3 = boto3.client('s3', region_name=REGION)

# List all objects inside the bucket
response = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix=PREFIX)

log_entries = []

# Download and extract each .json.gz log file
for obj in response.get('Contents', []):
    key = obj['Key']
    if key.endswith('.json.gz'):
        obj_data = s3.get_object(Bucket=BUCKET_NAME, Key=key)
        bytestream = io.BytesIO(obj_data['Body'].read())
        with gzip.GzipFile(fileobj=bytestream, mode='rb') as f:
            lines = f.read().decode('utf-8').splitlines()
            for line in lines:
                log_entries.append(json.loads(line))

# Convert to DataFrame
df = pd.DataFrame(log_entries)

# Combine fields into text for embedding
df["text"] = df.apply(lambda row: f"{row['event']} {row['username']} {row['ip']}", axis=1)

# Load BERT tokenizer and model
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
model = AutoModel.from_pretrained("bert-base-uncased")

# Function to generate embeddings
def get_embedding(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
    return outputs.last_hidden_state[:, 0, :].squeeze().numpy()

# Generate embeddings
embeddings = [get_embedding(text) for text in df["text"]]

# Anomaly Detection using Isolation Forest
clf = IsolationForest(contamination=0.1)
preds = clf.fit_predict(embeddings)

df["anomaly"] = preds

# Print Results
print(df[["event", "username", "ip", "anomaly"]])

# --- SNS ALERT SECTION ---

# Setup SNS client
sns = boto3.client('sns', region_name=REGION)

# Filter detected anomalies
anomalies = df[df["anomaly"] == -1]

if not anomalies.empty:
    # Create a message containing anomalies
    message = anomalies.to_json(orient="records", lines=True)

    # Publish alert to SNS topic
    response = sns.publish(
        TopicArn="arn:aws:sns:eu-west-2:345594588009:security-anomaly-alerts",  # Correct TopicArn here
        Message=message,
        Subject="🚨 Security Anomaly Detected!"
    )
    print("🚨 Anomaly alert sent via email!")
else:
    print("✅ No anomalies detected, no alert sent.")
