# 🤖 Autonomous Security Agent (AI-Powered Threat Detection)

This is a security AI project that:
- Streams security logs to AWS S3
- Uses BERT + Isolation Forest to detect anomalies
- Sends alerts via AWS SNS
- Shows logs and threats in a Streamlit dashboard

---

## 📦 Features
- Real-time log reading from AWS S3
- Anomaly detection with LLM embeddings
- Email alerting via SNS
- Web dashboard with Streamlit

---

## 🛠 Tech Stack
- Python
- HuggingFace Transformers
- AWS S3 + SNS
- Streamlit

---

## 🚀 Run It
```bash
pip install -r requirements.txt
python detect_anomalies.py
streamlit run dashboard.py

autonomous-security-agent/
│
├── detect_anomalies.py
├── dashboard.py
├── requirements.txt
├── sample_logs.json.gz
└── README.md
