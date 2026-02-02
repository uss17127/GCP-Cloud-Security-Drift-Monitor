# GCP Cloud Security Drift Monitor

A Python-based cloud security automation tool that analyzes Google Cloud
Storage (GCS) IAM policies to detect security drift. Checks for publicly
accessible buckets and unauthorized service account access.

---

## Features

- Inspects IAM policies across GCS buckets
- Detects public access via `allUsers` or `allAuthenticatedUsers`
- Identifies unexpected or unauthorized service accounts
- Enforces least-privilege access using an allowlist configuration
- Dockerized 

---

## Configuration

### `config.yaml`
Define approved service accounts allowed to access buckets:

## yaml
allowed_service_accounts:
  - drift-monitor-sa@my-project.iam.gserviceaccount.com

---

## Project Structure
gcp-drift-monitor/\
├── Dockerfile\
├── README.md\
├── main.py\
├── requirements.txt\
└── creds.json\

---

## Authentication

This tool uses **Google Application Default Credentials** to authenticate with GCP.  

---

## Local Execution

Set the path to your credentials file:

##bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/creds.json

---

## Build Docker image and run container

docker build -t gcp-drift-monitor .

docker run --rm \
  -e GOOGLE_APPLICATION_CREDENTIALS=/app/creds.json \
  -v /path/to/creds.json:/app/creds.json \
  gcp-drift-monitor

