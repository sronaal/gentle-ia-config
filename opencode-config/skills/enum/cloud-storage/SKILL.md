---
name: cloud-storage
description: Cloud storage bucket enumeration (S3, GCS, Azure Blob)
version: 1.0.0
phase: enum
category: cloud
tags: [aws, gcs, azure, storage, buckets]
tools: [curl, aws, gsutil]
difficulty: intermediate
opsec_level: low
time_estimate: 60s
severity_if_found: high
related_skills:
  - github-dorking
  - api-discovery
mitre_attack:
  - T1530
  - T1619
---

## When to Use

Use this skill to find publicly accessible or misconfigured cloud storage
buckets on AWS S3, Google Cloud Storage, or Azure Blob Storage.

## Prerequisites

- curl
- aws-cli (for S3)
- gsutil (for GCS)

## Procedure

```bash
# Step 1: AWS S3 — check if bucket exists
curl -sk https://TARGET.s3.amazonaws.com/ | head -20
curl -sk https://s3.amazonaws.com/TARGET

# Step 2: AWS S3 — list bucket contents
aws s3 ls s3://TARGET --no-sign-request
aws s3 ls s3://TARGET --no-sign-request --recursive

# Step 3: AWS S3 — check bucket policy
aws s3api get-bucket-policy --bucket TARGET --no-sign-request 2>/dev/null

# Step 4: Google Cloud Storage
curl -sk https://storage.googleapis.com/TARGET/
curl -sk "https://storage.googleapis.com/TARGET/?prefix=&delimiter=/"

# Step 5: Azure Blob Storage
curl -sk "https://TARGET.blob.core.windows.net/?comp=list"
curl -sk "https://TARGET.blob.core.windows.net/?restype=container&comp=list"

# Step 6: Enumerate common subdomains for storage
for sub in "s3" "storage" "blobs" "files"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://${sub}.TARGET/")
  echo "$code ${sub}.TARGET"
done

# Step 7: Check for open directories
curl -sk "https://TARGET.s3.amazonaws.com/?list-type=2" | jq '.ListBucketResult.Contents[].Key'
```

## OPSEC Rules

- Do NOT download files without authorization
- Do NOT modify or delete any objects
- Do NOT attempt to write to buckets
- Read-only enumeration only
- Document all accessed URLs for legal review

## Verification

- Confirm bucket exists and is accessible
- Verify you can list objects (not just get a 403)
- Check if bucket policy allows public access

## Pitfalls

- Some buckets return 403 but still leak object names
- ACLs may allow listing but not downloading
- Azure requires correct API version parameter
- S3 Object Ownership settings affect access patterns

## Output Format

```
[S3]      s3://TARGET — LISTABLE — 47 objects
[S3]      s3://TARGET-backups — LISTABLE — 12 objects
[AZURE]   TARGET.blob.core.windows.net — container "data" accessible
[GCS]     storage.googleapis.com/TARGET — LISTABLE
[CRITICAL] Public bucket contains backup files and credentials
```
