---
name: gcp-storage-buckets
description: Discover and enumerate Google Cloud Storage buckets
version: 1.0.0
phase: cloud
category: enumeration
tags: [gcp, storage, buckets, cloud]
tools: [curl, gsutil]
difficulty: intermediate
opsec_level: passive
time_estimate: 120s
severity_if_found: high
related_skills:
  - cloud-provider-detect
  - aws-s3-buckets
  - azure-blob-storage
mitre_attack:
  - T1619
  - T1530
---

## When to Use

Use this skill after identifying GCP as the target cloud provider. Enumerate
Google Cloud Storage buckets for publicly accessible data and misconfigurations.

## Prerequisites

- curl
- gsutil (optional, for authenticated access)

## Procedure

```bash
# Step 1: Check common bucket name permutations
for prefix in "target" "target-data" "target-backup" "target-config" \
              "target-logs" "target-assets" "target-app" "target-www"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${prefix}/")
  if [ "$code" != "404" ]; then
    echo "[$code] storage.googleapis.com/${prefix}/"
  fi
done

# Step 2: List bucket contents (if public)
curl -sk "https://storage.googleapis.com/target/?prefix=" | xmllint --format -

# Step 3: Check authenticated access with gsutil
gsutil ls gs://target 2>&1
gsutil ls gs://target/** 2>&1

# Step 4: Check bucket IAM (if authenticated)
gsutil iam get gs://target 2>/dev/null

# Step 5: Check for uniform vs fine-grained access
gsutil defacl get gs://target 2>/dev/null
```

## OPSEC Rules

- Read-only enumeration only
- Do not modify ACLs or bucket policies
- Respect GCP rate limits (100 requests/100 seconds per user)
- Use `--no-sign-request` equivalent where available

## Verification

- Cross-reference with DNS: `dig +short target.storage.googleapis.com`
- Confirm access level via anonymous curl
- Verify bucket location for region identification

## Pitfalls

- Uniform bucket-level access disables per-object ACL checking
- GCP returns 400 for non-existent buckets (not 404)
- XML API requires different endpoint than JSON API
- Requester Pays buckets block anonymous requests

## Output Format

```
[GCS]      storage.googleapis.com/target — 400 (bucket does not exist)
[GCS]      storage.googleapis.com/target-data — 200 — LISTABLE
  Object:  backup/db.sql.gz — 2.3MB
  Object:  config/app.yaml — 4.2KB
[GCS]      storage.googleapis.com/target-backup — 403 (exists, denied)
CRITICAL:  target-data bucket publicly listable, 47 objects visible
```
