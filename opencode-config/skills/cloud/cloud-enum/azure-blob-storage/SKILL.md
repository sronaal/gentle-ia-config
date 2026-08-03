---
name: azure-blob-storage
description: Discover and enumerate Azure Blob Storage accounts
version: 1.0.0
phase: cloud
category: enumeration
tags: [azure, blob, storage, cloud]
tools: [curl, az-cli]
difficulty: intermediate
opsec_level: passive
time_estimate: 120s
severity_if_found: high
related_skills:
  - cloud-provider-detect
  - aws-s3-buckets
  - gcp-storage-buckets
mitre_attack:
  - T1619
  - T1530
---

## When to Use

Use this skill after identifying Azure as the target cloud provider. Discover
misconfigured Azure Blob Storage containers that expose sensitive data.

## Prerequisites

- curl
- az-cli (optional, for authenticated access)

## Procedure

```bash
# Step 1: Check common blob storage account name permutations
for account in "target" "targetdata" "targetblob" "targetstorage" \
               "targetbackup" "targetassets" "targetmedia"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://${account}.blob.core.windows.net/?comp=list")
  if [ "$code" != "404" ]; then
    echo "[$code] https://${account}.blob.core.windows.net/"
  fi
done

# Step 2: List containers (if account accessible)
code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.blob.core.windows.net/?comp=list")
if [ "$code" = "200" ]; then
  curl -sk "https://target.blob.core.windows.net/?comp=list" | xmllint --format -
fi

# Step 3: Check public container access
for container in "data" "backups" "files" "public" "uploads" "config" "logs"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.blob.core.windows.net/${container}?restype=container&comp=list")
  if [ "$code" = "200" ]; then
    echo "LISTABLE: ${container}"
    curl -sk "https://target.blob.core.windows.net/${container}?restype=container&comp=list" | xmllint --format -
  fi
done

# Step 4: Check for common blob names
for blob in "index.html" "config.json" "backup.zip" "credentials.txt"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.blob.core.windows.net/data/${blob}")
  echo "[$code] data/${blob}"
done
```

## OPSEC Rules

- Read-only enumeration only
- Do not download files without authorization
- Respect Azure rate limits (90 requests/minute per IP)
- Some Azure responses are cached — allow 30s between rechecks

## Verification

- Verify via `az-cli` if credentials are available
- Check Access Policy via `az storage container policy list`
- Confirm blob URLs resolve to Azure CDN or direct endpoint

## Pitfalls

- Storage accounts may return 403 with public access disabled
- Azure CDN may mask the underlying blob URL
- Anonymous access may be enabled on containers but not the account
- XML parsing requires `xmllint` or similar

## Output Format

```
[AZURE]    target.blob.core.windows.net — 403 (exists, access denied)
[AZURE]    targetdata.blob.core.windows.net — 200 — LISTABLE
  Container: data — 12 blobs (config.json, backup.sql, ...)
  Container: backups — 47 blobs
CRITICAL:  targetdata.blob.core.windows.net/data/config.json — public config dump
```
