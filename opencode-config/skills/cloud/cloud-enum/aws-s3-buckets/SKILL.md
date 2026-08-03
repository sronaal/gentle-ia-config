---
name: aws-s3-buckets
description: Discover and enumerate AWS S3 buckets via permutations and DNS resolution
version: 1.0.0
phase: cloud
category: enumeration
tags: [aws, s3, storage, buckets]
tools: [curl, aws-cli]
difficulty: intermediate
opsec_level: passive
time_estimate: 120s
severity_if_found: high
related_skills:
  - cloud-provider-detect
  - gcp-storage-buckets
  - azure-blob-storage
mitre_attack:
  - T1619
  - T1530
---

## When to Use

Use this skill after confirming the target uses AWS. Enumerate S3 buckets
to find misconfigured public buckets, sensitive data exposure, and potential
attack paths through bucket policies.

## Prerequisites

- curl
- aws-cli (for signed requests)

## Procedure

```bash
# Step 1: Generate bucket name permutations from target
for prefix in "target" "target-backup" "target-dev" "target-staging" \
              "target-data" "target-logs" "target-assets" "target-media"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://${prefix}.s3.amazonaws.com/")
  if [ "$code" != "404" ]; then
    echo "[$code] https://${prefix}.s3.amazonaws.com/"
  fi
done

# Step 2: Check bucket listing (no-sign-request)
for bucket in "target" "target-backup" "target-data"; do
  result=$(aws s3 ls "s3://${bucket}" --no-sign-request 2>&1)
  if [ $? -eq 0 ]; then
    echo "LISTABLE: s3://${bucket}"
    echo "$result" | head -20
  fi
done

# Step 3: Check bucket policy
aws s3api get-bucket-policy --bucket target --no-sign-request 2>/dev/null
aws s3api get-bucket-acl --bucket target --no-sign-request 2>/dev/null

# Step 4: Check for public list via API
curl -sk "https://target.s3.amazonaws.com/?list-type=2" | jq '.ListBucketResult.Contents[].Key' 2>/dev/null

# Step 5: DNS-based bucket existence check
for prefix in "target" "target-backups" "target-config"; do
  dig +short "${prefix}.s3.amazonaws.com" && echo "EXISTS: ${prefix}.s3.amazonaws.com"
done
```

## OPSEC Rules

- Read-only enumeration only — do NOT write, modify, or delete
- Do NOT download files without explicit authorization
- Respect `--no-sign-request` — authenticated access may be logged
- Rate limit curl requests to 3/second

## Verification

- Confirm public accessibility via anonymous curl
- Cross-reference bucket names from multiple sources
- Verify bucket region via `aws s3api get-bucket-location`

## Pitfalls

- Some buckets return 403 but still list objects via API
- Bucket policies may allow listing but not downloading
- DNS-based checks may return false positives (NXDOMAIN redirects)
- Permission delegation with S3 Object Ownership changes access patterns

## Output Format

```
[BUCKET]   target.s3.amazonaws.com — 403 (Forbidden — exists)
[BUCKET]   target-backup.s3.amazonaws.com — 200 — LISTABLE — 47 objects
[BUCKET]   target-dev.s3.amazonaws.com — 404 (NoSuchBucket)
CRITICAL:  target-backup.s3.amazonaws.com is publicly listable, contains config files
```
