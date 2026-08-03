---
name: google-dorks
description: Use Google dork queries to find sensitive files and exposed panels
version: 1.0.0
phase: recon
category: osint
tags: [google, dorks, sensitive-files]
tools: [google-search]
difficulty: basic
opsec_level: low
time_estimate: 60s
severity_if_found: high
related_skills:
  - js-secrets
  - source-leaks
mitre_attack:
  - T1593.002
  - T1596
---

## When to Use

Use this skill to find exposed configuration files, backup files, admin panels,
logs, and other sensitive resources indexed by search engines.

## Prerequisites

- Web browser or curl with search engine access
- No special tools required

## Procedure

```bash
# Find sensitive file types
site:TARGET ext:sql | ext:log | ext:bak | ext:conf

# Find admin panels
site:TARGET inurl:admin | inurl:login | inurl:dashboard

# Find directory listings
site:TARGET intitle:"index of"

# Find exposed credentials
site:TARGET filetype:env | filetype:log | filetype:yml

# Find API documentation
site:TARGET inurl:swagger | inurl:api-docs | inurl:graphql

# Google cache inspection
cache:TARGET
```

## OPSEC Rules

- Do not automate Google searches — this triggers CAPTCHAs
- Use manual searches or spaced-out queries
- Do not use the same IP for bulk dorking
- Rotate user agents if using curl
- Respect Google's robots.txt

## Verification

- Manually verify each result before adding to findings
- Check if files are still accessible (not cached/stale)
- Confirm sensitive data is actually present in the file

## Pitfalls

- Google may have cached pages that are no longer live
- Some results may require authentication
- Rate limiting is aggressive for automated queries
- Results vary by region and language

## Output Format

```
[EXPOSED FILE] https://target.com/backup/db.sql (size: 2.3MB)
[PANEL] https://target.com/admin/login
[LOG] https://target.com/logs/error.log
```
