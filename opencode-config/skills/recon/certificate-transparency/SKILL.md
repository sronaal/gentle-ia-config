---
name: certificate-transparency
description: Enumerate subdomains via Certificate Transparency logs
version: 1.0.0
phase: recon
category: discovery
tags: [subdomains, certificates, ct-logs]
tools: [curl]
difficulty: basic
opsec_level: low
time_estimate: 10s
severity_if_found: info
related_skills:
  - subdomain-discovery
  - dns-enumeration
mitre_attack:
  - T1596.001
  - T1592
---

## When to Use

Use this skill to discover subdomains from Certificate Transparency logs. CT logs
are a goldmine for passive subdomain enumeration without touching the target.

## Prerequisites

- curl
- jq (optional, for JSON parsing)

## Procedure

```bash
# Query crt.sh (CT log aggregator)
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' | sort -u > ct_subdomains.txt

# Parse and deduplicate
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' | tr ',' '\n' | sed 's/^\*\.//' | sort -u > ct_unique.txt

# Count results
wc -l ct_unique.txt

# Check for wildcards
grep -c '^\*' ct_unique.txt || echo "No wildcards"
```

## OPSEC Rules

- crt.sh is a public service — queries are safe
- Rate limit: no more than 10 requests per minute
- Do not query for every subdomain discovered (diminishing returns)
- Cache results — CT logs update periodically

## Verification

- Cross-reference with subfinder/amass results
- Check if discovered subdomains resolve (dig +short)
- Verify wildcard certificates are not generating false subdomains

## Pitfalls

- crt.sh may be slow or temporarily unavailable
- Some subdomains use Let's Encrypt short-lived certs (recent only)
- Wildcard certs (*.target.com) appear for every subdomain
- Results may include staging/dev subdomains not in DNS

## Output Format

```
api.target.com
dev.target.com
mail.target.com
staging.target.com
```

One subdomain per line, sorted alphabetically.
