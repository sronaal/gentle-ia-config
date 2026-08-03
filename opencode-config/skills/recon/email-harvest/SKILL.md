---
name: email-harvest
description: Harvest email addresses associated with a target domain from public sources
version: 1.0.0
phase: recon
category: osint
tags: [emails, osint, social-engineering]
tools: [theHarvester, holehe, emailhippo]
difficulty: basic
opsec_level: low
time_estimate: 45s
severity_if_found: medium
related_skills:
  - whois-intel
  - subdomain-discovery
mitre_attack:
  - T1589.002
  - T1591.002
---

## When to Use

Use this skill to collect email addresses for credential stuffing, password
spraying, or social engineering. Email addresses are entry points for phishing.

## Prerequisites

- theHarvester
- holehe (optional, for email validation)
- emailhippo (optional, for validation)

## Procedure

```bash
theHarvester -d TARGET -b all -f harvester_results.html
theHarvester -d TARGET -b google,linkedin,bing -f harvester_google.html
grep -oE "[a-zA-Z0-9._%+-]+@TARGET" harvester_results.html | sort -u > emails.txt
```

## OPSEC Rules

- Use proxy or VPN to avoid IP-based rate limiting
- Limit searches to 100 per source to avoid bans
- Rotate user agents between requests
- Do not scrape LinkedIn directly — use theHarvester's API

## Verification

- Validate emails with holehe or emailhippo
- Check MX records to confirm email delivery path
- Cross-reference with HaveIBeenPwned for breach data

## Pitfalls

- Many email harvesting sources are blocked or rate-limited
- Google has stopped showing email results in search
- Results may contain outdated or invalid addresses
- Some sources require API keys (full coverage requires paid access)

## Output Format

```
admin@target.com
john.doe@target.com
info@target.com
support@target.com
```

One email per line, sorted alphabetically, deduplicated.
