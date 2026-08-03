---
name: google-dorks-catalog
description: 100+ dork patterns organized by service type
version: 1.0.0
phase: meta
category: methodology
tags: [google, dorks, osint, shodan, censys]
tools: [google-search, shodan, censys]
difficulty: basic
opsec_level: low
time_estimate: 1m
severity_if_found: high
related_skills:
  - google-dorks
  - source-leaks
  - shodan-censys
mitre_attack:
  - T1593.002
  - T1596
---

## When to Use

Use this skill as a comprehensive dork library for OSINT, finding exposed
resources, or building automated dork scanners.

## Prerequisites

- Google Search access (browser or API)
- Shodan API key (optional), Censys account (optional)

## Procedure

### Generic Dorks

```bash
site:TARGET ext:env | ext:conf | ext:ini | ext:yml       # Config files
site:TARGET ext:sql | ext:db | ext:sqlite                  # Database files
site:TARGET ext:bak | ext:backup | ext:old | ext:swp       # Backup files
site:TARGET ext:log | ext:logs                              # Log files
site:TARGET ext:php | ext:asp | ext:py | ext:rb            # Source code
site:TARGET filetype:pdf intext:"password"                  # Credentials
site:TARGET intitle:"index of"                              # Dir listings
site:TARGET inurl:admin | inurl:login | inurl:dashboard    # Admin panels
site:TARGET inurl:api | inurl:v1 | inurl:graphql           # API endpoints
site:TARGET inurl:debug | inurl:test | inurl:staging       # Dev/debug
```

### Cloud: `site:s3.amazonaws.com "TARGET"`, `site:storage.googleapis.com "TARGET"`, `site:blob.core.windows.net "TARGET"`, `site:firebaseio.com "TARGET"`

### GitHub: `"TARGET" language:python password`, `org:TARGET private:true`, `repo:TARGET issue "password"`

### Shodan: `http.title:"TARGET"`, `org:"TARGET" port:22`, `org:"TARGET" port:3306 mysql`, `org:"TARGET" port:5432 postgresql`, `org:"TARGET" port:27017 mongodb`

### Censys: `services.tls.certificates.leaf.names: "TARGET"`, `vulnerabilities.cve: "CVE-*" and names: "TARGET"`

### WordPress: `site:TARGET inurl:wp-admin`, `site:TARGET inurl:/wp-content/plugins/`, `site:TARGET inurl:/wp-json/wp/v2/users`

### SaaS: `site:TARGET force.com`, `site:TARGET inurl:slack.com/signin`, `site:TARGET inurl:/jira | inurl:confluence`, `site:TARGET inurl:grafana`

## OPSEC Rules

- Do not automate Google searches — triggers CAPTCHAs
- Space manual queries by 5-10 seconds
- Use different IPs for bulk dorking
- Monitor Shodan/Censys rate limits
- Do not access found resources without authorization

## Verification

- Manually verify each result before adding to findings
- Confirm dork returns expected resource type
- Check if resources are still accessible

## Pitfalls

- Google caches may show stale results
- Some dorks return false positives
- Rate limiting is aggressive for automation
- Shodan/Censys data may be outdated

## Output Format

```
[DORK] site:TARGET ext:env — 3 results
[SHODAN] org:"TARGET" port:3306 — 2 results
[FINDING] 3 sensitive files found via dorks
```
