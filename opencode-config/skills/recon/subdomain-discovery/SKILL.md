---
name: subdomain-discovery
description: Discover subdomains of a target domain using passive and active enumeration
version: 1.0.0
phase: recon
category: discovery
tags: [subdomains, dns, osint]
tools: [subfinder, amass, assetfinder]
difficulty: basic
opsec_level: low
time_estimate: 60s
severity_if_found: info
related_skills:
  - dns-enumeration
  - certificate-transparency
  - vhost-enumeration
mitre_attack:
  - T1596.001
  - T1592
---

## When to Use

Use this skill during the initial recon phase to build a comprehensive list of subdomains
for the target domain. Subdomains reveal additional attack surface, internal services, and
forgotten applications.

## Prerequisites

- subfinder (ProjectDiscovery)
- amass (OWASP)
- assetfinder
- Internet access for passive sources

## Procedure

```bash
subfinder -d TARGET -silent -o subfinder_results.txt
amass enum -d TARGET -passive -o amass_results.txt
assetfinder --subs-only TARGET > assetfinder_results.txt
sort -u subfinder_results.txt amass_results.txt assetfinder_results.txt > all_subdomains.txt
wc -l all_subdomains.txt
```

## OPSEC Rules

- Passive enumeration only — no direct requests to target infrastructure
- Rate limit: no more than 10 requests/second per source
- Avoid triggering cloud provider abuse detection
- Do not use brute-force wordlists in passive mode
- Use `-silent` to reduce output noise

## Verification

- Cross-reference findings across multiple tools (subfinder + amass)
- Check if subdomains resolve: `dig +short subdomain`
- Verify HTTP status: `httpx -l all_subdomains.txt -silent -mc 200,301,302,403`

## Pitfalls

- Some subdomains may only resolve from specific networks (internal DNS)
- Cloudflare-protected domains may hide the origin IP
- CT log sources may have stale entries (weeks old)
- Amass passive mode depends on API keys for full coverage

## Output Format

```
admin.target.com
dev.target.com
api.target.com
staging.target.com
```

One subdomain per line, sorted alphabetically, deduplicated.
