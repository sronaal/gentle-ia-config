---
name: vhost-enumeration
description: Discover virtual hosts on the target web server
version: 1.0.0
phase: recon
category: discovery
tags: [vhosts, web, enumeration]
tools: [ffuf, vhost-scanner]
difficulty: intermediate
opsec_level: medium
time_estimate: 60s
severity_if_found: medium
related_skills:
  - subdomain-discovery
  - dir-busting
mitre_attack:
  - T1592.002
  - T1046
---

## When to Use

Use this skill to discover virtual hosts (vhosts) hosted on the same IP. Vhosts
often reveal internal applications, admin panels, and staging environments.

## Prerequisites

- ffuf (Fuzz Faster U Fool)
- A wordlist for vhost names
- Target IP and base domain

## Procedure

```bash
# Basic vhost enumeration
ffuf -u https://TARGET -H "Host: FUZZ.TARGET" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302,403 -fs SIZE -o vhosts.json

# Filter by response size to remove default vhosts
ffuf -u https://TARGET -H "Host: FUZZ.TARGET" -w wordlist.txt -mc all -fs DEFAULT_SIZE -o vhosts_filtered.json

# Check discovered vhosts
curl -sk "https://DISCOVERED_VHOST" -H "Host: DISCOVERED_VHOST" -o /dev/null -w "%{http_code}"
```

## OPSEC Rules

- Rate limit to 50 requests per second maximum
- Do not use the full 5000-word list without size filtering
- Start with a small wordlist (top 500) and expand if needed
- Monitor for WAF/rate limiting responses (429, 403)

## Verification

- Manually visit each discovered vhost in browser
- Verify the vhost shows different content than the default
- Check DNS resolution for discovered vhost names

## Pitfalls

- Default response size filtering is essential to reduce noise
- Some vhosts require specific Host headers AND IP combinations
- CDN may serve the same content for all vhosts
- SSL certificates may reveal vhost names in SANs

## Output Format

```
[VHOST] admin.target.com — 200 (size: 1234)
[VHOST] staging.target.com — 301 (size: 0)
[VHOST] internal.target.com — 403 (size: 567)
```
