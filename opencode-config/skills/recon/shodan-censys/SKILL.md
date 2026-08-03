---
name: shodan-censys
description: Query Shodan and Censys for exposed services, banners, and vulnerabilities
version: 1.0.0
phase: recon
category: infrastructure
tags: [shodan, censys, banners, services]
tools: [shodan, censys]
difficulty: basic
opsec_level: low
time_estimate: 15s
severity_if_found: medium
related_skills:
  - port-scan
  - service-detection
mitre_attack:
  - T1046
  - T1592.002
---

## When to Use

Use this skill to discover open ports, services, and banners without actively
scanning the target. Shodan and Censys provide passive recon data.

## Prerequisites

- Shodan API key (free tier available)
- Censys API credentials (optional)
- curl or shodan CLI

## Procedure

```bash
# Shodan host lookup
curl -s "https://api.shodan.io/shodan/host/IP_ADDRESS?key=YOUR_API_KEY" | python3 -m json.tool

# Shodan search by hostname
shodan search hostname:TARGET --fields ip_str,port,product,vulns

# Censys search (if credentials available)
curl -s -u "CENSYS_ID:CENSYS_SECRET" "https://search.censys.io/api/v2/hosts/search?q=TARGET" | python3 -m json.tool
```

## OPSEC Rules

- API queries are passive — no direct traffic to target
- Respect API rate limits (1 request/second for free tier)
- Do not cache API keys in plaintext
- Use environment variables for credentials

## Verification

- Cross-reference Shodan data with active scans (nmap)
- Verify open ports are still active
- Check if banners match expected services

## Pitfalls

- Shodan data may be stale (last scan date varies)
- Free tier limits results to 100 per query
- Some services are behind VPN/Tor — not indexed
- Censys requires paid tier for full results

## Output Format

```
[SHODAN] 192.168.1.10:80 — nginx/1.18.0
[SHODAN] 192.168.1.10:443 — OpenSSL/1.1.1k
[SHODAN] 192.168.1.10:22 — OpenSSH 8.4p1
[VULNS] CVE-2021-44228 (Log4j) detected
```
