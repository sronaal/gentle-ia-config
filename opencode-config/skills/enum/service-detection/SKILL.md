---
name: service-detection
description: Identify service versions and detect known vulnerabilities
version: 1.0.0
phase: enum
category: network
tags: [services, versions, vulnerabilities]
tools: [nmap, banner-grab]
difficulty: basic
opsec_level: medium
time_estimate: 60s
severity_if_found: medium
related_skills:
  - port-scan
  - ssl-tls-analysis
mitre_attack:
  - T1046
  - T1592.002
---

## When to Use

Use this skill to determine exact service versions on discovered open ports.
Knowing the version allows mapping to known CVEs.

## Prerequisites

- nmap with NSE scripts
- curl (for banner grabbing)

## Procedure

```bash
# Version detection on specific port
nmap -sV -p PORT TARGET

# Full version detection with scripts
nmap -sV -sC -p PORT TARGET --script=banner

# Banner grab manually
echo "" | nc -w3 TARGET PORT

# HTTP banner
curl -skI "https://TARGET" | head -20
```

## OPSEC Rules

- Target specific ports, not full range scans
- Limit to 3 requests per second
- Do not run aggressive NSE scripts without authorization
- Document service versions before testing for vulns

## Verification

- Cross-check nmap version with manual banner grab
- Verify against vendor documentation
- Check Shodan for historical version data

## Pitfalls

- Version detection may be inaccurate (banner spoofing)
- Some services don't respond to version probes
- Nmap scripts may trigger IDS alerts
- Version numbers may be misleading (e.g., Apache mod_version)

## Output Format

```
PORT   SERVICE VERSION
22/tcp ssh      OpenSSH 8.4p1 Ubuntu-3ubuntu2.1
80/tcp http     nginx 1.18.0 (Ubuntu)
```
