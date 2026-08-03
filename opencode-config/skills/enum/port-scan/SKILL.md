---
name: port-scan
description: Discover open ports and services on target hosts
version: 1.0.0
phase: enum
category: network
tags: [ports, services, scanning]
tools: [nmap, masscan, naabu]
difficulty: basic
opsec_level: medium
time_estimate: 120s
severity_if_found: info
related_skills:
  - service-detection
  - shodan-censys
mitre_attack:
  - T1046
  - T1592.002
---

## When to Use

Use this skill to identify open TCP/UDP ports, running services, and service
versions. Non-standard ports often host overlooked services.

## Prerequisites

- nmap
- masscan (optional, for fast full-range scans)
- naabu (ProjectDiscovery, optional)

## Procedure

```bash
# Quick top-1000 scan
nmap -sV -sC -T4 TARGET -oN nmap_quick.txt

# Full TCP scan (slower but thorough)
nmap -sV -sC -T4 -p- TARGET -oN nmap_full.txt

# Fast full-range with masscan
masscan --rate=1000 TARGET -p0-65535 --open -oJ masscan_results.json

# UDP top-100
nmap -sU -T4 --top-ports 100 TARGET -oN nmap_udp.txt
```

## OPSEC Rules

- Use `-T3` or lower in production environments
- `--rate=1000` for masscan is safe; do not exceed 10000
- Avoid SYN scans (`-sS`) unless authorized — they are noisy
- Do not scan the entire internet range — target specific IPs
- Document all scans with timestamps

## Verification

- Cross-reference nmap and masscan results
- Verify services are actually running: `nc -zv TARGET PORT`
- Check if open ports match expected services

## Pitfalls

- Firewalls may block or rate-limit scans
- Some services respond slowly on large scans
- UDP scans are unreliable and slow
- Masscan may miss services that nmap catches (and vice versa)

## Output Format

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1
80/tcp   open  http    nginx 1.18.0
443/tcp  open  https   nginx 1.18.0
8080/tcp open  http    Apache Tomcat 9.0.65
```
