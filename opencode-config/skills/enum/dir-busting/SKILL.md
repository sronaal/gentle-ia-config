---
name: dir-busting
description: Discover hidden directories and files on web servers
version: 1.0.0
phase: enum
category: web
tags: [directories, files, web, brute-force]
tools: [ffuf, gobuster, dirsearch]
difficulty: basic
opsec_level: medium
time_estimate: 120s
severity_if_found: medium
related_skills:
  - api-discovery
  - vhost-enumeration
mitre_attack:
  - T1592.002
  - T1083
---

## When to Use

Use this skill to discover hidden directories, files, and endpoints on web
servers. Admin panels, config files, and backups are common findings.

## Prerequisites

- ffuf or gobuster
- A wordlist (common.txt, directory-list-2.3-medium.txt)

## Procedure

```bash
# ffuf directory enumeration
ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -o dir_results.json

# gobuster directory mode
gobuster dir -u https://TARGET -w /usr/share/wordlists/dirb/common.txt -t 20 -o gobuster_results.txt

# Filter by response size to reduce noise
ffuf -u https://TARGET/FUZZ -w wordlist.txt -mc all -fs 0 -o filtered.json

# Recursive enumeration
ffuf -u https://TARGET/FUZZ -w wordlist.txt -recursion -recursion-depth 2 -o recursive.json
```

## OPSEC Rules

- Use 20-50 threads maximum to avoid detection
- Set realistic User-Agent
- Monitor response codes — 429 means slow down
- Do not use full wordlists on first pass (start with common.txt)
- Respect WAF and rate limiting

## Verification

- Manually visit discovered directories in browser
- Check if files contain sensitive data
- Verify directories are not just default installations

## Pitfalls

- Response size filtering is critical to reduce false positives
- Some applications return 200 for all paths (SPA)
- WAF may block after too many requests
- Recursive enumeration multiplies request count exponentially

## Output Format

```
[DIR] /admin — 301 (size: 0)
[FILE] /robots.txt — 200 (size: 123)
[FILE] /.env — 200 (size: 456)
[DIR] /api — 200 (size: 789)
```
