---
name: wordpress-scan
description: Enumerate WordPress installations for plugins, themes, and users
version: 1.0.0
phase: enum
category: cms
tags: [wordpress, plugins, themes, users]
tools: [wpscan, wpcli]
difficulty: intermediate
opsec_level: medium
time_estimate: 60s
severity_if_found: high
related_skills:
  - cms-detection
  - dir-busting
mitre_attack:
  - T1592.002
  - T1595.002
---

## When to Use

Use this skill when WordPress is detected. wpscan enumerates plugins, themes,
users, and version information — all critical for exploitation.

## Prerequisites

- wpscan
- WordPress target URL

## Procedure

```bash
# Enumerate plugins, themes, and users
wpscan --url TARGET --enumerate ap,at,u --random-user-agent -o wpscan_results.txt

# Enumerate with API token for better results
wpscan --url TARGET --enumerate ap,at,u --api-token YOUR_TOKEN --random-user-agent

# Check for specific plugin vulnerabilities
wpscan --url TARGET --enumerate vp --api-token YOUR_TOKEN

# Version detection only
wpscan --url TARGET --wp-version-detection mixed
```

## OPSEC Rules

- Use `--random-user-agent` to avoid fingerprinting
- Limit request rate: `--throttle 100` (ms between requests)
- Do not enumerate without API token — limited vulnerability data
- Do not run multiple wpscan instances against same target
- Log all requests for audit trail

## Verification

- Cross-reference plugin versions with WordPress.org
- Verify user enumeration results with login page
- Check theme version against GitHub/WordPress.org

## Pitfalls

- wpscan without API token has limited CVE data
- Some plugins respond with 200 even when not installed
- User enumeration may be disabled in WordPress config
- CDN/WAF may block wpscan requests

## Output Format

```
[PLUGIN] Contact Form 7 — version 5.7.7
[THEME] Twenty Twenty-Three — version 1.0
[USER] admin (ID: 1)
[VULN] Plugin: Contact Form 7 < 5.8 — CVE-2023-XXXXX
```
