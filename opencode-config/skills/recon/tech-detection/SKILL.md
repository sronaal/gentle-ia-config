---
name: tech-detection
description: Detect web technologies, frameworks, and versions used by a target
version: 1.0.0
phase: recon
category: fingerprinting
tags: [technologies, fingerprinting, versions]
tools: [httpx, whatweb, wappalyzer]
difficulty: basic
opsec_level: low
time_estimate: 15s
severity_if_found: medium
related_skills:
  - port-scan
  - dir-busting
mitre_attack:
  - T1592.002
  - T1595.002
---

## When to Use

Use this skill to identify web servers, frameworks, CMS platforms, and version numbers.
Outdated technologies with known CVEs are immediate exploitation targets.

## Prerequisites

- httpx (ProjectDiscovery)
- whatweb
- wappalyzer (optional, CLI or browser extension)

## Procedure

```bash
httpx -u TARGET -tech-detect -silent
whatweb TARGET -v
wappalyzer TARGET 2>/dev/null || echo "Install wappalyzer-cli"
```

## OPSEC Rules

- Use a single request per technology check
- Set realistic User-Agent headers
- Respect rate limits — no burst requests
- Use `-silent` on httpx to reduce log noise

## Verification

- Cross-reference technologies found by multiple tools
- Verify version numbers against public CVE databases
- Check if identified tech matches expected stack (e.g., WordPress site)

## Pitfalls

- Technology detection is not 100% accurate — false positives occur
- CDN layers (Cloudflare, Akamai) may hide origin technologies
- Some frameworks don't expose version headers
- WAF may strip or modify response headers

## Output Format

```
[httpx] https://target.com [200] [nginx/1.18.0, PHP/8.1.2, WordPress/6.4.1]
[whatweb] https://target.com [200] WordPress[6.4.1], PHP[8.1.2], jQuery[3.7.1]
```
