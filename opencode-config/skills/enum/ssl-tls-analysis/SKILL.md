---
name: ssl-tls-analysis
description: Analyze SSL/TLS configuration for weak ciphers and misconfigurations
version: 1.0.0
phase: enum
category: crypto
tags: [ssl, tls, certificates, ciphers]
tools: [testssl.sh, sslscan]
difficulty: basic
opsec_level: low
time_estimate: 30s
severity_if_found: high
related_skills:
  - service-detection
  - port-scan
mitre_attack:
  - T1557
  - T1040
---

## When to Use

Use this skill to identify weak SSL/TLS configurations, expired certificates,
vulnerable cipher suites, and known attacks (Heartbleed, POODLE, BEAST).

## Prerequisites

- testssl.sh
- sslscan
- openssl (usually pre-installed)

## Procedure

```bash
# Full SSL/TLS analysis with testssl.sh
testssl.sh TARGET

# Quick cipher scan with sslscan
sslscan TARGET

# Check certificate details
echo | openssl s_client -connect TARGET:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer

# Check for specific vulnerabilities
testssl.sh --heartbleed TARGET
testssl.sh --poodle TARGET
testssl.sh --beast TARGET
```

## OPSEC Rules

- SSL testing is low-risk — standard TLS handshakes
- Do not run testssl.sh on all ports simultaneously
- Limit to 1-2 full scans per target
- Document results before moving to exploitation

## Verification

- Cross-check findings between testssl.sh and sslscan
- Verify certificate expiry dates manually
- Check if certificate is for the correct domain

## Pitfalls

- testssl.sh takes 2-5 minutes for a full scan
- Some servers reject connections from certain IP ranges
- Results may vary between IPv4 and IPv6
- CDN may present different certificates than origin

## Output Format

```
[SSL] Certificate: valid until 2025-06-15
[SSL] Protocol: TLSv1.3 supported
[CIPHER] Weak: TLS_RSA_WITH_AES_128_CBC_SHA (deprecated)
[VULN] Heartbleed: NOT vulnerable
[VULN] POODLE: vulnerable (SSLv3 enabled)
```
