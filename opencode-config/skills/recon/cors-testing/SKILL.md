---
name: cors-testing
description: Test Cross-Origin Resource Sharing configuration for misconfigurations
version: 1.0.0
phase: recon
category: web
tags: [cors, web, authentication]
tools: [curl]
difficulty: intermediate
opsec_level: low
time_estimate: 15s
severity_if_found: high
related_skills:
  - hunt-cors-exploit
  - js-secrets
mitre_attack:
  - T1189
---

## When to Use

Use this skill to detect CORS misconfigurations that could allow credential theft
via cross-origin requests. A reflected Origin header is a critical finding.

## Prerequisites

- curl
- Target must have an HTTP(S) endpoint

## Procedure

```bash
# Test basic CORS — reflected origin
curl -skI "https://TARGET" -H "Origin: https://evil.com" 2>/dev/null | grep -i "access-control"

# Test wildcard
curl -skI "https://TARGET" -H "Origin: https://evil.com" 2>/dev/null | grep "Access-Control-Allow-Origin: \*"

# Test null origin
curl -skI "https://TARGET" -H "Origin: null" 2>/dev/null | grep -i "access-control"

# Test subdomain matching
curl -skI "https://TARGET" -H "Origin: https://evil.TARGET" 2>/dev/null | grep -i "access-control"

# Test with credentials
curl -skI "https://TARGET" -H "Origin: https://evil.com" 2>/dev/null | grep -i "access-control-allow-credentials"
```

## OPSEC Rules

- Only send 4-5 test requests total
- Do not fuzz Origin header variations
- Use a single session to avoid noise
- Do not test authenticated endpoints without authorization

## Verification

- Confirm the reflected Origin in the response body, not just headers
- Test if credentials are actually sent (Access-Control-Allow-Credentials: true)
- Verify the finding with a second request after 30+ seconds

## Pitfalls

- Some CDNs add default CORS headers
- Pre-flight (OPTIONS) responses may differ from actual (GET/POST)
- HSTS may complicate testing over HTTP
- Rate limiting on CORS endpoints is rare but possible

## Output Format

```
[CORS MISCONFIG] Origin: https://evil.com
  Access-Control-Allow-Origin: https://evil.com
  Access-Control-Allow-Credentials: true
  Severity: HIGH — reflected origin with credentials
```
