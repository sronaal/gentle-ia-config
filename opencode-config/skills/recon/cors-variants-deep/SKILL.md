---
name: cors-variants-deep
description: Test 8 CORS misconfiguration variants for credential theft
version: 1.0.0
phase: recon
category: discovery
tags: [cors, misconfiguration, credential-theft, web]
tools: [curl]
difficulty: intermediate
opsec_level: medium
time_estimate: 5m
severity_if_found: high
related_skills:
  - hardcoded-credentials
mitre_attack:
  - T1189
---

## When to Use

- Target has authentication (cookies, tokens)
- Testing CORS misconfigurations enabling cross-origin data theft
- Hunting reflected Origin in Access-Control-Allow-Origin

## Prerequisites

- Valid session cookie or auth token for the target
- curl installed

## Procedure

### 1. Baseline — Check Current CORS Headers

```bash
curl -sI -H "Origin: https://evil.com" "https://TARGET/api/userinfo" \
  | grep -i "access-control"
```

### 2. V1 — Null Origin Bypass

```bash
curl -sI -H "Origin: null" "https://TARGET/api/userinfo" \
  | grep -i "access-control-allow-origin"
```

### 3. V2 — Subdomain of Target

```bash
curl -sI -H "Origin: https://sub.TARGET.com" "https://TARGET/api/userinfo" \
  | grep -i "access-control"
```

### 4. V3 — Regex Bypass (Prefix Match)

```bash
curl -sI -H "Origin: https://TARGET.com.evil.com" "https://TARGET/api/userinfo" \
  | grep -i "access-control"
```

### 5. V4 — Protocol Downgrade

```bash
curl -sI -H "Origin: http://TARGET.com" "https://TARGET/api/userinfo" \
  | grep -i "access-control"
```

### 6. V5 — Special Characters in Domain

```bash
curl -sI -H "Origin: https://TARGET_.com" "https://TARGET/api/userinfo" \
  | grep -i "access-control"
curl -sI -H "Origin: https://TARGET-.com" "https://TARGET/api/userinfo" \
  | grep -i "access-control"
```

### 7. V6 — Reflected Origin with Credentials

```bash
curl -sv -H "Origin: https://evil.com" \
  -H "Cookie: session=TOKEN_HERE" \
  "https://TARGET/api/userinfo" 2>&1 | grep -E "access-control|set-cookie"
```

### 8. V7 — Trusted Third-Party Origin

```bash
curl -sI -H "Origin: https://accounts.google.com" "https://TARGET/api/userinfo" \
  | grep -i "access-control"
curl -sI -H "Origin: https://apis.google.com" "https://TARGET/api/userinfo" \
  | grep -i "access-control"
```

### 9. V8 — Wildcard with Credentials

```bash
curl -sv -H "Origin: https://evil.com" \
  -H "Cookie: session=TOKEN_HERE" \
  "https://TARGET/api/userinfo" 2>&1 \
  | grep "access-control-allow-credentials: true"
```

## OPSEC Rules

- Only test with your own session tokens, never harvest victim tokens
- Log all Origin values sent for audit trail
- Do not exfiltrate data during recon — prove the misconfig exists only

## Verification

```bash
for variant in "null" "https://evil.com" "http://TARGET.com"; do
  echo "Testing: $variant"
  curl -sI -H "Origin: $variant" "https://TARGET/api/userinfo" \
    | grep -i "access-control-allow-origin"
done
```

## Pitfalls

- Some apps only set CORS headers on specific API paths — test `/api/`, `/graphql`, `/rest/`
- `Access-Control-Allow-Origin: *` without credentials is NOT exploitable
- Timing matters — CORS may only be set after authentication
- CDN/proxy may strip CORS headers before they reach you

## Output Format

```json
{
  "target": "https://TARGET",
  "vulnerable_variants": ["V1-null", "V3-regex"],
  "acao_reflected": "https://evil.com",
  "acac_enabled": true,
  "exploitable": true,
  "severity": "high"
}
```
