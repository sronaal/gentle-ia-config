---
name: hardcoded-credentials
description: Hunt hardcoded passwords in HTML, JS, and API configs
version: 1.0.0
phase: recon
category: discovery
tags: [credentials, secrets, hardcoded, web, api]
tools: [curl, grep, gf]
difficulty: intermediate
opsec_level: low
time_estimate: 5m
severity_if_found: critical
related_skills:
  - js-secrets
  - cors-variants-deep
mitre_attack:
  - T1552
---

## When to Use

- Hunting plaintext credentials in client-side code
- Reviewing JavaScript bundles for API keys and secrets
- Checking configuration endpoints for hardcoded passwords
- Pre-auth credential discovery for initial access

## Prerequisites

- curl, grep, and gf (grep-fu) installed
- Access to target web application
- GF patterns (`go install github.com/tomnomnom/gf@latest`)

## Procedure

### 1. Spider JavaScript Files

```bash
curl -s "https://TARGET/" | grep -oP 'src="[^"]*\.js[^"]*"' | \
  sed 's/src="//;s/"//' > js_files.txt

while read -r js; do
  curl -s "https://TARGET$js" >> all_js.txt
done < js_files.txt
```

### 2. Password Pattern Search

```bash
grep -rni "password\|passwd\|pwd\|pass=" /tmp/target_files/ 2>/dev/null
grep -rni "api[_-]key\|apikey\|secret[_-]key\|access[_-]token" /tmp/target_files/ 2>/dev/null
grep -rni "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*" /tmp/target_files/ 2>/dev/null
```

### 3. GF Pattern Matching

```bash
curl -s "https://TARGET/" | grep -oP 'src="[^"]*"' | sed 's/src="//;s/"//' | \
  xargs -I{} curl -s "https://TARGET{}" | gf secrets

curl -s "https://TARGET/login.js" | gf passwords
curl -s "https://TARGET/api.js" | gf apikeys
```

### 4. HTML Form Default Values

```bash
curl -s "https://TARGET/login" | grep -i 'value="[^"]*"' | grep -iv "submit\|button\|checkbox"
```

### 5. Config Endpoint Discovery

```bash
for endpoint in "/config.json" "/api/config" "/env.js" "/config.js" \
  "/settings.json" "/.env" "/config.yml" "/app.config.js"; do
  STATUS=$(curl -sI "https://TARGET$endpoint" -o /dev/null -w "%{http_code}")
  [ "$STATUS" = "200" ] && echo "CONFIG: $endpoint"
done
curl -s "https://TARGET/config.json" 2>/dev/null | python3 -m json.tool 2>/dev/null
```

### 6. Source Code Comment Analysis

```bash
grep -rni "//.*password\|#.*password\|/\*.*password" /tmp/target_files/ 2>/dev/null
grep -rni "TODO.*password\|FIXME.*auth\|HACK.*cred" /tmp/target_files/ 2>/dev/null
```

### 7. Build Artifact Analysis

```bash
curl -s "https://TARGET/static/js/main.js.map" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for f in data.get('sources', []): print(f)
except: pass
"
```

## OPSEC Rules

- Only search PUBLICLY accessible files — do not bypass auth
- Do not attempt to USE discovered credentials during recon
- Document the EXACT location of found credentials
- Report critical findings immediately to engagement lead

## Verification

```bash
grep -i "password" /tmp/results.txt | grep -v "your_password_here\|changeme\|example"
```

## Pitfalls

- Minified JS makes grep unreliable — use deobfuscation tools
- Some "password" strings are field labels, not actual credentials
- Base64-encoded credentials may appear as "random" strings
- `.env` files may return 200 but be empty or rate-limited

## Output Format

```json
{
  "target": "https://TARGET",
  "credentials_found": [
    {"location": "login.js:42", "type": "api_key", "value": "sk-***"},
    {"location": "config.json", "type": "database_password", "value": "***"}
  ],
  "severity": "critical"
}
```
