---
name: api-param-mining
description: Discover hidden API parameters via fuzzing, bruteforce, and comparison
version: 1.0.0
phase: recon
category: discovery
tags: [api, parameters, fuzzing, discovery]
tools: [ffuf, curl, arjun]
difficulty: intermediate
opsec_level: medium
time_estimate: 120s
severity_if_found: high
related_skills:
  - hidden-endpoints
  - source-leaks
mitre_attack:
  - T1595.004
  - T1589.003
---

## When to Use

Use this skill to discover undocumented or hidden API parameters that may enable
privilege escalation, IDOR bypass, or feature gates. Hidden parameters like `?admin=true`,
`?debug=1`, or `?internal_id=` often expose backend functionality not intended for
public consumption.

## Prerequisites

- ffuf (with a parameter wordlist — e.g., `secLists/Discovery/Web-Content/burp-parameter-names.txt`)
- arjun (optional — Python-based parameter bruteforce)
- curl
- At least one known API endpoint on the target

## Procedure

```bash
TARGET="https://api.target.com/endpoint"
WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"

# 1. Parameter fuzzing with ffuf — discover valid parameters via response-size diff
ffuf -u "$TARGET?FUZZ=test" \
     -w "$WORDLIST" \
     -t 20 \
     -c \
     -fc 400,404,500 \
     -mc 200,201,202,301,302 \
     -o ffuf_params.json

# 2. Arjun parameter bruteforce — detects params even when they return 200 by default
arjun -u "$TARGET" \
      -oT arjun_params.json \
      --stable \
      --passive

# 3. Parameter comparison — test known endpoint with and without each discovered param
curl -sk "$TARGET" -o response_baseline.json
while IFS= read -r param; do
    curl -sk "$TARGET?${param}=true" -o "response_${param}.json"
    if ! diff -q response_baseline.json "response_${param}.json" > /dev/null 2>&1; then
        echo "[PARAM ALTERS RESPONSE] $param"
    fi
done < discovered_params.txt

# 4. Hidden parameter value fuzzing — try common values for discovered params
ffuf -u "$TARGET?admin=FUZZ" \
     -w /usr/share/seclists/Fuzzing/big.txt \
     -t 20 \
     -c \
     -fc 400,404,403,500

# 5. POST body parameter testing (JSON)
curl -sk -X POST "$TARGET" \
     -H "Content-Type: application/json" \
     -d '{"known_param": "value", "hidden_param": "test"}' \
     -o response_hidden.json
```

## OPSEC Rules

- Limit ffuf threads to 20 (`-t 20`) to avoid request flooding
- Ignore 400/404/403/500 responses to reduce false-positive noise
- For Arjun, use `--stable` mode to pace requests
- Do not use `-ac` (auto-calibration) on authenticated endpoints — it may trigger alerts
- Stop fuzzing if WAF error pages appear; switch to passive parameter mining instead

## Verification

- Send each discovered parameter individually and compare response bodies
- Test both `?param=true` and `?param=false` — behavior may differ
- Check for parameters that accept JSON arrays or nested objects (mass assignment risk)
- Verify hidden parameters on POST endpoints by adding them to the request body
- Re-test discovered parameters across multiple endpoints — they may be global

## Pitfalls

- Parameter names in SecLists may be outdated or miss modern frameworks
- Arjun can produce false positives — always manually verify each finding
- Some APIs ignore unknown parameters silently — a 200 response is not proof of validity
- WAF/CDN may return different responses to fuzzed requests vs. legitimate ones
- Parameter pollution (HPP) can give false positives when multiple params are interpreted
- Rate limiting may kick in during longer fuzzing sessions — pace requests

## Output Format

```
[PARAM FOUND] debug (type: switch)
  Endpoint: https://api.target.com/admin/users
  Behavior: ?debug=true returns verbose error messages
  Confidence: HIGH

[PARAM FOUND] internal_id (type: value)
  Endpoint: https://api.target.com/api/v2/orders
  Behavior: ?internal_id=INT-2024-001 returns order outside user scope
  Confidence: MEDIUM — requires auth context verification

[ARJUN] 3 new params: page_size, sort_by, include_archived
  Endpoint: https://api.target.com/api/v2/products
```
