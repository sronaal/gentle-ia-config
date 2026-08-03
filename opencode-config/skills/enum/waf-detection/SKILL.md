---
name: waf-detection
description: Web Application Firewall detection and fingerprinting
version: 1.0.0
phase: enum
category: web
tags: [waf, firewall, bypass, fingerprinting]
tools: [wafw00f, curl]
difficulty: basic
opsec_level: low
time_estimate: 60s
severity_if_found: info
related_skills:
  - dir-busting
  - api-discovery
mitre_attack:
  - T1592.002
---

## When to Use

Use this skill to detect if a Web Application Firewall is in front of the
target and identify its type for potential bypass opportunities.

## Prerequisites

- wafw00f
- curl

## Procedure

```bash
# Step 1: Automated WAF detection
wafw00f https://TARGET -o wafw00f_output.txt -f json -v

# Step 2: Manual detection — check response headers
curl -sk -I https://TARGET/ | grep -iE "server|x-|cf-|via|x-waf"

# Step 3: Trigger WAF with benign payloads
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/?id=1' OR '1'='1"
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/?q=<script>alert(1)</script>"
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/?file=../../etc/passwd"

# Step 4: Check WAF response patterns
curl -sk "https://TARGET/?id=<script>" -D - | head -20

# Step 5: Fingerprint specific WAFs
# Cloudflare
curl -sk -I https://TARGET/ | grep -i "cf-ray"
# AWS WAF
curl -sk -I https://TARGET/ | grep -i "x-amzn"
# Akamai
curl -sk -I https://TARGET/ | grep -i "x-akamai"
# Imperva
curl -sk -I https://TARGET/ | grep -i "x-iinfo"

# Step 6: Check for WAF bypass indicators
curl -sk -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 127.0.0.1" "https://TARGET/"

# Step 7: Detect rate limiting
for i in $(seq 1 20); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/?i=$i")
  echo "$i → $code"
done
```

## OPSEC Rules

- Do NOT send large volumes of attack payloads
- Limit trigger requests to 5 per detection
- Do not attempt WAF bypass without authorization
- Log all responses for documentation
- WAFs may block your IP after detection attempts

## Verification

- Confirm WAF type matches wafw00f output
- Verify response codes indicate blocking (403/406/429)
- Check if headers match known WAF signatures

## Pitfalls

- Some WAFs only block specific attack types
- CDN may mask the actual WAF behind it
- WAF detection may trigger false positives
- Rate limiting may block your IP mid-scan

## Output Format

```
[WAF]     Detected: Cloudflare (CF-RAY header present)
[WAF]     Status: Active — blocks SQLi, XSS
[WAF]     Response codes: 403 (blocked), 200 (allowed)
[INFO]    WAF may be bypassable via HTTP/2 or origin IP
[INFO]    No rate limiting detected on /api endpoint
```
