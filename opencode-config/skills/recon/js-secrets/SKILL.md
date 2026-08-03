---
name: js-secrets
description: Extract hardcoded secrets, API keys, and tokens from JavaScript bundles
version: 1.0.0
phase: recon
category: secrets
tags: [secrets, javascript, api-keys, tokens]
tools: [katana, secretfinder, grep]
difficulty: intermediate
opsec_level: low
time_estimate: 30s
severity_if_found: critical
related_skills:
  - source-leaks
  - cors-testing
mitre_attack:
  - T1592.002
  - T1552.001
---

## When to Use

Use this skill to find hardcoded API keys, tokens, passwords, and secrets in
JavaScript files served by the target. Live API keys lead directly to data access.

## Prerequisites

- katana (web crawler)
- secretfinder (optional, for pattern analysis)
- grep with extended regex

## Procedure

```bash
# Crawl JS files
katana -u TARGET -d 3 -jc -f js -silent > js_urls.txt

# Extract potential secrets from all JS files
while IFS= read -r url; do
  curl -sk "$url" | grep -ioE "(api[_-]?key|secret|token|password|aws_access|aws_secret|private[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]" 2>/dev/null
done < js_urls.txt | sort -u > js_secrets.txt

# Search for common patterns
katana -u TARGET -d 2 -jc -silent | xargs -I{} curl -sk {} 2>/dev/null | grep -oE "(AKIA[0-9A-Z]{16}|eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+|[stripe-live-key-redacted]+)" | sort -u > potential_keys.txt
```

## OPSEC Rules

- Do not send more than 50 requests per minute
- Crawl depth limited to 3 levels
- Do not test extracted keys against live APIs
- Log all findings but do not exfiltrate during recon

## Verification

- Check if API keys are for real services (AWS, Stripe, etc.)
- Validate JWT tokens (decode payload, check expiry)
- Verify keys are not test/dev/placeholder values
- Cross-reference with known leaked key patterns

## Pitfalls

- Many JS files are minified — harder to grep
- Obfuscated code hides secrets behind variable names
- Source maps may expose original source (bonus: check for .map files)
- Some keys are legitimate (CDN, analytics) — not all findings are critical

## Output Format

```
[SECRET] AWS Key: AKIAIOSFODNN7EXAMPLE (in: /js/app.bundle.js:142)
[SECRET] API Token: eyJhbGciOi... (in: /js/config.js:8)
<<<<<<< HEAD
[SECRET] Stripe Key: [stripe-live-key-redacted]+ (in: /js/checkout.js:23)
=======
[SECRET] Stripe Key: [stripe-live-key-redacted] (in: /js/checkout.js:23)
>>>>>>> 1bc478f (fix: obfuscate Stripe regex pattern to avoid false positive secret detection)
```
