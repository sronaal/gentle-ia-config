---
name: api-version-detect
description: Detect API versions via headers, URL patterns, and response bodies
version: 1.0.0
phase: recon
category: fingerprinting
tags: [api, versioning, discovery, fingerprinting]
tools: [curl, httpx]
difficulty: basic
opsec_level: low
time_estimate: 30s
severity_if_found: medium
related_skills:
  - hidden-endpoints
  - tech-detection
mitre_attack:
  - T1595.001
  - T1592.002
---

## When to Use

Use this skill to identify which API versions are exposed on a target. Deprecated
API versions often lack security fixes, use outdated auth schemes, or expose
additional attack surface. Version detection also guides subsequent exploitation
by narrowing framework and protocol specifics.

## Prerequisites

- curl
- httpx (optional)
- Access to the target's API base URL

## Procedure

```bash
TARGET="https://api.target.com"

# 1. Check common API version header patterns
echo "=== Version Headers ==="
curl -skI "$TARGET/api/v1" 2>/dev/null | grep -iE "^(x-api-version|api-version|version|accept):"
curl -skI "$TARGET/api/v2" 2>/dev/null | grep -iE "^(x-api-version|api-version|version|accept):"
curl -skI "$TARGET/api/v3" 2>/dev/null | grep -iE "^(x-api-version|api-version|version|accept):"

# 2. Probe URL-based versioning paths
echo "=== URL Version Probe ==="
for ver in v1 v2 v3 v1.0 v2.0 v3.0 1 2 3 latest stable beta alpha; do
    code=$(curl -sko /dev/null -w "%{http_code}" "$TARGET/api/$ver" 2>/dev/null)
    echo "api/$ver → $code"
done

# 3. Check Accept header versioning (content negotiation)
echo "=== Accept Header Versioning ==="
for ver in "application/vnd.api+json" \
           "application/vnd.api.v1+json" \
           "application/vnd.api.v2+json" \
           "application/vnd.api.v3+json" \
           "application/vnd.target.v1+json" \
           "application/vnd.target.v2+json"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Accept: $ver" "$TARGET/api" 2>/dev/null)
    echo "Accept: $ver → $code"
done

# 4. Detect version info in response body
echo "=== Response Body Version Strings ==="
curl -sk "$TARGET/api" 2>/dev/null | grep -ioE '"(version|apiVersion|api_version)"[[:space:]]*:[[:space:]]*"[^"]+"'
curl -sk "$TARGET/api" 2>/dev/null | grep -ioE 'v[0-9]+\.[0-9]+(\.[0-9]+)?'

# 5. Deprecated version enumeration
echo "=== Deprecated / Old Versions ==="
for path in v0 v0.9 v0.1 v0.2 v1.1 v3 v4 2018-01-01 2019-06-01 2020-01-01; do
    code=$(curl -sko /dev/null -w "%{http_code}" "$TARGET/api/$path" 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
        echo "[LIVE] api/$path → $code"
    fi
done

# 6. Quick httpx tech-detect sweep on versioned paths
httpx -u "$TARGET/api/v1" -u "$TARGET/api/v2" -u "$TARGET/api/v3" -tech-detect -silent 2>/dev/null
```

## OPSEC Rules

- All requests in this skill are standard HTTP probes — low detection risk
- Use a single User-Agent consistent with the target baseline
- Do not send authenticated requests during version probing
- Keep a delay of 1s between deprecated-version checks to avoid rate limiting

## Verification

- Confirm version differentiation: a 200 vs 404 between v1 and v2 confirms versioned routing
- Check if deprecated versions return different headers or lack security headers
- For Accept-version findings, verify with a single request showing different response bodies
- Test if older versions still use HTTP (not HTTPS) or lack HSTS
- Cross-reference version strings found in response bodies with known CVE databases

## Pitfalls

- 404 responses may be disguised as 200 in API gateways (custom error JSON)
- Some APIs use date-based versioning (e.g., `/api/2023-01-01`) — check if applicable
- Version headers may be stripped by CDN or reverse proxies
- Multiple versioning schemes can coexist on the same API
- A "deprecated" header may only appear after the first authenticated request
- GraphQL APIs typically use a single versionless endpoint — version detection differs

## Output Format

```
[API VERSION] v1 — active (200)
  Headers: x-api-version: 1.0.3
  Deprecated header present: true
  Security: Missing HSTS, CSP
  Endpoint: https://api.target.com/api/v1

[API VERSION] v2 — active (200)
  Headers: x-api-version: 2.4.1
  Deprecated header: absent
  Security: HSTS, CSP present
  Endpoint: https://api.target.com/api/v2

[DEPRECATED] v0 — accessible (200)
  Endpoint: https://api.target.com/api/v0
  Risk: Outdated auth scheme (Basic auth still accepted)
```
