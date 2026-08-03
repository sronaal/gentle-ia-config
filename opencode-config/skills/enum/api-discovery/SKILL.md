---
name: api-discovery
description: Discover and enumerate API endpoints and documentation
version: 1.0.0
phase: enum
category: web
tags: [api, endpoints, graphql, swagger]
tools: [ffuf, arjun, Kiterunner]
difficulty: intermediate
opsec_level: medium
time_estimate: 90s
severity_if_found: medium
related_skills:
  - dir-busting
  - hunt-idor-api
mitre_attack:
  - T1592.002
  - T1046
---

## When to Use

Use this skill to find API endpoints, documentation (Swagger/OpenAPI), GraphQL
endpoints, and REST APIs. Undocumented endpoints are prime exploitation targets.

## Prerequisites

- ffuf with API wordlist
- arjun (parameter discovery)
- Kiterunner (API endpoint discovery)

## Procedure

```bash
# Discover API paths
ffuf -u https://TARGET/api/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,401,403

# Discover API parameters
arjun -u https://TARGET/api/endpoint -m JSON

# Kiterunner for API route discovery
kr scan TARGET -w routes-large.kite -x 20 -o kr_results.json

# Check common API documentation paths
for path in "swagger.json" "openapi.json" "api-docs" "graphql" ".well-known/openapi" "swagger-ui.html"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$path")
  echo "$code /$path"
done
```

## OPSEC Rules

- Rate limit to 20 requests per second
- Do not fuzz API parameters without authorization
- Log all requests for audit trail
- Do not send malicious payloads during discovery

## Verification

- Manually test discovered endpoints with valid requests
- Verify API documentation matches actual endpoints
- Check if authentication is required for discovered endpoints

## Pitfalls

- API endpoints may require authentication tokens
- GraphQL introspection may be disabled
- Rate limiting may trigger after a few requests
- Some APIs use non-standard paths

## Output Format

```
[API] GET /api/v1/users — 401 (auth required)
[API] POST /api/v1/login — 200
[DOC] /swagger.json — 200 (OpenAPI 3.0)
[GRAPHQL] /graphql — 200 (introspection enabled)
```
