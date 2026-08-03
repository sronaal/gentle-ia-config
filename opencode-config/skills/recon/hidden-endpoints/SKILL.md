---
name: hidden-endpoints
description: Discover hidden API endpoints via fuzzing, JS mining, and archive analysis
version: 1.0.0
phase: recon
category: discovery
tags: [api, endpoints, discovery, fuzzing, wayback]
tools: [ffuf, gobuster, curl]
difficulty: intermediate
opsec_level: medium
time_estimate: 180s
severity_if_found: high
related_skills:
  - api-param-mining
  - source-leaks
  - tech-detection
mitre_attack:
  - T1595.001
  - T1595.004
  - T1589.003
---

## When to Use

Use this skill to discover unadvertised API endpoints, internal/admin interfaces,
alternative API versions, and development/staging endpoints. Hidden endpoints often
expose debug consoles, Swagger/OpenAPI docs, GraphQL interfaces, gRPC endpoints,
or internal microservices running on the same origin.

## Prerequisites

- ffuf (with API-specific wordlists — `secLists/Discovery/Web-Content/api/`)
- gobuster (alternative directory busting)
- curl
- Wayback Machine access (`curl https://web.archive.org`)
- Python 3 (for JS extraction, optional `getallurls` or `subjs`)

## Procedure

```bash
TARGET="https://target.com"
DOMAIN=$(echo "$TARGET" | sed 's|https\?://||; s|/.*||')

# 1. API endpoint fuzzing with targeted API wordlist
echo '=== API Endpoint Fuzzing ==='
ffuf -u "$TARGET/FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
     -t 30 \
     -c \
     -fc 400,404,403,500,502,503 \
     -mc 200,201,202,204,301,302,401,405 \
     -o ffuf_api.json

ffuf -u "$TARGET/FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -t 30 \
     -c \
     -fc 400,404,403,500,502,503 \
     -mc 200,201,202,204,301,302,401,405 \
     -o ffuf_api2.json

# 2. Common API version and prefix paths
echo '=== API Version & Prefix Fuzzing ==='
for prefix in api v1 v2 v3 v4 api/v1 api/v2 api/v3 \
              graphql gql rest public private internal \
              app backend service services gateway \
              swagger docs openapi documentation \
              admin manage management console dashboard \
              dev staging test sandbox playground \
              beta alpha edge preview; do
    code=$(curl -sko /dev/null -w "%{http_code}" "$TARGET/$prefix" 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
        size=$(curl -sko /dev/null -w "%{size_download}" "$TARGET/$prefix" 2>/dev/null)
        echo "[$code] /$prefix — ${size} bytes"
    fi
done

# 3. Swagger/OpenAPI endpoint discovery
echo '=== Swagger Discovery ==='
for path in swagger.json swagger/v1/swagger.json \
            api/swagger.json api/swagger/v1/swagger.json \
            api-docs api/docs api/documentation \
            openapi.json openapi.yaml \
            v1/api-docs v2/api-docs v3/api-docs \
            swagger-ui.html api/swagger-ui.html \
            swagger-resources; do
    code=$(curl -sko /dev/null -w "%{http_code}" "$TARGET/$path" 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
        echo "[$code] $path — verify for API docs"
    fi
done

# 4. Wayback Machine endpoint extraction
echo '=== Wayback Machine ==='
curl -sk "https://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=json&fl=original&collapse=urlkey" \
    2>/dev/null | jq -r '.[] | .[0] // empty' 2>/dev/null | sort -u | head -100 > wayback_urls.txt
echo "Extracted $(wc -l < wayback_urls.txt) unique URLs from Wayback Machine"

# Filter to API-relevant paths
grep -iE "(/api/|/v[0-9]/|graphql|\.json|\.do|\.action|/rest/|swagger|admin)" \
     wayback_urls.txt 2>/dev/null | sort -u > wayback_api_urls.txt
echo "API-relevant: $(wc -l < wayback_api_urls.txt)"

# 5. JS file endpoint mining
echo '=== JS File Endpoint Mining ==='
# Collect JS files from the target
ffuf -u "$TARGET/FUZZ" \
     -w /usr/share/seclists/Discovery/Web-Content/js-files.txt \
     -t 20 \
     -c \
     -fc 404 \
     -mc 200 \
     -e .js \
     -o ffuf_js.json 2>/dev/null

# Extract endpoints from JS files (basic grep)
js_endpoints=$(curl -sk "$TARGET" 2>/dev/null | grep -oP '(src|href)="[^"]+\.js"' | sed 's/.*"\(.*\)"/\1/')
for js in $js_endpoints; do
    echo "--- $js ---"
    curl -sk "$TARGET/$js" 2>/dev/null | grep -oP '["'\'']/[a-zA-Z0-9_/.-]+["'\'']' | sort -u | head -20
done

# 6. Gobuster as alternative (if ffuf unavailable)
# gobuster dir -u "$TARGET" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -t 30

# 7. Common internal/admin endpoint checks
echo '=== Internal / Admin Endpoints ==='
for path in /internal /internal/api /internal/health /healthz /health \
            /metrics /info /status /ping /_internal /_debug \
            /actuator /actuator/health /actuator/info \
            /console /h2-console /druid/index.html \
            /api/admin /api/private /api/internal \
            /api/health /api/status /api/metrics \
            /.well-known/security.txt /.well-known/openid-configuration; do
    code=$(curl -sko /dev/null -w "%{http_code}" "$TARGET$path" 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
        echo "[$code] $path"
    fi
done
```

## OPSEC Rules

- Use ffuf with `-t 30` max — do not exceed moderate rate
- Skip Wayback Machine extraction if OPSEC level is `silent` (archive queries can be logged)
- JS file endpoint mining is passive but do not use aggressive JS scraping tools like `subjs` without authorization
- Do not access discovered `/internal/*` endpoints from an external perspective without scope approval
- Swagger/OpenAPI endpoints may require authentication or expose security schemes
- Avoid fuzzing on the main origin during peak hours to minimize noise

## Verification

- For each discovered endpoint, send a GET request and a POST request with a minimal JSON body
- Check if different HTTP methods produce different responses (method confusion)
- Verify Swagger/OpenAPI schemas — they often list every live endpoint
- Cross-reference Wayback endpoints against currently active endpoints
- For JS-found endpoints, confirm they are server-side (not just frontend routes)
- Check if the endpoint requires authentication — a 401/403 is still a valid finding
- Test discovered endpoints from a different IP/context to confirm accessibility

## Pitfalls

- Many modern SPAs use client-side routing — JS endpoints may be frontend-only routes
- Wayback URLs may be outdated or from different deployment stages
- 403 responses may be WAF blocks, not actual endpoint presence
- Swagger UI and Swagger JSON may be present on different paths
- Some API gateways return 404 for disabled endpoints even if they exist
- Wordlists from SecLists may miss framework-specific endpoints (e.g., Spring Actuator, Laravel Telescope)
- Internal endpoints returning 200 may be serving a frontend app at a misleading path

## Output Format

```
[ENDPOINT] /graphql — 200 (text/html)
  Endpoint: https://target.com/graphql
  Note: GET returns GraphQL Playground; POST accepts queries
  Severity: MEDIUM

[ENDPOINT] /api/internal/users — 401 (application/json)
  Endpoint: https://target.com/api/internal/users
  Note: Internal API accessible but requires auth
  Severity: HIGH — internal routing exposed

[SWAGGER] /api/swagger.json — 200 (4.2 KB)
  Endpoint: https://target.com/api/swagger.json
  Contains: 27 endpoints documented, including deprecated /v1/orders
  Severity: MEDIUM

[WAYBACK] 142 unique URLs found, 23 API-relevant
  Includes: /api/v2/admin/users, /api/v1/debug/clear-cache
  Severity: MEDIUM — reveals historical endpoints

[JS MINING] 3 internal endpoints extracted from app.bundle.js
  Endpoints: /api/internal/reports, /api/internal/config, /ws/admin
  Severity: HIGH
```
