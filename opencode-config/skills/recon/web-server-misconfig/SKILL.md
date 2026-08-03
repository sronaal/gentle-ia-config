---
name: web-server-misconfig
description: Detect web server misconfigurations and information disclosure
version: 1.0.0
phase: recon
category: misconfiguration
tags: [web, misconfiguration, information-disclosure, security-headers]
tools: [nmap, curl, testssl.sh]
difficulty: intermediate
opsec_level: medium
time_estimate: 60s
severity_if_found: high
related_skills:
  - hidden-endpoints
  - source-leaks
mitre_attack:
  - T1595.001
  - T1592.002
  - T1589.001
---

## When to Use

Use this skill to identify common web server misconfigurations that lead to
information disclosure or unauthorized access. Exposed `.git` directories, `.env`
files, directory listing, permissive HTTP methods, verbose server headers, and
missing security headers are frequent findings that enable further exploitation.

## Prerequisites

- nmap (for HTTP method scan via `http-methods` NSE)
- curl
- testssl.sh (optional — for TLS configuration checks)

## Procedure

```bash
TARGET="https://target.com"
DOMAIN=$(echo "$TARGET" | sed 's|https\?://||; s|/.*||')

# 1. Sensitive file discovery — .git, .env, backup files, config dumps
echo '=== Sensitive File Disclosure ==='
for path in .git/config .env .env.example .env.bak \
            .gitignore .htaccess config.json config.php \
            wp-config.php wp-config.bak \
            backup.sql dump.sql database.sql \
            admin/.env admin/config.php \
            .aws/credentials .s3cfg \
            composer.json package.json \
            phpinfo.php info.php test.php \
            crossdomain.xml clientaccesspolicy.xml \
            robots.txt sitemap.xml; do
    status=$(curl -sko /dev/null -w "%{http_code}" "$TARGET/$path" 2>/dev/null)
    if [ "$status" != "404" ] && [ "$status" != "403" ] && [ "$status" != "000" ]; then
        size=$(curl -sk -o /dev/null -w "%{size_download}" "$TARGET/$path" 2>/dev/null)
        echo "[FOUND] $path — HTTP $status — ${size} bytes"
        [ "$status" = "200" ] && curl -sk "$TARGET/$path" | head -c 200
        echo "---"
    fi
done

# 2. Directory listing detection
echo '=== Directory Listing ==='
for dir in / /admin/ /assets/ /uploads/ /backup/ /logs/ /tmp/ /images/ /css/ /js/; do
    resp=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$dir" 2>/dev/null)
    if [ "$resp" = "200" ]; then
        content=$(curl -sk "$TARGET$dir" 2>/dev/null)
        if echo "$content" | grep -qiE "(index of|directory listing|parent directory|<title>Index of)" 2>/dev/null; then
            echo "[DIR LISTING] $dir — Index of listing enabled"
        fi
    fi
done

# 3. HTTP methods (PUT, DELETE, TRACE, PATCH)
echo '=== HTTP Methods ==='
nmap --script http-methods --script-args http-methods.url-path=/ -p 443 "$DOMAIN" 2>/dev/null
# Also test manually
for method in PUT DELETE TRACE OPTIONS PATCH; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X "$method" "$TARGET/" 2>/dev/null)
    echo "$method / → $code"
    if [ "$method" = "PUT" ] && [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
        echo "[PUT ENABLED] Test upload: curl -sk -X PUT -d 'test' $TARGET/test_upload.txt"
    fi
    if [ "$method" = "DELETE" ] && [ "$code" = "200" ] || [ "$code" = "204" ]; then
        echo "[DELETE ENABLED] May allow resource deletion"
    fi
done

# 4. Server header information disclosure
echo '=== Server Information Disclosure ==='
curl -skI "$TARGET" 2>/dev/null | grep -iE "^server:|^x-powered-by|^x-aspnet-version|^x-runtime|^x-rack-cache|^via:|^x-served-by|^x-backend|^x-cache:"
# Detailed via nmap
nmap --script http-headers -p 443 "$DOMAIN" 2>/dev/null | grep -iE "(server|x-powered|x-aspnet)"

# 5. Missing security headers check
echo '=== Security Headers Audit ==='
headers_needed=(
    "Strict-Transport-Security"
    "Content-Security-Policy"
    "X-Content-Type-Options"
    "X-Frame-Options"
    "X-XSS-Protection"
    "Referrer-Policy"
    "Permissions-Policy"
    "Access-Control-Allow-Origin"
)
all_headers=$(curl -skI "$TARGET" 2>/dev/null)
for header in "${headers_needed[@]}"; do
    if echo "$all_headers" | grep -qi "^$header:"; then
        echo "[PRESENT] $header"
    else
        echo "[MISSING] $header"
    fi
done

# 6. Default credential check on common interfaces
echo '=== Default Credential Checks ==='
for path in /admin /manager /console /phpmyadmin /pgadmin /adminer /wp-admin /admin/login; do
    status=$(curl -sko /dev/null -w "%{http_code}" "$TARGET$path" 2>/dev/null)
    [ "$status" != "404" ] && [ "$status" != "000" ] && echo "[ACCESSIBLE] $path — HTTP $status"
done

# 7. Optional: TLS misconfiguration scan
if command -v testssl.sh &> /dev/null; then
    echo '=== TLS Configuration ==='
    testssl.sh --quiet --fast "$TARGET" 2>/dev/null | grep -iE "(WARN|finding|vuln|weak)" | head -5
fi
```

## OPSEC Rules

- Sensitive file checks (`.git`, `.env`) are passive — single GET requests each
- Directory listing checks target only obvious paths — do not fuzz
- HTTP method check uses a single OPTIONS request per endpoint
- Default credential paths are checked only for existence, never submitted credentials
- nmap scripts `http-methods` and `http-headers` are non-intrusive
- Remove test files immediately if PUT upload is successful
- Do NOT .git clone an exposed repository — that is exfiltration

## Verification

- For `.git` exposures, verify with `curl -sk "$TARGET/.git/HEAD"` — should return `ref: refs/heads/main`
- For `.env` exposures, confirm it contains sensitive keys (DB_PASSWORD, API_KEY, etc.)
- For directory listing, confirm actual filenames are listed (not just a default page)
- For PUT method, verify a real file can be created and deleted after testing
- For missing headers, confirm at browser level (some headers are stripped by curl)
- Cross-verify security headers with https://securityheaders.com
- Default credential pages should be verified against known vendor defaults

## Pitfalls

- Cloudflare and other CDNs strip or modify server headers — server info may be unreliable
- 403 on `.git/HEAD` does NOT mean `.git` is absent — try `.git/config` with different paths
- Directory listing may be disabled for GET but enabled for other HTTP methods
- PUT may be allowed for specific content types (XML vs JSON)
- Security headers may only appear on authenticated responses
- testssl.sh may trigger WAF if the target has request inspection
- A 404 response for `.env` may come from the auth layer, not the web server

## Output Format

```
[SENSITIVE FILE] .git/HEAD exposed (200, 23 bytes)
  URL: https://target.com/.git/HEAD
  Content: ref: refs/heads/main
  Severity: HIGH — full repository can be downloaded

[SENSITIVE FILE] .env.example exposed (200, 412 bytes)
  URL: https://target.com/.env.example
  Contains: DB_HOST, DB_USER placeholders
  Severity: MEDIUM — reveals environment structure

[DIR LISTING] /backups/ — Index of /backups
  Files: db_dump_2024-01.sql, config_old.php
  Severity: HIGH — data exposure

[MISCONFIG] PUT method enabled on /
  Risk: Arbitrary file upload — unauthorized content creation
  Severity: HIGH

[SECURITY HEADERS] Missing:
  - Content-Security-Policy
  - Permissions-Policy
  Severity: LOW — no immediate exploit but weakens client-side security
```
