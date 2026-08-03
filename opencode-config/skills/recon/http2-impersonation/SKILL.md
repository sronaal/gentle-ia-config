---
name: http2-impersonation
description: HTTP/2 header and SETTINGS frame impersonation for fingerprint bypass
version: 1.0.0
phase: recon
category: fingerprinting
tags: [http2, h2, impersonation, fingerprint, waf]
tools: [curl]
difficulty: advanced
opsec_level: high
time_estimate: 5m
severity_if_found: N/A
related_skills:
  - tls-fingerprint
  - stealth-browser
mitre_attack:
  - T1071
---

## When to Use

- WAF analyzing HTTP/2 fingerprint (SETTINGS frame, header order)
- Bypassing HTTP/2-based bot detection
- Target uses H2 fingerprinting for rate limiting

## Prerequisites

- curl with HTTP/2 support (`curl --version | grep http2`)
- Understanding of HTTP/2 protocol mechanics
- wireshark or nghttp for frame inspection

## Procedure

### 1. Check HTTP/2 Support

```bash
curl --version | grep -i "http2"
curl --http2 -sI "https://TARGET/" | head -3
```

### 2. Default HTTP/2 SETTINGS Fingerprint

```bash
curl --http2 -s "https://TARGET/" -o /dev/null -v 2>&1 | grep -i "settings"
```

### 3. Chrome HTTP/2 Impersonation

```bash
# Chrome 120: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
# MAX_CONCURRENT_STREAMS=1000, INITIAL_WINDOW_SIZE=6291456

curl --http2 -s "https://TARGET/" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "Cache-Control: max-age=0" \
  -H "Sec-CH-UA: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"" \
  -H "Sec-CH-UA-Mobile: ?0" \
  -H "Sec-CH-UA-Platform: \"Windows\"" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1" \
  -H "Upgrade-Insecure-Requests: 1"
```

### 4. Firefox HTTP/2 Impersonation

```bash
# Firefox 121: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
# MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=131072

curl --http2 -s "https://TARGET/" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "DNT: 1" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1"
```

### 5. Pseudo-Header Order Testing

```bash
# Chrome order: :method, :authority, :scheme, :path
# Firefox order: :method, :path, :authority, :scheme
nghttp -v --header-table-size=65536 "https://TARGET/"
```

### 6. WINDOW_SIZE Manipulation

```bash
curl --http2 -s "https://TARGET/" \
  --http2-window-size "2147483647" \
  -o /dev/null -w "HTTP Code: %{http_code}\n"
```

## OPSEC Rules

- Use HTTP/2 impersonation only when actively fingerprinted
- Do NOT combine with credential attacks
- Document which SETTINGS values bypassed detection
- Test against validation endpoints before targeting protected resources

## Verification

```bash
curl --http2 -sI "https://TARGET/" | grep -i "HTTP/2"
```

## Pitfalls

- Not all servers support HTTP/2 — test first
- SETTINGS are negotiated during TLS handshake — cannot change mid-connection
- Some WAFs inspect frame ordering, not just SETTINGS values
- curl may not support custom SETTINGS without impersonation libraries

## Output Format

```json
{
  "target": "https://TARGET",
  "http2_supported": true,
  "impersonation_target": "chrome-120",
  "settings_fingerprint": "matched",
  "waf_bypassed": true,
  "technique": "http2-impersonation"
}
```
