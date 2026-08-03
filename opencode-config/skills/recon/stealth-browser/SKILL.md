---
name: stealth-browser
description: Browser fingerprint evasion and TLS/HTTP2 impersonation
version: 1.0.0
phase: recon
category: fingerprinting
tags: [stealth, browser, fingerprint, tls, evasion]
tools: [curl, python3]
difficulty: advanced
opsec_level: high
time_estimate: 5m
severity_if_found: N/A
related_skills:
  - tls-fingerprint
  - http2-impersonation
mitre_attack:
  - T1071
---

## When to Use

- WAF/CDN blocking automated requests
- Need to bypass TLS fingerprinting (JA3/JA4)
- Evading bot detection during reconnaissance

## Prerequisites

- curl-impersonate or curl with TLS modification
- Python3 with requests library

## Procedure

### 1. Check Current TLS Fingerprint

```bash
curl -s "https://ja3er.com/getjson/TARGET_HOST" | python3 -m json.tool 2>/dev/null
nmap --script ssl-enum-ciphers -p 443 TARGET
```

### 2. curl-impersonate Installation

```bash
# Docker
docker run --rm curlimages/curl-impersonate curl-impersonate-chrome "https://TARGET"

# Binary
wget https://github.com/lwthiker/curl-impersonate/releases/download/v0.6.1/curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz
tar xzf curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz
```

### 3. Chrome TLS Impersonation

```bash
curl-impersonate-chrome -s "https://TARGET/" \
  --tlsv1.3 --ciphers TLS_AES_128_GCM_SHA256

curl-impersonate-chrome --http2 -s "https://TARGET/" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
```

### 4. Firefox TLS Impersonation

```bash
curl-impersonate-firefox -s "https://TARGET/" \
  --tlsv1.3 --ciphers TLS_AES_256_GCM_SHA384
```

### 5. Python Requests with Custom TLS

```bash
python3 << 'EOF'
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

class TLSFingerprintAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM')
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

session = requests.Session()
session.mount('https://', TLSFingerprintAdapter())
resp = session.get('https://TARGET/', headers={
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
})
print(resp.status_code)
EOF
```

### 6. HTTP/2 Settings Impersonation

```bash
curl-impersonate-chrome --http2 -s "https://TARGET/" \
  -H "Sec-CH-UA: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"" \
  -H "Sec-CH-UA-Mobile: ?0" \
  -H "Sec-CH-UA-Platform: \"Windows\""
```

## OPSEC Rules

- Use impersonation only when actively blocked by WAF
- Rotate TLS fingerprints across requests
- Do NOT use impersonation for credential stuffing or brute force
- Document which fingerprint worked for audit trail

## Verification

```bash
curl-impersonate-chrome -s "https://ja3er.com/getjson/TARGET_HOST" | \
  python3 -m json.tool 2>/dev/null
```

## Pitfalls

- curl-impersonate may not be available in default repos
- Some WAFs check more than TLS fingerprint (HTTP/2 settings, header order)
- JA3 hashes are not unique per browser version
- Cloudflare uses multiple detection layers

## Output Format

```json
{
  "target": "https://TARGET",
  "original_ja3": "abc123...",
  "impersonated_ja3": "def456...",
  "waf_bypassed": true,
  "fingerprint_used": "chrome-120",
  "technique": "tls-impersonation"
}
```
