---
name: tls-fingerprint
description: TLS fingerprint impersonation to bypass JA3/JA4 detection
version: 1.0.0
phase: recon
category: fingerprinting
tags: [tls, ja3, ja4, fingerprint, impersonation]
tools: [curl, curl-impersonate]
difficulty: advanced
opsec_level: high
time_estimate: 5m
severity_if_found: N/A
related_skills:
  - stealth-browser
  - http2-impersonation
mitre_attack:
  - T1071
---

## When to Use

- WAF blocking based on JA3/JA4 TLS fingerprint
- Need to impersonate Chrome, Firefox, or Safari TLS handshake
- Bypassing Cloudflare Bot Management or similar

## Prerequisites

- curl-impersonate installed
- Understanding of TLS fingerprinting concepts
- Access to ja3er.com or similar validation service

## Procedure

### 1. Baseline TLS Fingerprint

```bash
# Get current JA3 hash
curl -s "https://ja3er.com/" > /dev/null && \
  curl -s "https://TARGET/" -o /dev/null -w "JA3: %{ssl_ja3_hash}\n"
```

### 2. Chrome 120 Fingerprint

```bash
# Chrome 120 on Windows 10
curl-impersonate-chrome -s "https://TARGET/" \
  --ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 \
  --http2 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
```

### 3. Firefox 121 Fingerprint

```bash
# Firefox 121 on Windows 10
curl-impersonate-firefox -s "https://TARGET/" \
  --ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256 \
  --http2 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
```

### 4. Safari 17 Fingerprint

```bash
# Safari 17 on macOS
curl-impersonate-safari -s "https://TARGET/" \
  --ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 \
  --http2 \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
```

### 5. Validate Fingerprint Change

```bash
# Test against JA3 validation service
for impersonate in "chrome" "firefox" "safari"; do
  echo "Testing: $impersonate"
  curl-impersonate-$impersonate -s "https://ja3er.com/getjson/$(curl-impersonate-$impersonate -s -o /dev/null -w '%{url_effective}' https://TARGET/)" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f'JA3: {d.get(\"ja3_hash\",\"unknown\")}')" 2>/dev/null
done
```

### 6. Custom TLS Configuration

```bash
# Custom cipher list for specific fingerprint
curl-impersonate-chrome -s "https://TARGET/" \
  --tlsv1.3 \
  --ciphers "TLS_AES_128_GCM_SHA256" \
  --curves "X25519:P-256:P-384" \
  --sigalgs "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256"
```

## OPSEC Rules

- Rotate fingerprints across requests to avoid pattern detection
- Do NOT use impersonation for attacks (brute force, credential stuffing)
- Document which fingerprint bypassed which WAF
- Use impersonation sparingly — multiple fingerprints from same IP is suspicious

## Verification

```bash
# Confirm TLS fingerprint matches expected browser
curl-impersonate-chrome -s "https://TARGET/" -o /dev/null \
  -w "HTTP Code: %{http_code}\nTLS Version: %{ssl_version}\n"
```

## Pitfalls

- JA3 hashes are not unique per browser — many browsers share hashes
- Some WAFs use JA4 or custom fingerprinting beyond JA3
- HTTP/2 SETTINGS frame must match browser for full impersonation
- TLS extension order matters — curl-impersonate handles this automatically

## Output Format

```json
{
  "target": "https://TARGET",
  "impersonation_target": "chrome-120",
  "ja3_before": "original_hash",
  "ja3_after": "impersonated_hash",
  "waf_bypassed": true,
  "technique": "tls-fingerprint-impersonation"
}
```
