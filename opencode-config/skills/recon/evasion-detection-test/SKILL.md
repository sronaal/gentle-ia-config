---
name: evasion-detection-test
description: Test if you are being detected, blocked, or inspected by the target's defensive controls
version: 1.0.0
phase: recon
category: evasion
tags: [detection, healthcheck, opsec, blocking]
tools: [curl, nmap, python3]
difficulty: intermediate
opsec_level: covert
time_estimate: 60s
severity_if_found: info
related_skills:
  - evasion-request-profiling
  - hunt-waf-bypass
mitre_attack:
  - T1595
  - T1046
---

## When to Use

Use this skill before launching any active scanning or exploitation to determine whether the target is actively monitoring, blocking, or inspecting your traffic. Establishes a baseline of what "normal" looks like from your source and detects WAF, IPS, rate-limiting, TCP blocking, JS challenges, or traffic inspection. Run this at the start of every engagement from each source IP/network you plan to use.

## Prerequisites

- curl, nmap, python3 installed
- Target domain or IP
- A known-good baseline endpoint (e.g., google.com) on the same network for comparison
- Multiple User-Agent strings prepared

## Procedure

```bash
# 1. BASELINE RESPONSE COMPARISON
# Compare response times and sizes between target and control

# Record control baseline (known-good host)
curl -sI -o /dev/null -w "HTTP %{http_code} Time: %{time_total}s Size: %{size_download}\n" \
  https://example.com -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# Record target baseline
curl -sI -o /dev/null -w "HTTP %{http_code} Time: %{time_total}s Size: %{size_download}\n" \
  https://TARGET -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# Compare response body sizes — identical sized responses may indicate a block page
curl -s https://TARGET | wc -c
curl -s https://TARGET/login | wc -c
curl -s https://TARGET/nonexistent-path-12345 | wc -c

# 2. WAF TRIGGER DETECTION
# Send known attack strings and compare response with baseline

# SQL injection pattern — watch for different status code, size, or RST
curl -sk "https://TARGET/?id=1%27%20OR%201=1--" -o /dev/null -w "SQLi probe: HTTP %{http_code} Time: %{time_total}s Size: %{size_download}\n"

# XSS pattern
curl -sk "https://TARGET/?q=%3Cscript%3Ealert(1)%3C/script%3E" -o /dev/null -w "XSS probe: HTTP %{http_code} Time: %{time_total}s Size: %{size_download}\n"

# Directory traversal
curl -sk "https://TARGET/?file=../../../etc/passwd" -o /dev/null -w "Path traversal: HTTP %{http_code} Time: %{time_total}s Size: %{size_download}\n"

# 3. DNS RESOLUTION ANOMALIES
# DNS can reveal blocking before HTTP does

dig TARGET +short
dig TARGET A +short @1.1.1.1
dig TARGET A +short @8.8.8.8

# Compare against expected IP — if resolution returns different IPs per resolver, NXDOMAIN,
# or sinkhole IPs (0.0.0.0, 127.0.0.x, 10.x.x.x), you may be DNS-blocked
python3 -c "
import dns.resolver
for ns in ['1.1.1.1', '8.8.8.8', '9.9.9.9']:
    try:
        answers = dns.resolver.resolve('TARGET', 'A', nameservers=[ns])
        print(f'{ns}: {answers[0]}')
    except Exception as e:
        print(f'{ns}: BLOCKED — {e}')
"

# 4. TCP RST vs SYN-ACK ANALYSIS
# RST responses to SYN probes indicate active TCP blocking

sudo nmap -sS -p 80,443,8080 TARGET --max-retries 1 --max-rtt-timeout 500ms 2>&1 | grep -E "(open|filtered|closed)"

# Compare against a SYN scan with decoy IP — if your real IP gets RST while decoys
# get SYN-ACK, the target is blocking your specific source
sudo nmap -sS -p 80,443 TARGET -D RND:3 --max-retries 1 2>&1

# 5. CAPTCHA / JS CHALLENGE DETECTION
# Check for Cloudflare, Akamai, or other JS challenge pages

curl -sk https://TARGET -o /tmp/target_response.html
grep -qi "cloudflare" /tmp/target_response.html && echo "⚠ Cloudflare detected"
grep -qi "cdn-cgi" /tmp/target_response.html && echo "⚠ Cloudflare challenge detected"
grep -qi "just a moment" /tmp/target_response.html && echo "⚠ JS challenge (Cloudflare) detected"
grep -qi "captcha" /tmp/target_response.html && echo "⚠ CAPTCHA wall detected"
grep -qi "window.__cf" /tmp/target_response.html && echo "⚠ Cloudflare JS challenge detected"
grep -qi "g-recaptcha" /tmp/target_response.html && echo "⚠ reCAPTCHA detected"

# 6. LOGIN PAGE vs REAL LOGIN PAGE COMPARISON
# WAFs often rewrite login pages — compare direct vs proxied

curl -sk https://TARGET/login -o /tmp/login_direct.html
python3 -c "
import hashlib
with open('/tmp/login_direct.html', 'rb') as f:
    print('Login page hash:', hashlib.md5(f.read()).hexdigest())
"

# Compare with a different User-Agent or path
curl -sk https://TARGET/login \
  -H "User-Agent: curl/8.0" -o /tmp/login_curl.html
diff /tmp/login_direct.html /tmp/login_curl.html && echo "IDENTICAL — responses are generic, possibly WAF-generated" || echo "DIFFERENT — real login page is being served"

# 7. IP REPUTATION CHECK
# Check if your source IP is flagged

curl -s https://whatismyipaddress.com/blacklist-check 2>/dev/null || \
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$(curl -s ifconfig.me)" 2>/dev/null || \
echo "Manual: check IP at https://www.virustotal.com or https://www.abuseipdb.com"

# 8. TIMING ANALYSIS
# Increased response times often indicate traffic inspection (proxies, IPS, SSL inspection)

python3 << 'EOF'
import time
import subprocess
import statistics

def time_request(url):
    start = time.time()
    try:
        subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{time_total}", url],
            capture_output=True, text=True, timeout=10
        )
    except:
        pass

# Run 5 requests and measure variance
timings = []
for i in range(5):
    start = time.time()
    result = subprocess.run(
        ["curl", "-sk", "-o", "/dev/null", "-w", "%{time_total}",
         "https://TARGET", "-A", "Mozilla/5.0"],
        capture_output=True, text=True, timeout=10
    )
    elapsed = float(result.stdout.strip())
    timings.append(elapsed)
    time.sleep(0.5)

print(f"Target timings: min={min(timings):.3f}s max={max(timings):.3f}s "
      f"mean={statistics.mean(timings):.3f}s stdev={statistics.stdev(timings):.3f}s")
print(f"Variance: {max(timings) - min(timings):.3f}s — "
      f"{'HIGH (>1s variance = likely inspection)' if max(timings)-min(timings) > 1 else 'NORMAL'}")

# Compare with control host
control_timings = []
for i in range(5):
    start = time.time()
    result = subprocess.run(
        ["curl", "-sk", "-o", "/dev/null", "-w", "%{time_total}",
         "https://example.com", "-A", "Mozilla/5.0"],
        capture_output=True, text=True, timeout=10
    )
    elapsed = float(result.stdout.strip())
    control_timings.append(elapsed)
    time.sleep(0.5)

print(f"Control timings: min={min(control_timings):.3f}s max={max(control_timings):.3f}s "
      f"mean={statistics.mean(control_timings):.3f}s")
ratio = statistics.mean(timings) / statistics.mean(control_timings)
print(f"Target/Control ratio: {ratio:.2f}x — "
      f"{'HIGH (>3x = deep packet inspection likely)' if ratio > 3 else 'NORMAL'}")
EOF

# 9. USER-AGENT SENSITIVITY TEST
# Compare responses across different User-Agents to detect UA-based filtering

for ua in \
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1" \
  "curl/8.0" \
  "python-requests/2.31.0" \
  "Go-http-client/2.0"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET" -A "$ua")
  size=$(curl -sk -o /dev/null -w "%{size_download}" "https://TARGET" -A "$ua")
  echo "UA: $(echo $ua | cut -c1-40)... → HTTP $code Size: $size"
done

# 10. HTTP/S PROTOCOL SENSITIVITY
# Compare HTTP/1.0, HTTP/1.1, and HTTP/2 responses

curl -sk --http1.0 -o /dev/null -w "HTTP/1.0: %{http_code} %{time_total}s\n" https://TARGET
curl -sk --http1.1 -o /dev/null -w "HTTP/1.1: %{http_code} %{time_total}s\n" https://TARGET
curl -sk --http2   -o /dev/null -w "HTTP/2:   %{http_code} %{time_total}s\n" https://TARGET
```

## OPSEC Rules

- Run detection tests from the SAME source IP/network you will use for the actual engagement — detection status is per-source
- Do NOT send exploit payloads during this test — use innocuous-but-suspicious patterns (SQLi/XSS probes without actual exploitation intent)
- Use a minimum 2-second delay between test requests to avoid rate-limit triggers
- If WAF detection is confirmed, stop active probing and switch to passive techniques
- Document all baseline metrics before proceeding to other skills — they become your "clean" reference
- Do not run this more than once per session per target to avoid alerting threshold accumulation

## Verification

- Confirm detection status by cross-referencing at least 2 independent indicators (e.g., timing + response size + DNS)
- A SINGLE anomalous indicator is inconclusive — require at least 2 different tests pointing in the same direction
- If blocking is suspected, verify from a DIFFERENT source IP (Tor exit, VPN, cloud VM) to confirm it's IP-based vs. account-based
- Re-test after changing User-Agent, source IP, or using a different protocol (HTTP/1.0 vs HTTP/2)

## Pitfalls

- CDN edge caches return inconsistent results — warm the cache with a clean request first
- Some WAFs delay responses selectively (only on known-bad patterns) — timing analysis must use exploit patterns, not just clean URLs
- Response size comparison alone is unreliable — WAFs sometimes inject invisible elements (beacons, tracking pixels) that change size
- Cloudflare's "I'm Under Attack" mode blocks ALL curl-based probing — distinguish this from per-IP blocking
- High latency networks can produce false positives in timing analysis — always compare against a control host on the same network path
- Some WAFs serve different responses based on geolocation — test from multiple regions

## Output Format

```json
{
  "skill": "evasion-detection-test",
  "target": "TARGET",
  "source_ip": "x.x.x.x",
  "detection_status": "clean | blocked | inspected | waf_detected | js_challenge | captcha",
  "indicators": [
    {
      "test": "baseline_comparison",
      "baseline_size": 12345,
      "block_page_size": 456,
      "anomalous": true
    },
    {
      "test": "timing_analysis",
      "target_mean": 1.234,
      "control_mean": 0.456,
      "ratio": 2.71,
      "anomalous": false
    }
  ],
  "summary": "No detection indicators found — target responses are consistent with baseline",
  "recommendation": "Proceed with OPSEC_level: silent source, re-test every 30 minutes"
}
```
