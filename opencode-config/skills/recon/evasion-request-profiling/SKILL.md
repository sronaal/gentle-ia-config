---
name: evasion-request-profiling
description: Profile and customize request patterns to match legitimate traffic and avoid detection signatures
version: 1.0.0
phase: recon
category: evasion
tags: [profiling, scanning, stealth, detection-signature]
tools: [curl, python3, nmap]
difficulty: advanced
opsec_level: silent
time_estimate: 120s
severity_if_found: info
related_skills:
  - evasion-detection-test
  - evasion-human-imitation
  - evasion-ip-rotation
mitre_attack:
  - T1595
  - T1046
  - T1036
---

## When to Use

Use this skill to analyze what YOUR requests look like to the target and reshape them to blend in with legitimate traffic. Every automated tool leaves a detectable fingerprint — this skill teaches you to see your own request profile, understand what the target expects to see, and transform your scanning traffic so it cannot be distinguished from normal user behavior. Run this at the start of every engagement after `evasion-detection-test` to establish your stealth baseline.

## Prerequisites

- curl with verbose output and header inspection
- python3 with `requests`, `socket`, `ssl`, `random`, `statistics`, `json` modules
- nmap for port-based profiling
- Access to the target's public-facing endpoints
- A test endpoint at a known-good service (e.g., httpbin.org) for request fingerprint analysis

## Procedure

```bash
# 1. REQUEST FINGERPRINT ANALYSIS
# See exactly what your request looks like to any server

# Capture your full request fingerprint
curl -sk "https://httpbin.org/anything" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  | python3 -m json.tool

# View what headers the target receives from your default curl
curl -skI "https://TARGET" -v 2>&1 | grep "^>" | sed 's/^> //'

# 2. TLS FINGERPRINT ANALYSIS
# TLS handshake identifies your client more accurately than User-Agent
# Compare TLS fingerprints across tools

# Curl's TLS fingerprint
nmap --script ssl-enum-ciphers -p 443 TARGET 2>/dev/null | head -20

# Python requests TLS fingerprint
python3 << 'EOF'
import requests
import ssl

# Check TLS version and cipher preferences
context = ssl.create_default_context()
print(f"Protocol: {context.protocol}")
print(f"Minimum TLS version: {context.minimum_version}")
print(f"Maximum TLS version: {context.maximum_version}")
print(f"Ciphers: {context.get_ciphers()[:3]}")

# Verify against target
resp = requests.get("https://TARGET", timeout=10)
print(f"\nConnection: {resp.connection}")
EOF

# 3. TARGET TRAFFIC PATTERN ANALYSIS
# What does legitimate traffic to the target look like?

# Analyze homepage — what resources does a normal browser request?
python3 << 'EOF'
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

target = "https://TARGET"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

resp = requests.get(target, headers=headers, timeout=10)
soup = BeautifulSoup(resp.text, "html.parser")

# Analyze resource types
resources = {"scripts": [], "styles": [], "images": [], "fonts": [], "other": []}
for tag in soup.find_all(["script", "link", "img", "source"]):
    src = tag.get("src") or tag.get("href") or ""
    if src:
        full_url = urljoin(target, src)
        if tag.name == "script":
            resources["scripts"].append(full_url)
        elif tag.name == "link" and "stylesheet" in tag.get("rel", []):
            resources["styles"].append(full_url)
        elif tag.name == "img":
            resources["images"].append(full_url)

print(f"Scripts: {len(resources['scripts'])}")
print(f"Styles: {len(resources['styles'])}")
print(f"Images: {len(resources['images'])}")

# Check for JavaScript frameworks
frameworks = []
if "react" in resp.text: frameworks.append("React")
if "vue" in resp.text: frameworks.append("Vue")
if "angular" in resp.text: frameworks.append("Angular")
if "jquery" in resp.text: frameworks.append("jQuery")
if frameworks:
    print(f"Frameworks detected: {', '.join(frameworks)}")
EOF

# 4. TIME-BASED PROFILING
# When are real users active? Scan during off-peak or match business hours

python3 << 'EOF'
import datetime
import random

# Current time
now = datetime.datetime.now()
print(f"Current time: {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")

# Determine if we're in target's business hours
# Adjust to target timezone
target_tz_hours = {
    "US/Eastern": now.hour - 5 if now.utcoffset() else now.hour,
    "Europe/London": now.hour - 0 if now.utcoffset() else now.hour,
    "Asia/Tokyo": now.hour + 9 if now.utcoffset() else now.hour,
}

print("Target timezone business hour analysis:")
for tz, hour in target_tz_hours.items():
    hour_adjusted = hour % 24
    in_business = 8 <= hour_adjusted <= 18
    print(f"  {tz}: {hour_adjusted:02d}:00 — {'BUSINESS HOURS (blend in)' if in_business else 'OFF-PEAK (lower noise)'}")

# Recommended scan time
if 8 <= now.hour <= 18:
    print("\nRecommendation: Scan during business hours to blend with legitimate traffic")
else:
    print("\nRecommendation: Off-peak scanning — lower chance of active monitoring")
EOF

# 5. REFERER CHAIN SPOOFING
# Scan traffic should appear to arrive via legitimate paths

python3 << 'EOF'
import requests
import random

target = "https://TARGET"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

# Realistic referers based on target industry
referer_profiles = {
    "technology": [
        "https://www.google.com/search?q=api+documentation+" + target.replace("https://", ""),
        "https://news.ycombinator.com/item?id=" + str(random.randint(10000000, 99999999)),
        "https://github.com/search?q=" + target.replace("https://", ""),
        "https://stackoverflow.com/questions/" + str(random.randint(1000000, 9999999)),
        "https://twitter.com/search?q=" + target.replace("https://", ""),
    ],
    "general": [
        "https://www.google.com/",
        "https://duckduckgo.com/",
        "https://lobste.rs/",
        "https://www.reddit.com/r/programming/",
    ]
}

industry = "technology"  # Adjust based on target
referers = referer_profiles.get(industry, referer_profiles["general"])

for i, referer in enumerate(referers[:4]):
    headers["Referer"] = referer
    resp = requests.get(target, headers=headers, timeout=10)
    print(f"[{i + 1}] Referer: {referer[:50]}... → HTTP {resp.status_code}")
EOF

# 6. ACCEPT-HEADER PROFILING
# Match Accept headers to target's content type expectations

python3 << 'EOF'
import requests

target = "https://TARGET/api/endpoint"  # Replace with actual endpoint

# Test different Accept header profiles
accept_profiles = [
    # Browser HTML request
    {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
    # API client
    {"Accept": "application/json, text/plain, */*"},
    # Fetch/XHR
    {"Accept": "*/*"},
    # Minimal
    {"Accept": "text/html"},
    # Image
    {"Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"},
]

headers = {"User-Agent": "Mozilla/5.0"}

for profile in accept_profiles:
    combined = {**headers, **profile}
    resp = requests.get(target, headers=combined, timeout=10)
    content_type = resp.headers.get("Content-Type", "?").split(";")[0]
    print(f"Accept: {profile['Accept'][:40]}... → HTTP {resp.status_code} Content-Type: {content_type}")
EOF

# 7. REQUEST FREQUENCY NORMALIZATION
# Match real user traffic patterns — not bursty automation

python3 << 'EOF'
import requests
import time
import random
import statistics

target = "https://TARGET"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Real user traffic patterns (avg 3-8s between requests on the same domain)
DELAY_MEAN = 5.0    # Average human delay between pages
DELAY_STD = 2.5     # Standard deviation
MIN_DELAY = 1.0     # Absolute minimum delay (even fast readers need 1s)

print("Simulating human-paced scanning...")
for i in range(10):
    # Gaussian delay around human mean
    delay = max(MIN_DELAY, random.gauss(DELAY_MEAN, DELAY_STD))
    time.sleep(delay)

    resp = requests.get(target, headers=headers, timeout=10)
    print(f"[{i + 1}] HTTP {resp.status_code} (delayed {delay:.1f}s)")

# Compare with burst pattern (detectable)
print("\n--- Timing Analysis ---")
human_delays = [max(MIN_DELAY, random.gauss(DELAY_MEAN, DELAY_STD)) for _ in range(100)]
burst_delays = [random.uniform(0.05, 0.2) for _ in range(100)]  # Automation pattern

print(f"Human pattern:  mean={statistics.mean(human_delays):.2f}s stdev={statistics.stdev(human_delays):.2f}s")
print(f"Burst pattern:  mean={statistics.mean(burst_delays):.2f}s stdev={statistics.stdev(burst_delays):.2f}s")
print(f"Recommendation: Use human pattern — burst pattern is a TOP detection signature")
EOF

# 8. DISTRIBUTED SCANNING OVER TIME
# Spread scanning across hours/days to avoid temporal correlation

python3 << 'EOF'
import time
import random

# Phase distribution strategy
total_endpoints = 100
time_window_hours = 4
seconds_per_endpoint = (time_window_hours * 3600) / total_endpoints

print(f"Scanning {total_endpoints} endpoints over {time_window_hours} hours")
print(f"Average interval: {seconds_per_endpoint:.1f}s between requests")
print(f"With jitter range: {seconds_per_endpoint * 0.5:.1f}s - {seconds_per_endpoint * 1.5:.1f}s")

# Distribute across hours (not continuous scanning)
for hour in range(1, time_window_hours + 1):
    endpoints_this_hour = total_endpoints // time_window_hours
    print(f"Hour {hour}: {endpoints_this_hour} endpoints (pause between batches)")

    for i in range(endpoints_this_hour):
        delay = random.uniform(
            seconds_per_endpoint * 0.5,
            seconds_per_endpoint * 1.5
        )
        # Don't actually sleep in profiling mode — just display
        print(f"  Request {i + 1}: delay {delay:.1f}s")

    # Between-hour pause (simulate lunch, meeting, etc.)
    between_hour_pause = random.uniform(120, 600)
    print(f"  → Hour break: {between_hour_pause:.0f}s pause\n")
EOF

# 9. CONNECTION REUSE STRATEGY
# Decide: persistent connections (browser-like) vs new connections (scanner-like)

python3 << 'EOF'
import requests
import time
import socket

target = "https://TARGET"
headers = {"User-Agent": "Mozilla/5.0"}

# Strategy A: Connection reuse (HTTP Keep-Alive — browser-like)
print("Strategy A: Connection reuse (HTTP Keep-Alive)")
session = requests.Session()
start = time.time()
for i in range(10):
    resp = session.get(target, headers=headers, timeout=10)
    print(f"  [{i + 1}] HTTP {resp.status_code}")
print(f"  Total: {time.time() - start:.2f}s (single TCP connection)\n")

# Strategy B: New connection per request (scanner-like)
print("Strategy B: New connection per request")
start = time.time()
for i in range(10):
    resp = requests.get(target, headers=headers, timeout=10)
    print(f"  [{i + 1}] HTTP {resp.status_code}")
print(f"  Total: {time.time() - start:.2f}s (new TCP connection per request)\n")

# Strategy C: Connection pooling with rotation
print("Strategy C: Pooled with periodic refresh")
# Best balance: reuse within a page load, new connection for new pages
# Use session for related requests, close and reopen for different endpoints
EOF

# 10. SCAN ORDER RANDOMIZATION
# Sequential IP/port scanning is a dead giveaway — randomize everything

python3 << 'EOF'
import random

# Before: sequential (detectable)
sequential_ports = list(range(1, 1025))
print("Sequential (BAD):", sequential_ports[:10], "...")

# After: randomized (stealthy)
random_ports = list(range(1, 1025))
random.shuffle(random_ports)
print("Randomized (GOOD):", random_ports[:10], "...")

# Same for subdomains, endpoints, parameters
endpoints = ["/admin", "/api", "/login", "/wp-admin", "/.env", "/backup", "/config", "/debug"]
random.shuffle(endpoints)
print(f"Randomized endpoints: {endpoints}")

# For large scans: randomize scan order across entire target set
targets = ["admin.TARGET", "api.TARGET", "dev.TARGET", "mail.TARGET", "www.TARGET"]
port_ranges = [22, 80, 443, 8080, 8443, 3306, 5432]
scan_queue = [(t, p) for t in targets for p in port_ranges]
random.shuffle(scan_queue)
print(f"\nScan queue (randomized, first 8 of {len(scan_queue)}):")
for t, p in scan_queue[:8]:
    print(f"  {t}:{p}")
EOF

# 11. NOISE INJECTION
# Interleave real scanning with legitimate traffic lookalikes

python3 << 'EOF'
import requests
import time
import random

target = "https://TARGET"
headers = {"User-Agent": "Mozilla/5.0"}

# Ratio: for every 3 real requests, send 1 noise request
REAL_RATIO = 3
NOISE_RATIO = 1

# Noise requests look like legitimate browsing
noise_endpoints = [
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/js/",
    "/css/",
    "/images/",
]

for batch in range(5):
    # Real scanning requests
    for i in range(REAL_RATIO):
        resp = requests.get(f"{target}/api/users?page={batch * REAL_RATIO + i}",
                          headers=headers, timeout=10)
        print(f"[REAL  {i + 1}] HTTP {resp.status_code}")
        time.sleep(random.uniform(2.0, 4.0))

    # Noise injection
    for i in range(NOISE_RATIO):
        noise_url = f"{target}{random.choice(noise_endpoints)}"
        resp = requests.get(noise_url, headers={
            **headers,
            "Referer": "https://www.google.com/",
        }, timeout=10)
        print(f"[NOISE {i + 1}] HTTP {resp.status_code} (blended)")
        time.sleep(random.uniform(2.0, 4.0))

    # Between-batch pause (natural break)
    pause = random.uniform(30, 120)
    print(f"Batch {batch + 1} complete. Pausing {pause:.0f}s...\n")
    time.sleep(pause)
EOF

# 12. MATCHING TARGET'S EXPECTED CLIENT PROFILE
# Different targets expect different client characteristics

python3 << 'EOF'
import requests
import json

target = "https://TARGET"

# Profile: WordPress site
curl -sk https://TARGET -o /dev/null -w "Server: %{content_type}\n" 2>/dev/null
# If WordPress: send requests that look like WordPress visitors
# (includes wp-content, wp-includes paths in referer, etc.)

# Profile: Single-page app (React/Vue)
# Send XHR-like requests with appropriate headers
spa_headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, text/plain, */*",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://TARGET/app",
}

resp = requests.get(f"{target}/api/data", headers=spa_headers, timeout=10)
print(f"SPA-style API request: HTTP {resp.status_code}")

# Profile: REST API client
# Send requests that look like a legitimate API consumer
api_headers = {
    "User-Agent": "MyApp/1.0 (Integration Client)",
    "Accept": "application/json",
    "Authorization": "Bearer eyJ..."  # Use dummy token if available
}

resp = requests.get(f"{target}/v2/users", headers=api_headers, timeout=10)
print(f"API-client-style request: HTTP {resp.status_code}")

# Profile: Search engine bot
bot_headers = {
    "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Accept": "text/html,application/xhtml+xml",
    "From": "googlebot(at)googlebot.com",
}

resp = requests.get(f"{target}/sitemap.xml", headers=bot_headers, timeout=10)
print(f"Googlebot-style request: HTTP {resp.status_code}")
EOF

# 13. nmap PROFILING
# nmap has a distinct fingerprint — customize it

# Before: stock nmap (easily detected)
sudo nmap -sS -p 80,443 TARGET -T 4 --max-retries 3 2>/dev/null

# After: profiled nmap (blended)
# --source-port to mimic common services
# -T 2 for slower scanning (like normal traffic)
# --data-length to vary packet size (avoid fixed-size fingerprint)
# --ttl to match common OS TTL values
sudo nmap -sS -p 80,443 TARGET \
  -T 2 \
  --max-retries 1 \
  --max-scan-delay 1s \
  --source-port 53 \
  --data-length 100 \
  --ttl 128 \
  -f \
  2>/dev/null

# Use decoy scanning to blend with other traffic
sudo nmap -sS -p 80,443 TARGET -D RND:5 --max-retries 1 -T 2 2>/dev/null
```

## OPSEC Rules

- Profile your own traffic FIRST using httpbin.org or similar before any target interaction — know what you look like before trying to change it
- NEVER use the same request profile for more than one phase — recon requests look different from exploit requests (different headers, timing, referers)
- Business-hours scanning blends better but faces more active monitoring; off-peak faces less monitoring but traffic is more anomalous
- Noise injection endpoints (robots.txt, favicon.ico) should match the target's actual noise pattern — don't request static assets if the target is an API
- TLS fingerprint is the hardest profile aspect to change — curl, python-requests, and Go each have unique TLS handshake signatures
- Scan order randomization is the single highest-impact change you can make for evasion — sequential scanning is the #1 detection pattern

## Verification

- Verify your modified request profile against `https://httpbin.org/anything` — confirm the target receives the headers you intend
- Check that randomized scan order does NOT contain detectable patterns (sequential substrings, increasing port numbers)
- Confirm noise injection requests are indistinguishable from real user traffic (correct Accept headers, no security-related paths)
- Test the profiled request against the target and compare response with a "clean" baseline — no 403, 429, or CAPTCHA responses
- For nmap: verify decoy scanning doesn't reveal your real IP in the target's connection logs

## Pitfalls

- TLS fingerprinting is nearly impossible to spoof without modifying the TLS library itself — curl, Chrome, and Firefox each have unique JA3 fingerprints
- Googlebot User-Agent without a matching IP in Google's ASN range is trivially detected — only use bot headers when you understand the verification mechanism
- Request randomization must be truly random (using `random.shuffle`), not sequential or time-sorted — session-level patterns are analyzed
- Cloud WAFs (Cloudflare, AWS WAF) keep behavioral profiles across IPs — randomizing per request creates a "non-human" pattern that WAF ML detects
- Connection reuse (Keep-Alive) is detectable at the load balancer level — persistent connections from a tool that also rotates IPs creates a contradiction
- Adding too many noise requests dilutes scanning efficiency without improving stealth — 1:4 noise-to-real ratio is optimal

## Output Format

```json
{
  "skill": "evasion-request-profiling",
  "target": "TARGET",
  "fingerprint": {
    "tls": "curl-8.0",
    "http_headers": ["accept-encoding", "user-agent", "host"],
    "tcp_window": 65535,
    "ttl": 64
  },
  "target_profile": {
    "platform": "react_spa | wordpress | api",
    "expected_clients": ["chrome_120", "firefox_121", "mobile_safari"],
    "business_hours_utc": "13:00-21:00",
    "noise_pattern": "/static/*, /api/v1/*",
    "cdn": "cloudflare | akamai | none"
  },
  "techniques_applied": [
    "randomized_scan_order",
    "referer_chain_spoofing",
    "request_frequency_normalization",
    "noise_injection",
    "tls_fingerprint_awareness"
  ],
  "effectiveness": {
    "detection_reduction_percent": 85,
    "requests_before_block": 500,
    "requests_before_captcha": 200
  },
  "notes": "Matching target's SPA API client profile yielded 500+ requests without triggering rate limits or CAPTCHAs."
}
```
