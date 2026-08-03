---
name: evasion-human-imitation
description: Generate human-like browser interaction patterns — mouse, scroll, typing, navigation — to avoid bot detection
version: 1.0.0
phase: recon
category: evasion
tags: [human, imitation, automation, stealth, behavior]
tools: [playwright, puppeteer, curl, python3]
difficulty: advanced
opsec_level: silent
time_estimate: 60s
severity_if_found: info
related_skills:
  - evasion-request-profiling
  - evasion-captcha-bypass
  - stealth-browser
mitre_attack:
  - T1595
  - T1059
---

## When to Use

Use this skill when the target has behavioral detection — bot scores, mouse movement tracking, scroll analysis, or timing-based heuristics that distinguish humans from automated tools. Essential for targets protected by reCAPTCHA v3, Akamai BOTMAN, PerimeterX, DataDome, or any JS-based bot detection that analyzes interaction patterns rather than just headers and IPs. Run this as a prerequisite before any skill that needs to interact with JavaScript-heavy applications.

## Prerequisites

- playwright installed (`pip install playwright && playwright install chromium`)
- python3 with `asyncio`, `random`, `math`, `time`, `json` modules
- puppeteer (alternative for Node.js environments)
- Target URL to test interaction patterns against
- Understanding of the target's bot detection level (from evasion-detection-test)

## Procedure

```bash
# 1. MOUSE MOVEMENT SIMULATION (Bezier Curves)
# Humans don't move mice in straight lines — simulate non-linear paths

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright
import random
import math

async def human_mouse_move(page, target_x, target_y):
    """Move mouse along a Bezier-like curve with human characteristics."""
    # Get current mouse position
    current_pos = await page.evaluate("({x: window.mouseX || 0, y: window.mouseY || 0})")

    start_x, start_y = current_pos["x"], current_pos["y"]
    steps = random.randint(15, 30)

    # Control points for Bezier curve (add curvature)
    cp1_x = start_x + (target_x - start_x) * 0.3 + random.randint(-40, 40)
    cp1_y = start_y + (target_y - start_y) * 0.2 + random.randint(-30, 30)
    cp2_x = start_x + (target_x - start_x) * 0.7 + random.randint(-40, 40)
    cp2_y = start_y + (target_y - start_y) * 0.8 + random.randint(-30, 30)

    for i in range(steps):
        t = i / steps
        # Cubic Bezier
        x = (1-t)**3 * start_x + 3*(1-t)**2*t * cp1_x + 3*(1-t)*t**2 * cp2_x + t**3 * target_x
        y = (1-t)**3 * start_y + 3*(1-t)**2*t * cp1_y + 3*(1-t)*t**2 * cp2_y + t**3 * target_y

        # Add micro-jitter (human hand tremor)
        x += random.gauss(0, 1.5)
        y += random.gauss(0, 1.5)

        await page.mouse.move(x, y)
        # Variable delay: faster in middle, slower at start/end
        delay = 5 + random.randint(2, 8)
        if i < 3 or i > steps - 4:
            delay += random.randint(3, 10)  # Slower at edges
        await asyncio.sleep(delay / 1000)

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        await page.set_viewport_size({"width": 1920, "height": 1080})
        await page.goto("https://TARGET", wait_until="networkidle")

        # Wait for page to fully render
        await asyncio.sleep(2)

        # Simulate mouse hovering over page elements
        elements = await page.query_selector_all("a, button, input, [onclick]")
        for el in elements[:5]:
            try:
                box = await el.bounding_box()
                if box:
                    # Move to a random point within the element
                    target_x = box["x"] + random.randint(0, int(box["width"]))
                    target_y = box["y"] + random.randint(0, int(box["height"]))
                    await human_mouse_move(page, target_x, target_y)
                    # Pause on element (human hover)
                    await asyncio.sleep(random.uniform(0.3, 1.0))
            except:
                pass

        await browser.close()

asyncio.run(main())
EOF

# 2. REALISTIC SCROLLING PATTERNS
# Humans scroll with variable speed, random stop points, and overshoot

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright
import random

async def human_scroll(page, target_scroll, viewport_height):
    """Scroll to a target position with human-like acceleration/deceleration."""
    current_scroll = await page.evaluate("window.scrollY")
    direction = 1 if target_scroll > current_scroll else -1
    distance = abs(target_scroll - current_scroll)

    # Break scroll into segments with pauses
    segments = random.randint(3, 8)
    segment_size = distance / segments

    for i in range(segments):
        segment_target = current_scroll + direction * segment_size * (i + 1)
        # Add overshoot (humans often scroll past target and come back)
        if i == segments - 1:
            overshoot = random.randint(50, 150)
            segment_target += direction * overshoot

        # Variable scroll speed (faster in middle of page, slower at top/bottom)
        speed = random.randint(50, 200)  # pixels per event
        await page.evaluate(f"window.scrollBy(0, {direction * speed})")

        # Random pause between scroll bursts
        pause = random.uniform(0.3, 1.5)
        if i == segments - 1:
            # Pause longer at destination (reading)
            pause += random.uniform(0.5, 2.0)
        await asyncio.sleep(pause)

    # Scroll back to correct if overshot
    if direction > 0:
        actual_scroll = await page.evaluate("window.scrollY")
        if actual_scroll > target_scroll + 50:
            await page.evaluate(f"window.scrollTo(0, {target_scroll})")

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        await page.set_viewport_size({"width": 1920, "height": 1080})
        await page.goto("https://TARGET", wait_until="networkidle")

        await asyncio.sleep(2)

        # Scroll to different page positions
        viewport_height = 1080
        page_height = await page.evaluate("document.body.scrollHeight")

        # Scroll to 25%
        await human_scroll(page, page_height * 0.25, viewport_height)
        await asyncio.sleep(random.uniform(2, 4))

        # Scroll to 50%
        await human_scroll(page, page_height * 0.50, viewport_height)
        await asyncio.sleep(random.uniform(2, 4))

        # Scroll to 75%
        await human_scroll(page, page_height * 0.75, viewport_height)
        await asyncio.sleep(random.uniform(1, 3))

        # Scroll back to top
        await human_scroll(page, 0, viewport_height)

        await browser.close()

asyncio.run(main())
EOF

# 3. REALISTIC FORM FILLING (Character-by-character)
# Humans type with variable speed, not instant paste

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright
import random

async def human_type(page, selector, text):
    """Type text character by character with human-like timing."""
    await page.click(selector)

    for char in text:
        # Variable delay between keystrokes
        if char in " .,!?;:":
            delay = random.uniform(0.15, 0.35)  # Pause after punctuation
        elif char.isupper():
            delay = random.uniform(0.08, 0.18)  # Shift key takes slightly longer
        else:
            delay = random.uniform(0.04, 0.12)  # Normal keystroke

        await page.keyboard.type(char, delay=delay)

        # Simulate occasional typos and corrections (1% chance)
        if random.random() < 0.01 and len(text) > 5:
            typo_char = random.choice("abcdefghijklmnopqrstuvwxyz")
            await page.keyboard.type(typo_char, delay=0.05)
            await asyncio.sleep(random.uniform(0.2, 0.5))
            await page.keyboard.press("Backspace")
            await asyncio.sleep(random.uniform(0.1, 0.2))
            await page.keyboard.type(char, delay=0.08)

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()
        await page.goto("https://TARGET/login", wait_until="networkidle")

        await asyncio.sleep(2)

        # Type username
        await human_type(page, 'input[name="username"]', "john.doe@example.com")
        await asyncio.sleep(random.uniform(0.5, 1.5))

        # Tab to next field (human-like)
        await page.keyboard.press("Tab")
        await asyncio.sleep(random.uniform(0.2, 0.5))

        # Type password
        await human_type(page, 'input[name="password"]', "MyS3cur3P@ss!")
        await asyncio.sleep(random.uniform(0.5, 1.0))

        # Click submit with human-like mouse movement
        submit_button = await page.query_selector('button[type="submit"]')
        if submit_button:
            box = await submit_button.bounding_box()
            if box:
                target_x = box["x"] + box["width"] / 2 + random.randint(-10, 10)
                target_y = box["y"] + box["height"] / 2 + random.randint(-5, 5)
                await page.mouse.move(target_x, target_y)
                await asyncio.sleep(random.uniform(0.1, 0.3))
                await page.mouse.click(target_x, target_y)

        await browser.close()

asyncio.run(main())
EOF

# 4. TAB SWITCHING BEHAVIOR
# Humans have multiple tabs open — simulate tab switching

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright
import random

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        context = await browser.new_context()

        # Open multiple tabs (human-like behavior)
        pages = []
        for url in ["https://google.com", "https://TARGET", "https://github.com"]:
            page = await context.new_page()
            await page.goto(url, wait_until="domcontentloaded")
            pages.append(page)
            await asyncio.sleep(random.uniform(0.5, 1.5))

        # Switch between tabs
        for _ in range(5):
            tab = random.choice(pages)
            await tab.bring_to_front()
            await asyncio.sleep(random.uniform(2, 5))

            # Do something in the foreground tab
            await tab.evaluate("window.scrollBy(0, 100)")
            await asyncio.sleep(random.uniform(0.5, 1.5))

        await browser.close()

asyncio.run(main())
EOF

# 5. BROWSER FINGERPRINT SPOOFING
# Override Canvas, WebGL, WebRTC, and font fingerprints

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            timezone_id="America/New_York",
            permissions=["geolocation"],
            geolocation={"latitude": 40.7128, "longitude": -74.0060},  # New York
        )

        # Add stealth scripts to override fingerprint APIs
        await context.add_init_script("""
            // Override WebGL vendor/renderer
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) return 'Intel Inc.';  // UNMASKED_VENDOR_WEBGL
                if (parameter === 37446) return 'Intel Iris OpenGL Engine';  // UNMASKED_RENDERER_WEBGL
                return getParameter.call(this, parameter);
            };

            // Override Canvas fingerprint (add constant noise)
            const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function(type) {
                const canvas = this;
                const context = canvas.getContext('2d');
                if (context) {
                    // Add invisible noise pixel that changes hash
                    const imageData = context.getImageData(0, 0, 1, 1);
                    imageData.data[0] = imageData.data[0] ^ 1;  // Flip LSB
                    context.putImageData(imageData, 0, 0);
                }
                return origToDataURL.call(this, type);
            };

            // Override navigator.webdriver
            Object.defineProperty(navigator, 'webdriver', { get: () => false });

            // Add realistic plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [
                    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
                    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
                ]
            });

            // Override languages
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        """)

        page = await context.new_page()
        await page.goto("https://TARGET", wait_until="networkidle")

        # Test fingerprint
        fingerprint = await page.evaluate("""
            () => ({
                webdriver: navigator.webdriver,
                languages: navigator.languages,
                platform: navigator.platform,
                hardwareConcurrency: navigator.hardwareConcurrency,
                deviceMemory: navigator.deviceMemory,
            })
        """)
        print(f"Fingerprint: {fingerprint}")

        await browser.close()

asyncio.run(main())
EOF

# 6. REALISTIC NAVIGATION PATTERNS
# Humans don't jump directly to target — simulate navigation flow

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright
import random

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()

        # Natural navigation flow: Search engine → Article → Target
        # Step 1: Go to search engine
        await page.goto("https://google.com", wait_until="networkidle")
        await asyncio.sleep(random.uniform(1, 3))

        # Step 2: Search for something related
        search_box = await page.query_selector('textarea[name="q"]')
        if search_box:
            await search_box.click()
            await asyncio.sleep(random.uniform(0.2, 0.5))

            # Type slowly
            search_terms = ["technology news", "api documentation", "developer tools"]
            for char in random.choice(search_terms):
                await page.keyboard.type(char, delay=random.randint(50, 120))
            await asyncio.sleep(random.uniform(0.5, 1.5))
            await page.keyboard.press("Enter")

        await asyncio.sleep(random.uniform(2, 4))

        # Step 3: Click through to a result
        results = await page.query_selector_all("a[jsname]")
        if results:
            random_result = random.choice(results[:5])
            try:
                await random_result.click()
                await asyncio.sleep(random.uniform(2, 4))
            except:
                pass

        # Step 4: Finally navigate to target
        await page.goto("https://TARGET", wait_until="networkidle")
        await asyncio.sleep(random.uniform(1, 3))

        await browser.close()

asyncio.run(main())
EOF

# 7. CURL WITH HUMAN-LIKE HEADERS (Low-fidelity imitation)
# For tools that can't use a real browser, mimic browser request patterns

curl -sk "https://TARGET/api/endpoint" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "Sec-Ch-Ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" \
  -H "Sec-Ch-Ua-Mobile: ?0" \
  -H "Sec-Ch-Ua-Platform: \"Windows\"" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Referer: https://google.com/" \
  --compressed

# 8. REFERER CHAIN SPOOFING
# Humans arrive via links — spoof a realistic referer chain

curl -sk "https://TARGET/page" \
  -H "Referer: https://www.google.com/search?q=site%3ATARGET+api+documentation" \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

curl -sk "https://TARGET/page" \
  -H "Referer: https://lobste.rs/s/abc123/interesting_article" \
  -A "Mozilla/5.0"

curl -sk "https://TARGET/page" \
  -H "Referer: https://twitter.com/someuser/status/123456789" \
  -A "Mozilla/5.0"

# 9. VIEWPORT AND DEVICE EMULATION
# Match viewport to common device profiles

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright

DEVICE_PROFILES = [
    {"width": 1920, "height": 1080, "deviceScaleFactor": 1},   # Desktop
    {"width": 1440, "height": 900, "deviceScaleFactor": 2},    # MacBook
    {"width": 1536, "height": 864, "deviceScaleFactor": 1},    # Standard laptop
    {"width": 390, "height": 844, "deviceScaleFactor": 3},     # iPhone 14
    {"width": 412, "height": 915, "deviceScaleFactor": 2.625}, # Pixel 7
]

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)

        profile = DEVICE_PROFILES[0]  # Start with desktop
        context = await browser.new_context(
            viewport={"width": profile["width"], "height": profile["height"]},
            device_scale_factor=profile["deviceScaleFactor"],
            is_mobile=False,
            has_touch=False,
        )

        page = await context.new_page()
        await page.goto("https://TARGET", wait_until="networkidle")
        print(f"Viewport: {profile['width']}x{profile['height']}")

        await asyncio.sleep(5)
        await browser.close()

asyncio.run(main())
EOF

# 10. RANDOM BROWSER LANGUAGE & TIMEZONE
# Vary language and timezone to match expected geographic profile

python3 << 'EOF'
import asyncio
from playwright.async_api import async_playwright
import random

PROFILES = [
    {"locale": "en-US", "timezone": "America/New_York"},
    {"locale": "en-GB", "timezone": "Europe/London"},
    {"locale": "de-DE", "timezone": "Europe/Berlin"},
    {"locale": "ja-JP", "timezone": "Asia/Tokyo"},
    {"locale": "pt-BR", "timezone": "America/Sao_Paulo"},
]

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)

        profile = random.choice(PROFILES)
        context = await browser.new_context(
            locale=profile["locale"],
            timezone_id=profile["timezone"],
        )

        page = await context.new_page()
        await page.goto("https://TARGET", wait_until="networkidle")

        detected = await page.evaluate("""
            () => ({
                locale: navigator.language,
                languages: navigator.languages,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            })
        """)
        print(f"Profile: {profile}")
        print(f"Detected: {detected}")

        await browser.close()

asyncio.run(main())
EOF
```

## OPSEC Rules

- Set `headless=False` for the first run to visually verify behavior looks natural — debugging headless failures is harder without visual feedback
- NEVER reuse the same behavioral profile across sessions — vary viewport, locale, timezone, and navigation patterns
- Canvas/WebGL fingerprint overrides can be detected by comparing `toDataURL` calls — test against `https://coveryourtracks.eff.org`
- Character-by-character typing produces a distinctive inter-key timing pattern that ML detectors can fingerprint — vary timing within realistic ranges
- Human scroll patterns from code still differ from real human scrolls — micro-pauses at random DOM elements help
- Browser fingerprint overrides must be applied via `add_init_script` BEFORE navigation — applying them after the page loads is too late
- reCAPTCHA v3 scores below 0.5 indicate bot detection — if detected, increase randomization and add more realistic delays

## Verification

- Test human imitation against `https://bot.sannysoft.com` or `https://coveryourtracks.eff.org` to verify fingerprint spoofing
- Verify that repeated runs produce different behavioral signatures (mouse paths, scroll speeds, typing cadence)
- Check that the target does NOT serve CAPTCHAs or JS challenges after the imitation sequence
- For form filling: verify the submitted form data is complete and correct despite the slow typing
- Compare session cookies received with and without human imitation — human-like sessions should get longer-lived cookies

## Pitfalls

- Headless browsers are detectable via `navigator.webdriver`, missing `chrome.runtime`, and absent `window.chrome` — all must be patched
- reCAPTCHA v3 uses ML that adapts to behavioral patterns over time — static imitation scripts become detectable after repeated use
- Mouse movement recording and replay can be detected via acceleration analysis (code-generated Bezier curves differ from real hand movement)
- Form autofill vs. character-by-character typing: autofill is faster but detectable; typing is realistic but slow for large forms
- Some bot detectors (Akamai, PerimeterX) use AI that identifies synthetic interaction patterns regardless of the imitation quality
- High-latency connections break timing-based imitation — delays should account for network latency to maintain natural inter-event intervals

## Output Format

```json
{
  "skill": "evasion-human-imitation",
  "target": "TARGET",
  "detection_level": "recaptcha_v3 | behavioral_ml | none",
  "techniques_applied": [
    "bezier_mouse_movement",
    "variable_scroll_pauses",
    "character_by_character_typing",
    "canvas_fingerprint_override",
    "realistic_referer_chain"
  ],
  "bot_score": 0.87,
  "session_cookies": {
    "cf_clearance": "abc123...",
    "session_id": "xyz789..."
  },
  "notes": "Behavioral bypass successful. reCAPTCHA v3 score improved from 0.3 to 0.87 with full imitation profile."
}
```
