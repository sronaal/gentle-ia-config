---
name: screen-capture
description: Capture evidence screenshots — PoC proof for findings, authenticated page shots, desktop capture from compromised hosts, and report-ready compilation with annotations
version: 1.0.0
phase: report
category: documentation
tags: [screenshot, evidence, report, puppeteer, playwright, gowitness]
tools: [gowitness, shot-scraper, playwright, curl]
difficulty: intermediate
opsec_level: low
time_estimate: 120s
severity_if_found: info
related_skills:
  - visual-recon
  - generate-report
  - evidence-vault
mitre_attack: []
---

## When to Use

- After confirming a vulnerability — capture PoC screenshot for the report
- Before closing a finding — document the evidence with visual proof
- After post-exploitation — capture desktop, configs, or data screenshots from compromised hosts
- When generating the final report — compile all evidence into a single annotated document

## Prerequisites

- Chromium/Chrome installed (`playwright install chromium` or `apt install chromium-browser`)
- gowitness (`go install github.com/sensepost/gowitness@latest`)
- shot-scraper (`pip install shot-scraper`) or `npx shot-scraper`
- For desktop capture: `scrot`, `gnome-screenshot`, or `import` (ImageMagick) on Linux

## Procedure

### 1. Single PoC Screenshot (authenticated or unauthenticated)

```bash
# shot-scraper — quick PoC
shot-scraper "https://TARGET/admin" -o finding-xss-poc.png
shot-scraper "https://TARGET/vuln?q=<script>alert(1)</script>" -o xss-reflected.png --wait 2000

# shot-scraper with auth cookie
shot-scraper "https://TARGET/admin" -o admin-panel.png --cookie "session=COOKIE_VALUE"

# gowitness for bulk PoC
gowitness screenshot --url "https://TARGET/sqli?q=test" --resolution "1440x900" --timeout 30
```

### 2. Batch Evidence Capture from Findings List

```bash
# From a list of URLs with vulns
cat findings_urls.txt | while read url; do
    clean_name=$(echo "$url" | sha256sum | cut -c1-12)
    shot-scraper "$url" -o "evidence/${clean_name}.png" --wait 1500
done

# gowitness batch
gowitness file --filename findings_urls.txt --output-dir evidence/ --timeout 30
```

### 3. Desktop Capture (Post-Exploitation)

```bash
# Local desktop — capture full screen
import -window root desktop_full.png
scrot -d 5 desktop_delayed.png

# Remote via X11 forwarding
ssh -X user@TARGET "import -window root /tmp/evidence.png" && scp user@TARGET:/tmp/evidence.png .

# Remote via RDP session capture
xfreerdp /v:TARGET /u:user /p:pass /clipboard /drive:share,/tmp/evidence
```

### 4. Headless Browser with Custom Dimensions

```bash
# playwright script — full page screenshot
python3 -c "
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={'width': 1440, 'height': 900})
    page.goto('https://TARGET/vuln?q=PAYLOAD')
    page.screenshot(path='poc_fullpage.png', full_page=True)
    browser.close()
"

# shot-scraper with custom JS rendering
shot-scraper "https://TARGET/protected" -o protected.png \
  --javascript "document.querySelector('.secret-data').style.display='block'"
```

### 5. Annotated Report Compilation

```bash
# Compile all evidence into an HTML report
python3 << 'EOF'
import os, base64

evidence_dir = "evidence/"
html_parts = ["<html><body><h1>Evidence Report</h1><hr>"]

for img in sorted(os.listdir(evidence_dir)):
    if img.endswith(".png"):
        path = os.path.join(evidence_dir, img)
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        html_parts.append(f'<h3>{img}</h3><img src="data:image/png;base64,{b64}" style="max-width:100%"><hr>')

html_parts.append("</body></html>")
with open("evidence-report.html", "w") as f:
    f.write("\n".join(html_parts))
print("Evidence report: evidence-report.html")
EOF
```

## OPSEC Rules

- Never screenshot sensitive user data (PII, passwords, payment info) — blur or crop before inclusion
- Strip metadata from screenshots: `exiftool -all= *.png`
- Do not upload screenshots to third-party services
- Store evidence locally in `evidence/` directory
- Timestamp all screenshots for chain of custody
- For post-exploitation desktop capture, clean traces: `rm -f /tmp/evidence*.png`

## Verification

```bash
# Count PoC screenshots
ls evidence/*.png 2>/dev/null | wc -l

# Verify no metadata leaks
exiftool evidence/*.png | grep -E "User Comment|GPS|Software" || echo "Clean"

# Check resolution and readability
file evidence/*.png | head -5
```

## Pitfalls

- Headless browsers may render differently than real browsers — always verify the PoC is visible
- CAPTCHA or SSO pages may block automated screenshots
- Very large pages (>10000px) may timeout
- Desktop capture via X11 requires the session to be active
- Screenshot file sizes can be large — compress with `pngquant` or `optipng`

## Output Format

```json
{
  "skill": "screen-capture",
  "target": "TARGET",
  "screenshots_taken": 5,
  "evidence_dir": "evidence/",
  "compiled_report": "evidence-report.html",
  "formats": ["png", "html"],
  "severity": "info",
  "chain_of_custody": [
    {"file": "xss-poc.png", "timestamp": "2026-07-13T10:00:00Z", "finding_id": "F-001"}
  ]
}
```
