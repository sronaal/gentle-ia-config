---
name: visual-recon
description: Visual screenshot reconnaissance of web targets
version: 1.0.0
phase: recon
category: fingerprinting
tags: [visual, screenshot, gowitness, web, recon]
tools: [gowitness, httpx]
difficulty: basic
opsec_level: low
time_estimate: 5m
severity_if_found: info
related_skills:
  - cms-fingerprint-deep
mitre_attack:
  - T1592
---

## When to Use

- Visual identification of web services
- Quick assessment of target applications
- Identifying login pages, admin panels, error pages

## Prerequisites

- gowitness installed (`go install github.com/sensepost/gowitness@latest`)
- Chrome/Chromium browser installed

## Procedure

### 1. Prepare Target List

```bash
subfinder -d TARGET -silent -o subdomains.txt
httpx -l subdomains.txt -silent -o urls.txt
```

### 2. Single Screenshot

```bash
gowitness screenshot --url "https://TARGET" --timeout 30
gowitness screenshot --url "https://TARGET" --resolution "1920x1080"
```

### 3. Batch Screenshot

```bash
gowitness file --filename urls.txt --timeout 30
gowitness file --filename urls.txt --threads 10 --timeout 30
gowitness file --filename urls.txt --output-dir /tmp/screenshots
```

### 4. Screenshot with Authentication

```bash
gowitness screenshot --url "https://admin.TARGET" --basic-auth "admin:password"
gowitness screenshot --url "https://TARGET" --header "Authorization: Bearer TOKEN"
```

### 5. Generate HTML Report

```bash
gowitness report --source /tmp/screenshots --output /tmp/report.html
xdg-open /tmp/report.html 2>/dev/null
```

## OPSEC Rules

- Screenshots are passive reconnaissance — low risk
- Do NOT screenshot authentication pages without credentials
- Document timestamps of all screenshots
- Use reasonable thread counts to avoid triggering rate limits

## Verification

```bash
ls -la /tmp/screenshots/*.png | wc -l
```

## Pitfalls

- Some pages require JavaScript rendering — gowitness handles this
- Login pages may require authentication before screenshot
- CAPTCHA pages will not render properly
- Large target lists may take significant time

## Output Format

```json
{
  "target": "TARGET",
  "total_urls": 15,
  "screenshots_captured": 15,
  "output_dir": "/tmp/screenshots",
  "report_path": "/tmp/report.html",
  "notable_pages": [
    {"url": "https://admin.TARGET", "title": "Admin Panel"},
    {"url": "https://TARGET/login", "title": "Login Page"}
  ],
  "severity": "info"
}
```
