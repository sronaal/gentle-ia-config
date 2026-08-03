---
name: wp2shell-detect
description: "Detect WordPress wp2shell vulnerability (CVE-2026-60137 + CVE-2026-63030) — version check, batch API probe, and SQLi confirmation"
version: 1.0.0
phase: recon
category: fingerprinting
tags: [wordpress, wp2shell, cve-2026-60137, cve-2026-63030, rce, sql-injection]
tools: [curl, python3]
difficulty: intermediate
opsec_level: low
time_estimate: 30s
severity_if_found: critical
related_skills:
  - wordpress-mass-recon
  - wp2shell-exploit
  - wp2shell-rce
mitre_attack:
  - T1592.002
  - T1595.002
  - T1190
---

## Activation Contract

Load when WordPress is detected to assess wp2shell exposure.
Affects WP 6.9.0-6.9.4, 7.0.0-7.0.1 (RCE chain), 6.8.0-6.8.5 (SQLi only).

## Hard Rules

- Passive detection only (version + endpoint check).
- No SQLi payloads here.

## Decision Gates

| Check | Method | What It Reveals |
|-------|--------|-----------------|
| Version detection | /wp-json/, generator meta tag | Affected ranges |
| Batch endpoint | GET /wp-json/batch/v1 | 200 = active, blocked otherwise |
| CORS on batch | Origin header test | May amplify attack surface |

## Execution Steps

### Step 1: Version Detection
```bash
curl -skI "https://TARGET/wp-json/" | grep -i "x-powered-by\|link:.*api.w.org"
curl -sk "https://TARGET/" | grep -oP '<meta name="generator" content="WordPress \K[^"]+'
curl -sk "https://TARGET/readme.html" | grep -oP "Version \K[0-9.]+"
```

### Step 2: Batch API Probe
```bash
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/wp-json/batch/v1"
curl -sk -D- "https://TARGET/wp-json/batch/v1" | head -20
curl -sk -H "Origin: https://evil.com" "https://TARGET/wp-json/batch/v1" | grep -i "access-control"
```

### Step 3: Assessment
```bash
python3 -c "
import json, urllib.request, re
from packaging.version import Version
t = 'TARGET'; b = 'https://TARGET'
r = {'target': t, 'vulnerable': False}
try:
    html = urllib.request.urlopen(b + '/', timeout=10).read().decode()
    m = re.search(r'<meta name=\"generator\" content=\"WordPress ([^\"]+)\"', html)
    if m:
        ver = m.group(1)
        v = Version(ver)
        if Version('6.9.0') <= v <= Version('6.9.4') or Version('7.0.0') <= v <= Version('7.0.1'):
            r['vulnerable'] = True; r['status'] = 'VULNERABLE'
        elif Version('6.8.0') <= v <= Version('6.8.5'):
            r['status'] = 'SQLi ONLY'
        else:
            r['status'] = 'NOT VULNERABLE'
except Exception as e:
    r['error'] = str(e)
print(json.dumps(r, indent=2))
"
```

## Output Contract

- **type**: wp2shell_assessment
- **severity**: Critical if vulnerable
- **next_steps**: ["Run wp2shell-exploit if vulnerable"]
