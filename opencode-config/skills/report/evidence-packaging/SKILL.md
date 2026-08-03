---
name: evidence-packaging
description: Package evidence including screenshots, PoC commands, and request/response pairs
version: 1.0.0
phase: report
category: evidence
tags: [evidence, screenshots, poc, request-response]
tools: [curl, screenshot]
difficulty: basic
opsec_level: low
time_estimate: 30s
severity_if_found: info
related_skills:
  - finding-consolidation
  - generate-report
mitre_attack: []
---

## When to Use

Use this skill to organize and package evidence for each finding including
screenshots, proof-of-concept commands, and request/response pairs.

## Prerequisites

- Scored findings from previous step
- curl (for replaying requests)
- Screenshot tool (optional)

## Procedure

```bash
# Create evidence directory structure
mkdir -p evidence/{screenshots,poc,requests}

# Replay and capture request/response for each finding
for finding in findings/*.json; do
    name=$(python3 -c "import json; print(json.load(open('$finding'))['title'].replace(' ', '_'))")
    
    # Capture HTTP request/response
    curl -sk "TARGET_URL" -o "evidence/requests/${name}_response.txt" -D "evidence/requests/${name}_headers.txt"
    
    # Generate PoC command
    echo "curl -sk 'TARGET_URL'" > "evidence/poc/${name}_poc.sh"
done

# Package evidence
tar -czf evidence_package.tar.gz evidence/
```

## OPSEC Rules

- Do not capture sensitive data (passwords, tokens)
- Blur or redact personal information in screenshots
- Store evidence securely
- Document chain of custody

## Verification

- Verify evidence matches the finding description
- Check that PoC commands are reproducible
- Confirm screenshots are readable

## Pitfalls

- Screenshots may contain sensitive information
- Request/response pairs may be large
- Some evidence may expire or change
- Storage space may be limited

## Output Format

```
evidence/
├── screenshots/
│   └── finding_name.png
├── poc/
│   └── finding_name_poc.sh
└── requests/
    ├── finding_name_request.txt
    └── finding_name_response.txt
```
