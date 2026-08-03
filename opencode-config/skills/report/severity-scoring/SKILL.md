---
name: severity-scoring
description: Calculate CVSS scores and assign severity levels to findings
version: 1.0.0
phase: report
category: scoring
tags: [cvss, severity, scoring]
tools: []
difficulty: intermediate
opsec_level: low
time_estimate: 10s
severity_if_found: info
related_skills:
  - finding-consolidation
  - generate-report
mitre_attack: []
---

## When to Use

Use this skill to calculate CVSS scores for all findings and assign consistent
severity levels based on standardized metrics.

## Prerequisites

- Consolidated findings from previous step
- No external tools required (manual CVSS calculation)

## Procedure

```bash
# Calculate CVSS scores for each finding
python3 -c "
import json

with open('./findings/consolidated.json') as f:
    findings = json.load(f)

cvss_weights = {
    'critical': {'confidentiality': 0.56, 'integrity': 0.55, 'availability': 0.56},
    'high': {'confidentiality': 0.45, 'integrity': 0.44, 'availability': 0.45},
    'medium': {'confidentiality': 0.35, 'integrity': 0.34, 'availability': 0.35},
    'low': {'confidentiality': 0.22, 'integrity': 0.22, 'availability': 0.22},
}

for finding in findings:
    severity = finding.get('severity', 'medium')
    weights = cvss_weights.get(severity, cvss_weights['medium'])
    
    # Simplified CVSS calculation
    base_score = 5.0  # Default
    if severity == 'critical':
        base_score = 9.5
    elif severity == 'high':
        base_score = 7.5
    elif severity == 'medium':
        base_score = 5.0
    elif severity == 'low':
        base_score = 2.5
    
    finding['cvss_score'] = base_score
    finding['cvss_vector'] = f'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{weights[\"confidentiality\"]}/I:{weights[\"integrity\"]}/A:{weights[\"availability\"]}'

with open('./findings/scored.json', 'w') as f:
    json.dump(findings, f, indent=2)

print(f'Scored {len(findings)} findings')
"
```

## OPSEC Rules

- No OPSEC concerns — scoring is a local operation
- Use consistent scoring methodology
- Document scoring rationale

## Verification

- Verify CVSS scores are within valid range (0-10)
- Check that severity levels match scores
- Confirm all findings have scores assigned

## Pitfalls

- CVSS scoring is subjective without context
- Some findings may need manual adjustment
- Environmental factors may affect scoring

## Output Format

```json
[
  {
    "title": "SQL Injection",
    "severity": "critical",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  }
]
```
