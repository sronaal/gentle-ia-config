---
name: finding-consolidation
description: Consolidate and deduplicate findings from all pentest phases
version: 1.0.0
phase: report
category: aggregation
tags: [findings, consolidation, dedup]
tools: []
difficulty: basic
opsec_level: low
time_estimate: 10s
severity_if_found: info
related_skills:
  - severity-scoring
  - generate-report
mitre_attack: []
---

## When to Use

Use this skill to aggregate findings from all pentest phases, remove duplicates,
and produce a consolidated finding list for scoring and reporting.

## Prerequisites

- Findings from previous phases (recon, enum, exploit, post)
- No external tools required

## Procedure

```bash
# Aggregate findings from all phase results
findings_dir="./findings"
consolidated="$findings_dir/consolidated.json"

# Merge all JSON findings files
python3 -c "
import json, glob, os

all_findings = []
seen = set()

for f in glob.glob('$findings_dir/*.json'):
    with open(f) as fh:
        data = json.load(fh)
        findings = data if isinstance(data, list) else data.get('findings', [])
        for finding in findings:
            key = f\"{finding.get('title')}:{finding.get('evidence')}\"
            if key not in seen:
                seen.add(key)
                all_findings.append(finding)

with open('$consolidated', 'w') as out:
    json.dump(all_findings, out, indent=2)

print(f'Consolidated {len(all_findings)} findings')
"
```

## OPSEC Rules

- No OPSEC concerns — aggregation is a local operation
- Do not modify original findings data
- Preserve all evidence and metadata

## Verification

- Verify no findings were lost during consolidation
- Check that duplicates were correctly identified
- Confirm all phases are represented

## Pitfalls

- Different tools may report the same finding differently
- Some findings may be false positives
- Evidence may be incomplete or truncated

## Output Format

```json
[
  {
    "finding_type": "recon:subdomain",
    "severity": "info",
    "title": "Subdomain discovered",
    "evidence": "admin.target.com"
  }
]
```
