---
name: generate-report
description: Generate a comprehensive pentest report from consolidated findings
version: 1.0.0
phase: report
category: documentation
tags: [report, documentation, jinja2, markdown]
tools: [jinja2]
difficulty: intermediate
opsec_level: low
time_estimate: 60s
severity_if_found: info
related_skills:
  - finding-consolidation
  - severity-scoring
mitre_attack: []
---

## When to Use

Use this skill to generate a professional pentest report from all consolidated
and scored findings. Reports include executive summary, technical details, and
remediation recommendations.

## Prerequisites

- Scored findings from previous step
- Jinja2 (Python template engine)
- Evidence package

## Procedure

```bash
# Generate report using Python
python3 -c "
from jinja2 import Template
import json
from datetime import datetime

with open('./findings/scored.json') as f:
    findings = json.load(f)

template = Template('''# Penetration Test Report

## Executive Summary

**Date**: {{ date }}
**Total Findings**: {{ findings|length }}
**Critical**: {{ critical }}
**High**: {{ high }}
**Medium**: {{ medium }}
**Low**: {{ low }}

## Findings

{% for finding in findings %}
### {{ finding.title }}

**Severity**: {{ finding.severity }} (CVSS: {{ finding.cvss_score }})
**Type**: {{ finding.finding_type }}

**Description**: {{ finding.description }}

**Evidence**: {{ finding.evidence }}

---
{% endfor %}
''')

critical = sum(1 for f in findings if f['severity'] == 'critical')
high = sum(1 for f in findings if f['severity'] == 'high')
medium = sum(1 for f in findings if f['severity'] == 'medium')
low = sum(1 for f in findings if f['severity'] == 'low')

report = template.render(
    date=datetime.now().strftime('%Y-%m-%d'),
    findings=findings,
    critical=critical,
    high=high,
    medium=medium,
    low=low
)

with open('report.md', 'w') as f:
    f.write(report)

print('Report generated: report.md')
"
```

## OPSEC Rules

- No OPSEC concerns — report generation is local
- Do not include sensitive credentials in report
- Use placeholder values for actual passwords/tokens
- Review report before distribution

## Verification

- Verify all findings are included in the report
- Check that severity levels and scores are accurate
- Confirm remediation recommendations are present

## Pitfalls

- Report generation may fail if findings data is malformed
- Jinja2 templates may have syntax errors
- Large reports may take time to generate
- Evidence references may be broken

## Output Format

```markdown
# Penetration Test Report

## Executive Summary
...

## Findings
### Finding 1
...
```

Generated as `report.md` in the project root.
