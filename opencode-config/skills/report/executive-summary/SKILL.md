---
name: executive-summary
description: Generate 1-page executive summary for non-technical stakeholders
version: 1.0.0
phase: report
category: reporting
tags: [report, executive, summary, risk-rating]
tools: [jinja2, markdown]
difficulty: intermediate
opsec_level: low
time_estimate: 1m
severity_if_found: info
related_skills:
  - generate-report
  - severity-scoring
  - technical-report
mitre_attack: []
---

## When to Use

Use this skill to generate a 1-page executive summary for non-technical
stakeholders with risk rating, business impact, and strategic recommendations.

## Prerequisites

- Scored findings from severity-scoring
- Jinja2 installed (`pip install jinja2`)

## Procedure

```bash
python3 -c "
from jinja2 import Template
import json
from datetime import datetime

with open('./findings/scored.json') as f:
    findings = json.load(f)

critical = sum(1 for f in findings if f['severity'] == 'critical')
high = sum(1 for f in findings if f['severity'] == 'high')
medium = sum(1 for f in findings if f['severity'] == 'medium')
low = sum(1 for f in findings if f['severity'] == 'low')

if critical > 0: risk = 'CRITICAL'
elif high > 2: risk = 'HIGH'
elif high > 0 or medium > 3: risk = 'MEDIUM'
else: risk = 'LOW'

t = Template('''# Executive Summary
**Client**: {{ client }} | **Date**: {{ date }} | **Risk**: {{ risk }}

| Severity | Count | Impact |
|----------|-------|--------|
| Critical | {{ c }} | Immediate breach risk |
| High | {{ h }} | Significant gaps |
| Medium | {{ m }} | Moderate risk |
| Low | {{ l }} | Minor improvements |

**Total**: {{ total }} findings

## Immediate Risks
{% for f in findings if f.severity in ['critical','high'] %}
- **{{ f.title }}**: {{ f.business_impact }}
{% endfor %}

## Recommendations
1. **Immediate** (0-30 days): Critical + high findings
2. **Short-term** (30-90 days): Medium findings
3. **Long-term** (90+ days): Low findings

## Conclusion
{{ conclusion }}
''')

if risk == 'CRITICAL': conc = 'Immediate remediation required. Significant breach risk.'
elif risk == 'HIGH': conc = 'Urgent remediation recommended. Significant security gaps.'
elif risk == 'MEDIUM': conc = 'Planned remediation recommended. Moderate gaps.'
else: conc = 'Reasonable security posture. Minor improvements recommended.'

r = t.render(client='TARGET', date=datetime.now().strftime('%Y-%m-%d'),
    risk=risk, c=critical, h=high, m=medium, l=low,
    total=len(findings), findings=findings, conclusion=conc)

with open('executive_summary.md', 'w') as f: f.write(r)
print('Generated: executive_summary.md')
"
```

### Optional: Convert to PDF

```bash
pandoc executive_summary.md -o executive_summary.pdf --pdf-engine=xelatex
```

## OPSEC Rules

- No OPSEC concerns — local generation only
- Do not include real credentials or tokens
- Use [REDACTED] for sensitive values
- Review before distribution

## Verification

- All findings included in summary
- Risk rating matches finding severity distribution
- Business impact language is non-technical
- Report is 1 page max

## Pitfalls

- Many findings may exceed 1 page — prioritize top risks
- Jinja2 template errors prevent generation
- Business impact must be understandable by executives

## Output Format

```markdown
# Executive Summary
**Client**: TARGET | **Date**: 2026-07-05 | **Risk**: HIGH
...
```
Generated as `executive_summary.md`.
