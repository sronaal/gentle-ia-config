---
name: technical-report
description: Full technical report with evidence and remediation guidance
version: 1.0.0
phase: report
category: reporting
tags: [report, technical, findings, remediation, evidence]
tools: [jinja2, markdown]
difficulty: advanced
opsec_level: low
time_estimate: 5m
severity_if_found: info
related_skills:
  - generate-report
  - finding-consolidation
  - severity-scoring
  - evidence-packaging
  - executive-summary
mitre_attack: []
---

## When to Use

Use this skill to generate a detailed technical report with step-by-step
reproduction, evidence references, and remediation guidance per finding.

## Prerequisites

- Consolidated and scored findings
- Evidence package (screenshots, HTTP requests/responses)
- Jinja2 installed (`pip install jinja2`)

## Procedure

```bash
python3 -c "
from jinja2 import Template
import json
from datetime import datetime

with open('./findings/scored.json') as f: findings = json.load(f)
with open('./evidence/manifest.json') as f: evidence = json.load(f)

t = Template('''# Technical Report
**Client**: {{ client }} | **Date**: {{ date }} | **Scope**: {{ scope }}

## Findings
{% for f in findings %}
### {{ loop.index }}. {{ f.title }}
**Severity**: {{ f.severity|upper }} (CVSS: {{ f.cvss_score }}) | **CWE**: {{ f.cwe }}

**Description**: {{ f.description }}

**Proof of Concept**:
\\\`\\\`\\\`
{{ f.poc_step1 }}
\\\`\\\`\\\`

**Evidence**: {% for e in f.evidence %}[{{ e.type }}] {{ e.reference }} {% endfor %}

**Remediation** ({{ f.remediation_priority }}): {{ f.remediation_guidance }}

---
{% endfor %}

## Appendix: Tools
| Tool | Purpose |
|------|---------|
| nmap | Network scanning |
| httpx | HTTP probing |
| nuclei | Vuln scanning |
| Burp Suite | Manual testing |

*Generated {{ gen_date }}*
''')

r = t.render(client='TARGET', date=datetime.now().strftime('%Y-%m-%d'),
    scope='Web App + API', findings=findings, gen_date=datetime.now().strftime('%Y-%m-%d %H:%M'))

with open('technical_report.md', 'w') as f: f.write(r)
print('Generated: technical_report.md')
"
```

### Package Evidence & Convert

```bash
tar -czf evidence_package.tar.gz technical_report.md evidence/
pandoc technical_report.md -o technical_report.pdf --toc --pdf-engine=xelatex
```

## OPSEC Rules

- No OPSEC concerns — local generation only
- Do not include real credentials, tokens, or secrets
- Use [REDACTED] for sensitive values
- Review all evidence before including
- Encrypt report if containing sensitive findings
- Share via secure channel

## Verification

- All findings from scored.json included
- Each finding has evidence references
- Reproduction steps are accurate
- Remediation guidance is actionable

## Pitfalls

- Missing evidence references make findings unverifiable
- Vague remediation is not actionable
- Large reports may exceed PDF limits

## Output Format

```markdown
# Technical Report
### 1. SQL Injection in /api/users
**Severity**: CRITICAL (CVSS: 9.8)
...
```
Generated as `technical_report.md` + optional PDF + `evidence_package.tar.gz`.
