---
name: sector-recon-methodology
description: Sector-based recon with tier selection and vulnerability baselines
version: 1.0.0
phase: meta
category: methodology
tags: [sector, methodology, hipaa, pci-dss, saas]
tools: [nmap, curl, whatweb]
difficulty: advanced
opsec_level: medium
time_estimate: 15m
severity_if_found: medium
related_skills:
  - recon-playbook
  - attack-patterns-reference
mitre_attack:
  - T1595
  - T1592
---

## When to Use

Use this skill to apply sector-specific recon methodologies with tier selection
based on target industry and authorization level.

## Prerequisites

- Target organization with known industry sector
- Recon playbook Phase 0-1 results available
- nmap, curl, whatweb installed

## Procedure

### Step 1: Sector Identification

```bash
whois TARGET.com | grep -i "org\|descr\|industry"
echo "Healthcare: hospitals, clinics, pharma"
echo "Finance: banks, fintech, insurance"
echo "SaaS: multi-tenant, API-first"
```

### Step 2: Tier Selection

```bash
# Tier 1 — Passive only (unauthorized/pre-engagement)
# Tools: crt.sh, Shodan, Censys, WHOIS

# Tier 2 — Light active (authorized web app testing)
# Tools: httpx, curl, whatweb

# Tier 3 — Full active (full authorization + written ROE)
# Tools: nmap, sqlmap, nuclei
```

### Step 3: Sector-Specific Baselines

#### Healthcare (HIPAA)

```bash
nmap -sV -p 80,443,8080,8443 TARGET_RANGE | grep -i "medical\|dicom"
nmap -p 104,11112 TARGET_RANGE -oN dicom_scan.txt
curl -s "https://TARGET/api/patients" -H "Authorization: Bearer INVALID" | head -c 500
nmap -O -sV TARGET_RANGE | grep -iE "Windows (XP|Server 2003|7)"
```

#### Finance (PCI-DSS)

```bash
curl -s "https://TARGET" | grep -oiE '(stripe|paypal|braintree|square)[^"]*'
nmap --script ssl-enum-ciphers -p 443 TARGET | grep -i "TLS\|SSL"
curl -s "https://TARGET/api/v1" -H "Accept: application/json" | head -c 500
curl -s "https://TARGET" | grep -oiE '(api[_-]?key|secret|merchant)["\x27:=]+[^\s"'\'']{8,}'
```

#### SaaS (Multi-Tenant)

```bash
curl -s "https://TARGET/api/tenants/OTHER_TENANT/data" -H "Authorization: Bearer MY_TOKEN"
curl -s "https://TARGET/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'
for i in $(seq 1 100); do curl -s -o /dev/null -w "%{http_code}\n" "https://TARGET/api/resource"; done | sort | uniq -c
curl -s "https://TARGET/.well-known/openid-configuration" | jq .
```

### Step 4: Document Findings

```bash
cat > sector_findings.md << EOF
# Sector Recon Results
## Target: TARGET.com | Sector: $SECTOR | Tier: $TIER
### Compliance-Relevant Findings
- [ ] Finding 1
### Recommended Follow-up Skills
- skill-name-1
EOF
```

## OPSEC Rules

- Tier 1: No active probing — passive sources only
- Tier 2: 1 request/second maximum
- Tier 3: Only with written authorization
- Healthcare: Never access real patient data
- Finance: Never attempt actual transactions
- SaaS: Do not access other tenants' data

## Verification

- Confirm tier matches authorization level in ROE
- Validate sector identification against multiple sources
- Verify no out-of-scope testing performed

## Pitfalls

- Misidentifying sector leads to wrong attack surface focus
- Tier 3 without authorization is illegal
- Healthcare devices may be fragile — avoid aggressive scanning
- Financial APIs have fraud detection — triggering alerts is risky

## Output Format

```
[SECTOR] Healthcare — Tier 2 selected
[FINDING] DICOM service exposed on port 104
[BASELINE] HIPAA controls: 12/20 checked
[RECOMMEND] Use hunt-idor-api for PHI endpoint testing
```
