---
name: whois-intel
description: Gather WHOIS intelligence including registrar, contacts, and nameservers
version: 1.0.0
phase: recon
category: intelligence
tags: [whois, osint, registrar]
tools: [whois]
difficulty: basic
opsec_level: low
time_estimate: 10s
severity_if_found: low
related_skills:
  - subdomain-discovery
  - dns-enumeration
mitre_attack:
  - T1591.002
  - T1593
---

## When to Use

Use this skill to gather registrant information, nameservers, registrar details, and
creation/expiry dates. Exposed contact information can lead to social engineering.

## Prerequisites

- whois client

## Procedure

```bash
whois TARGET
whois TARGET | grep -iE "name server|registrar|creation|expir|email|phone"
```

## OPSEC Rules

- WHOIS queries go through public databases — safe
- Do not query whois for every subdomain (creates noise)
- Cache results — WHOIS data changes infrequently
- Respect RDAP rate limits

## Verification

- Cross-check registrar with ICANN lookup
- Verify nameservers match DNS enumeration results
- Check for recent updates that may indicate active management

## Pitfalls

- Many domains use privacy protection (WHOIS guard)
- GDPR has redacted most registrant contact details
- Registry-level WHOIS may differ from registrar WHOIS
- Some TLDs (.io, .co) have different data policies

## Output Format

```
Registrar: Example Registrar Inc.
Creation Date: 2020-01-15
Expiry Date: 2025-01-15
Name Servers: ns1.target.com, ns2.target.com
Registrant Email: admin@example.com
```
