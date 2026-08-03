---
name: dns-enumeration
description: Enumerate DNS records and test for zone transfers on a target domain
version: 1.0.0
phase: recon
category: dns
tags: [dns, zone-transfer, records]
tools: [dig, dnsenum, fierce]
difficulty: basic
opsec_level: low
time_estimate: 30s
severity_if_found: medium
related_skills:
  - subdomain-discovery
  - whois-intel
mitre_attack:
  - T1596.001
  - T1046
---

## When to Use

Use this skill to gather DNS records (A, AAAA, MX, NS, TXT, SOA) and test for zone
transfer vulnerabilities. Zone transfers can expose the entire DNS zone without any
brute forcing.

## Prerequisites

- dig (bind-utils)
- dnsenum
- fierce
- Network access to target DNS servers

## Procedure

```bash
dig TARGET ANY +noall +answer
dig TARGET A +noall +answer
dig TARGET AAAA +noall +answer
dig TARGET MX +noall +answer
dig TARGET NS +noall +answer
dig TARGET TXT +noall +answer
dig TARGET SOA +noall +answer
dnsenum --enum TARGET
fierce --domain TARGET
```

## OPSEC Rules

- Query the authoritative nameservers directly, not recursive resolvers
- Rate limit to 5 queries per second to avoid triggering IDS
- Do not perform zone transfers in rapid succession
- Use `-dns` flag to specify known nameservers
- Avoid DNS amplification patterns

## Verification

- Confirm zone transfer success by counting returned records
- Cross-validate DNS records with online tools (SecurityTrails, VirusTotal)
- Verify MX records point to expected mail servers

## Pitfalls

- Most modern DNS servers block zone transfers (AXFR)
- Some records only appear from specific source IPs
- DNSSEC-signed zones may have different transfer behavior
- Wildcard DNS records can produce false positives

## Output Format

```
Zone Transfer Results for TARGET:
  A     : 192.168.1.10
  MX    : mail.target.com (priority: 10)
  NS    : ns1.target.com
  TXT   : "v=spf1 include:_spf.google.com ~all"
  SOA   : ns1.target.com admin.target.com 2024010101 3600 900 604800 86400
```

Structured DNS record listing grouped by record type.
