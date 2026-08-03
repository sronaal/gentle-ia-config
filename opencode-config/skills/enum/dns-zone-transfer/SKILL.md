---
name: dns-zone-transfer
description: DNS zone transfer and subdomain enumeration
version: 1.0.0
phase: enum
category: network
tags: [dns, zone-transfer, subdomains]
tools: [dig, host, dnsrecon]
difficulty: basic
opsec_level: low
time_estimate: 30s
severity_if_found: high
related_skills:
  - port-scan
  - api-discovery
mitre_attack:
  - T1596.001
  - T1590.002
---

## When to Use

Use this skill to attempt DNS zone transfers (AXFR) and enumerate subdomains,
MX records, and other DNS information for a target domain.

## Prerequisites

- dig (bind9-host)
- host
- dnsrecon (optional, for automated enumeration)

## Procedure

```bash
# Step 1: Identify nameservers
dig NS TARGET.COM +short
dig TARGET.COM NS +short

# Step 2: Attempt zone transfer from each NS
for ns in $(dig NS TARGET.COM +short); do
  echo "=== Zone transfer from $ns ==="
  dig @$(dig NS TARGET.COM +short | head -1) TARGET.COM AXFR +noall +answer
done

# Step 3: host command zone transfer
host -t axfr TARGET.COM $(dig NS TARGET.COM +short | head -1)

# Step 4: Enumerate common record types
dig TARGET.COM A +short
dig TARGET.COM AAAA +short
dig TARGET.COM MX +short
dig TARGET.COM TXT +short
dig TARGET.COM SOA +short
dig TARGET.COM NS +short

# Step 5: Enumerate subdomains via DNS
for sub in www mail ftp vpn api dev staging prod test admin jenkins gitlab grafana; do
  ip=$(dig +short $sub.TARGET.COM)
  [ -n "$ip" ] && echo "$sub.TARGET.COM → $ip"
done

# Step 6: Reverse DNS on discovered IPs
for ip in $(dig TARGET.COM A +short); do
  echo "$ip → $(dig +short -x $ip)"
done

# Step 7: dnsrecon automated scan
dnsrecon -d TARGET.COM -t std,zonewalk 2>/dev/null | tee dnsrecon_output.txt
```

## OPSEC Rules

- Do NOT perform brute-force DNS enumeration
- Limit zone transfer attempts to 1 per nameserver
- Do not flood DNS servers with queries
- Document all queries for audit trail
- Zone transfers may be logged and alert defenders

## Verification

- Confirm zone transfer returns records (not REFUSED)
- Verify discovered IPs are in scope
- Check if wildcard DNS is configured

## Pitfalls

- Most modern DNS servers block zone transfers
- Wildcard DNS may return valid IPs for any subdomain
- Some DNS servers rate-limit AXFR requests
- Private DNS zones may not be accessible externally

## Output Format

```
[DNS]     NS: ns1.example.com, ns2.example.com
[ZONE]    AXFR from ns1.example.com — 47 records
[A]       mail.example.com → 10.0.1.5
[A]       vpn.example.com → 10.0.1.10
[MX]      mail.example.com (priority: 10)
[TXT]     "v=spf1 include:_spf.google.com ~all"
[CRITICAL] Zone transfer successful — full DNS zone exposed
```
