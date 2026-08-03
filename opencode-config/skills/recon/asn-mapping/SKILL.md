---
name: asn-mapping
description: Map ASN and IP ranges for target infrastructure
version: 1.0.0
phase: recon
category: enumeration
tags: [asn, ip-range, bgp, infrastructure, mapping]
tools: [whois, amass, bgp.he.net]
difficulty: basic
opsec_level: low
time_estimate: 5m
severity_if_found: info
related_skills:
  - origin-ip-discovery
  - subdomain-takeover
mitre_attack:
  - T1590
---

## When to Use

- Map complete IP infrastructure for target
- Hunting additional assets in same ASN
- Identifying hosting providers and cloud infrastructure
- Planning network-level attacks or pivoting

## Prerequisites

- whois and amass installed
- Access to BGP.he.net or similar tools

## Procedure

### 1. Basic ASN Lookup

```bash
TARGET_IP=$(dig TARGET +short | head -1)
whois $TARGET_IP | grep -i "origin\|netname\|descr\|org-name"
curl -s "https://api.iptoasn.com/v1/as/ip/$TARGET_IP" | python3 -m json.tool 2>/dev/null
```

### 2. IP Range Enumeration

```bash
whois $TARGET_IP | grep -E "inetnum|netrange|cidr"
amass intel -asn TARGET 2>/dev/null
curl -s "https://api.bgpview.io/asn/ASN_NUMBER/prefixes" | python3 -m json.tool 2>/dev/null
```

### 3. BGP.he.net Lookup

```bash
curl -s "https://bgp.he.net/ASASN_NUMBER" | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' | sort -u
curl -s "https://bgp.he.net/ASASN_NUMBER" | grep -i "netname\|org-name\|descr"
```

### 4. Amass Intelligence

```bash
amass intel -asn -d TARGET -timeout 300
amass enum -asn -d TARGET -o amass_results.txt

cat ip_list.txt | while read ip; do
  ASN=$(whois $ip | grep "Origin:" | awk '{print $2}')
  echo "$ip -> AS$ASN"
done
```

### 5. Cloud Provider Detection

```bash
for ip in $(dig TARGET +short); do
  WHOIS=$(whois $ip 2>/dev/null)
  echo "$WHOIS" | grep -i "amazon\|aws" && echo "$ip -> AWS"
  echo "$WHOIS" | grep -i "microsoft\|azure" && echo "$ip -> Azure"
  echo "$WHOIS" | grep -i "google\|gcp" && echo "$ip -> GCP"
  echo "$WHOIS" | grep -i "cloudflare" && echo "$ip -> Cloudflare"
done
```

### 6. Related IP Discovery

```bash
SUBNET=$(whois $TARGET_IP | grep "NetRange" | awk '{print $3}' | cut -d. -f1-3)
nmap -sL "$SUBNET.0/24" | grep "Nmap scan report" | awk '{print $NF}' | tr -d '()'

for ip in $(dig TARGET +short); do
  nmap -sV -p 80,443 $ip --open 2>/dev/null | grep -A2 "OPEN"
done
```

## OPSEC Rules

- ASN and IP range information is PUBLIC — no authorization needed
- Do NOT perform active scans against discovered IPs without authorization
- Document all findings for infrastructure mapping
- Use passive techniques first

## Verification

```bash
TARGET_IP=$(dig TARGET +short | head -1)
whois $TARGET_IP | grep -E "Origin:|NetName:"
```

## Pitfalls

- Multiple ASNs may serve the same IP (transit vs. origin)
- Cloud providers use shared IP ranges — same ASN for many customers
- BGP routing may differ from physical location
- Whois data may be outdated or incomplete

## Output Format

```json
{
  "target": "TARGET",
  "primary_asn": "AS13335",
  "organization": "Cloudflare, Inc.",
  "ip_ranges": ["104.16.0.0/12", "172.64.0.0/13"],
  "hosting_provider": "Cloudflare",
  "cloud_provider": null,
  "severity": "info"
}
```
