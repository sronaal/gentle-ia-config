---
name: subdomain-takeover
description: Detect dangling CNAME records for subdomain takeover
version: 1.0.0
phase: recon
category: enumeration
tags: [subdomain, takeover, dangling, cname, dns]
tools: [subfinder, httpx, curl]
difficulty: intermediate
opsec_level: low
time_estimate: 15m
severity_if_found: critical
related_skills:
  - origin-ip-discovery
  - asn-mapping
mitre_attack:
  - T1199
---

## When to Use

- Find subdomains pointing to unclaimed services
- Hunting dangling CNAME records (AWS, Azure, GitHub, etc.)
- Pre-exploitation recon for initial access vectors

## Prerequisites

- subfinder, httpx, and curl installed
- DNS resolution capability
- Understanding of common cloud service CNAME patterns

## Procedure

### 1. Subdomain Enumeration

```bash
subfinder -d TARGET -silent -o subdomains.txt
amass enum -passive -d TARGET -o subdomains_amass.txt
cat subdomains.txt subdomains_amass.txt | sort -u > all_subdomains.txt
```

### 2. DNS Resolution Check

```bash
httpx -l all_subdomains.txt -silent -dns-only -o resolved.txt

for sub in $(cat all_subdomains.txt); do
  CNAME=$(dig $sub CNAME +short 2>/dev/null)
  A=$(dig $sub A +short 2>/dev/null)
  [ -n "$CNAME" ] && echo "$sub -> CNAME: $CNAME"
  [ -z "$A" ] && [ -z "$CNAME" ] && echo "$sub -> UNRESOLVED"
done > dns_results.txt
```

### 3. Dangling CNAME Detection

```bash
grep "CNAME:" dns_results.txt | while read line; do
  SUB=$(echo $line | cut -d: -f1 | awk '{print $1}')
  CNAME_TGT=$(echo $line | cut -d"CNAME: " -f2)
  RESOLVES=$(dig $CNAME_TGT A +short 2>/dev/null)
  [ -z "$RESOLVES" ] && echo "DANGLING: $SUB -> $CNAME_TGT"
done > dangling_candidates.txt
```

### 4. Verify Takeover Opportunity

```bash
for sub in $(cat dangling_candidates.txt | awk '{print $2}'); do
  case $sub in
    *.github.io) echo "GitHub Pages: $sub" ;;
    *.amazonaws.com) echo "S3 Bucket: $sub" ;;
    *.azurewebsites.net) echo "Azure: $sub" ;;
    *.herokuapp.com) echo "Heroku: $sub" ;;
    *.cloudfront.net) echo "CloudFront: $sub" ;;
    *.s3.amazonaws.com) echo "S3: $sub" ;;
  esac
done
```

### 5. Claim Verification

```bash
# GitHub Pages
curl -s "https://TARGET.github.io/" | grep -i "there isn't a github pages site here"
# S3
curl -s "https://TARGET.s3.amazonaws.com/" | grep -i "NoSuchBucket"
# Azure
curl -s "https://TARGET.azurewebsites.net/" | grep -i "404 Web Site not found"
```

## OPSEC Rules

- Document all dangling CNAMEs found
- Do NOT claim subdomains during reconnaissance
- Do NOT host malicious content on discovered takeover points
- Report critical findings to engagement lead immediately

## Verification

```bash
dig DANGLING_SUBDOMAIN CNAME +short
curl -sI "https://DANGLING_SUBDOMAIN" | head -3
```

## Pitfalls

- Some CDNs return 200 even for non-existent subdomains
- CNAME chains may hide the actual target
- DNS propagation delays may cause false positives
- Some services (e.g., Fastly) require specific verification

## Output Format

```json
{
  "target": "TARGET",
  "total_subdomains": 150,
  "dangling_cnames": [
    {"subdomain": "test.TARGET", "cname": "test.TARGET.github.io",
     "service": "github-pages", "takeover_possible": true}
  ],
  "severity": "critical"
}
```
