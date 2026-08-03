---
name: origin-ip-discovery
description: Find origin server IP behind CDN or WAF protection
version: 1.0.0
phase: recon
category: discovery
tags: [origin-ip, cdn, cloudflare, dns, shodan]
tools: [curl, shodan, censys, dns]
difficulty: intermediate
opsec_level: low
time_estimate: 15m
severity_if_found: high
related_skills:
  - subdomain-takeover
  - asn-mapping
mitre_attack:
  - T1596
---

## When to Use

- Target is behind Cloudflare, Akamai, or other CDN
- Need to find origin server for direct attacks
- Bypassing CDN-based WAF protection
- Mapping infrastructure for targeted exploitation

## Prerequisites

- curl, dig, and shodan/censys CLI installed
- API keys for Shodan/Censys (optional but helpful)
- Understanding of DNS infrastructure

## Procedure

### 1. DNS History Check

```bash
dig TARGET +short
dig @8.8.8.8 TARGET +short
for sub in mail ftp vpn api dev staging; do
  dig $sub.TARGET +short 2>/dev/null
done
```

### 2. SSL Certificate Analysis

```bash
echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null | \
  openssl x509 -text -noout 2>/dev/null | grep -A1 "Subject Alternative Name"

curl -s "https://crt.sh/?q=%.TARGET&output=json" | \
  python3 -c "import sys,json; [print(x.get('name_value','')) for x in json.load(sys.stdin)]" 2>/dev/null
```

### 3. MX / Email Server IPs

```bash
dig TARGET MX +short
dig mail.TARGET +short
```

### 4. Shodan Search for Origin

```bash
shodan search "ssl.cert.subject.CN:TARGET" --fields ip_str,port,org 2>/dev/null
shodan search "hostname:TARGET" --fields ip_str,port,org 2>/dev/null
shodan search "net:KNOWN_RANGE/24 ssl.cert.subject.CN:TARGET" 2>/dev/null
```

### 5. Censys Search

```bash
censys search "parsed.subject.common_name:TARGET" --index-type certificates 2>/dev/null
censys search "services.tls.certificates.leaf_data.subject.common_name:TARGET" 2>/dev/null
```

### 6. Cloudflare Bypass Techniques

```bash
# Direct IP with Host header
for ip in $(dig TARGET +short); do
  curl -sI "https://$ip/" -H "Host: TARGET" -k 2>/dev/null | head -3
done

# Check for exposed origin headers
curl -sI "https://TARGET/" | grep -i "x-origin\|x-real-ip\|x-forwarded"

# Test subdomains not behind CDN
for sub in direct origin staging dev test; do
  IP=$(dig $sub.TARGET +short 2>/dev/null)
  [ -n "$IP" ] && echo "$sub.TARGET -> $IP"
done
```

### 7. Historical Records

```bash
curl -s "https://api.securitytrails.com/v1/domain/TARGET/history/a" \
  -H "apikey: YOUR_API_KEY" 2>/dev/null | python3 -m json.tool 2>/dev/null

curl -s "https://web.archive.org/web/*http://TARGET/" | \
  grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u
```

## OPSEC Rules

- Do NOT perform active scans against discovered origin IPs without authorization
- Document IP addresses found but do not exploit during recon
- Use passive techniques first before active probing
- Respect rate limits on Shodan/Censys APIs

## Verification

```bash
curl -sI "https://ORIGIN_IP/" -H "Host: TARGET" -k | head -5
```

## Pitfalls

- Multiple CDN IPs may be returned — need to identify the origin
- Some CDNs use Anycast — same IP serves multiple customers
- SSL certificates may be shared across multiple domains
- DNS history may be outdated or incomplete

## Output Format

```json
{
  "target": "TARGET",
  "cdn_provider": "cloudflare",
  "cdn_ips": ["104.16.0.1", "104.16.0.2"],
  "origin_ip_candidates": [
    {"ip": "203.0.113.50", "source": "shodan", "confidence": "high"},
    {"ip": "203.0.113.51", "source": "ssl-cert", "confidence": "medium"}
  ],
  "mail_server_ip": "203.0.113.60",
  "severity": "high"
}
```
