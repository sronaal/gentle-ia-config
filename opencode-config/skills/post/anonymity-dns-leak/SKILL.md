---
name: anonymity-dns-leak
description: DNS leak testing and prevention to maintain anonymity integrity
version: 1.0.0
phase: post
category: opsec
tags: [anonymity, dns, leak, opsec]
tools: [dig, curl, python3, systemd-resolved]
difficulty: intermediate
opsec_level: silent
time_estimate: 30s
severity_if_found: N/A
related_skills:
  - anonymity-macchanger
  - anonymity-traffic-blending
mitre_attack:
  - T1048
  - T1071
  - T1090.003
---

## When to Use

Use this skill AFTER establishing anonymity (Tor, VPN, SOCKS proxy) to verify
your traffic is not leaking through your real IP. DNS leaks are the most
common anonymity failure — a single DNS query bypassing your proxy reveals
your real ISP and geolocation. Test both IPv4 and IPv6 DNS resolution paths.

## Prerequisites

- Internet connectivity (for making requests to leak-test services)
- `dig` installed (Ubuntu: `apt install dnsutils`)
- `curl` installed
- Python 3 with `requests` library
- Passive TCP monitoring `tcpdump` or Wireshark for advanced verification

## Procedure

```bash
# ═══════════════════════════════════════════════════════════
# 1. DNS LEAK DETECTION — External services
# ═══════════════════════════════════════════════════════════
# ── ipleak.net (via CLI) ──────────────────────────────────
# Test if your DNS queries are leaking your real IP
curl -s https://ipleak.net/json/ | python3 -m json.tool

# ── dnsleaktest.com (via CLI) ─────────────────────────────
# Run the extended test
curl -s "https://dnsleaktest.com/index.html" | grep -i "dns"
# Or use their API:
curl -s "https://dnsleaktest.com/api/v1/status"

# ── bashooka DNS leak test ────────────────────────────────
# Resolves a unique subdomain to see which resolver sees it
UNIQUE_ID=$(openssl rand -hex 8)
dig +short "${UNIQUE_ID}.bashooka.com"

# ── Extended: Check what DNS resolvers are visible ───────
for dns_test_host in whoami.akamai.net whoami.ultradns.net; do
    dig +short "$dns_test_host" @8.8.8.8
done

# ── Comprehensive Python leak test ────────────────────────
python3 -c "
import requests, json

def test_dns_leak():
    # Test multiple leak detection services
    tests = {
        'ipleak': 'https://ipleak.net/json/',
        'myip': 'https://api.myip.com',
        'ipify': 'https://api.ipify.org?format=json',
    }
    for name, url in tests.items():
        try:
            r = requests.get(url, timeout=10)
            print(f'[{name}] {r.json()}')
        except Exception as e:
            print(f'[{name}] FAILED: {e}')

test_dns_leak()
"

# ═══════════════════════════════════════════════════════════
# 2. DNS LEAK DETECTION — Local packet capture
# ═══════════════════════════════════════════════════════════
# Monitor DNS queries leaving the machine (passive detection)
# Start this in a separate terminal BEFORE running any DNS queries
sudo tcpdump -i eth0 -n port 53 2>/dev/null

# Watch specifically for queries going outside of expected DNS servers
sudo tcpdump -i eth0 -n port 53 and 'not host 127.0.0.1' 2>/dev/null

# Monitor all UDP/53 traffic (including through tunnel)
sudo tcpdump -i any -n udp port 53 -e -v 2>/dev/null

# IPv6 DNS leak check
sudo tcpdump -i any -n ip6 and udp port 53 2>/dev/null

# ═══════════════════════════════════════════════════════════
# 3. DNS OVER TLS (DoT) — Secure DNS configuration
# ═══════════════════════════════════════════════════════════
# ── systemd-resolved with DoT ──────────────────────────────
cat >> /etc/systemd/resolved.conf.d/dns-over-tls.conf << 'DOTCONF'
[Resolve]
DNS=1.1.1.1 9.9.9.9
DNSOverTLS=yes
DNSSEC=yes
Cache=no
DOTCONF

sudo systemctl restart systemd-resolved

# Verify DoT is active
resolvectl status
resolvectl query example.com

# ── stubby (DNS-over-TLS daemon) ──────────────────────────
# apt install stubby
# Configure in /etc/stubby/stubby.yml
sudo systemctl restart stubby
# Point systemd-resolved to stubby:
resolvectl dns lo 127.0.0.1
resolvectl default-route lo false

# ═══════════════════════════════════════════════════════════
# 4. DNS OVER HTTPS (DoH) — Via cloudflared or direct
# ═══════════════════════════════════════════════════════════
# ── cloudflared (DoH proxy) ──────────────────────────────
# apt install cloudflared
cloudflared proxy-dns --port 5053 --upstream "https://1.1.1.1/dns-query"

# Test through the DoH proxy
dig @127.0.0.1 -p 5053 example.com +short

# ── Direct curl DoH request ──────────────────────────────
curl -s "https://cloudflare-dns.com/dns-query?name=example.com&type=A" \
    -H "accept: application/dns-json" | python3 -m json.tool

# ── Python DoH helper ────────────────────────────────────
python3 -c "
import requests, json
doh_servers = [
    'https://cloudflare-dns.com/dns-query',
    'https://dns.quad9.net/dns-query',
    'https://dns.google/dns-query',
]
params = {'name': 'example.com', 'type': 'A'}
headers = {'accept': 'application/dns-json'}
for server in doh_servers:
    try:
        r = requests.get(server, params=params, headers=headers, timeout=5)
        data = r.json()
        print(f'[{server}] {json.dumps(data[\"Answer\"], indent=2)}')
    except Exception as e:
        print(f'[{server}] FAILED: {e}')
"

# ═══════════════════════════════════════════════════════════
# 5. SYSTEMD-RESOLVED HARDENING
# ═══════════════════════════════════════════════════════════
# Force DNS through tunnel only (prevent direct queries)
cat > /etc/systemd/resolved.conf.d/force-tunnel.conf << 'HARDEN'
[Resolve]
DNS=127.0.0.1
Domains=~.
DNSStubListenerExtra=127.0.0.1
ReadEtcHosts=no
HARDEN

# Disable LLMNR (Link-Local Multicast Name Resolution)
cat > /etc/systemd/resolved.conf.d/disable-llmnr.conf << 'LLMNR'
[Resolve]
LLMNR=no
MulticastDNS=no
LLMNRNetworks=
HARDEN

sudo systemctl restart systemd-resolved

# ═══════════════════════════════════════════════════════════
# 6. /etc/resolv.conf HARDENING
# ═══════════════════════════════════════════════════════════
# Prevent the system from leaking DNS through ISP resolvers
# Check current state
ls -la /etc/resolv.conf

# If it's a symlink to systemd-resolved stub:
# /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf

# Lock it from being overwritten:
sudo chattr +i /etc/resolv.conf

# Or write a static hardened version:
cat > /tmp/resolv.conf.hardened << 'RESOLV'
# Hardened /etc/resolv.conf — only local stub listeners
# All DNS goes through DoT/DoH or tunnel
nameserver 127.0.0.1
options edns0 trust-ad
search .
RESOLV

sudo cp /tmp/resolv.conf.hardened /etc/resolv.conf
sudo chattr +i /etc/resolv.conf

# ═══════════════════════════════════════════════════════════
# 7. DNSSEC VALIDATION — Ensure DNS integrity
# ═══════════════════════════════════════════════════════════
# Verify DNSSEC is active
dig example.com +dnssec +multi

# Check AD flag (Authenticated Data)
dig example.com +dnssec | grep flags

# Test DNSSEC validation with known good domain
dig sigfail.verteiltesysteme.net @127.0.0.1
# Should return SERVFAIL (signed, invalid = proper validation)

# Test with known valid domain
dig sigok.verteiltesysteme.net @127.0.0.1
# Should return NOERROR (signed, valid)

# ═══════════════════════════════════════════════════════════
# 8. DNS REQUEST ROUTING VERIFICATION
# ═══════════════════════════════════════════════════════════
# Confirm all DNS traffic goes through your chosen anonymity layer
# ── While Tor is active ──────────────────────────────────
# Verify querying through Tor:
curl -x socks5://127.0.0.1:1080 "https://dnsleaktest.com/api/v1/status"

# ── Check actual DNS server being used ───────────────────
# Tool: dnstraceroute
dnstraceroute example.com

# ── Query a well-known exact-IP DNS test ─────────────────
# If you see your real ISP resolver in the chain → LEAK
dig +short myresolver.com @1.1.1.1

# ── Passive: confirm no direct DNS leaves ────────────────
sudo tcpdump -i eth0 -n 'udp port 53 and not src net 127.0.0.0/8' -c 1 -t 10
# If this captures ANYTHING, DNS is leaking
```

## OPSEC Rules

- **Run DNS leak check BEFORE and AFTER starting anonymity layer** — compare results
- If `tcpdump` shows ANY UDP/53 traffic leaving the physical interface, DNS is leaking — stop immediately
- Never use your ISP's DNS resolvers — they log everything and tie queries to your IP
- DoH is harder to inspect but easier to defend against (just block all UDP/53)
- Some corporate environments use DHCP-injected DNS servers — override explicitly
- IPv6 DNS is often forgotten — always check `ip6 and udp port 53`
- `systemd-resolved` caches may retain pre-anonymity entries — flush after setting up: `resolvectl flush-caches`
- The `+i` immutable flag on `/etc/resolv.conf` survives reboots but prevents legitimate DHCP updates
- DNSSEC validation adds latency but prevents DNS spoofing — weigh need vs. performance
- Check `/etc/nsswitch.conf` for `mdns` or `wins` entries that could bypass DNS

## Verification

- [ ] `tcpdump -i any -n udp port 53` shows NO traffic on physical interfaces after anonymity enable
- [ ] `curl -x socks5://127.0.0.1:1080 https://ipleak.net/json/` shows the exit IP, not the real IP
- [ ] `dig +short whoami.akamai.net @127.0.0.1` shows the anonymized resolver hostname
- [ ] DNSSEC: `dig sigfail.verteiltesysteme.net` returns SERVFAIL (validation working)
- [ ] DoT: `resolvectl status` shows the DNS-over-TLS server (1.1.1.1/853)
- [ ] `/etc/resolv.conf` points to localhost only (127.0.0.1)
- [ ] No IPv6 DNS queries captured on physical interface

## Pitfalls

- **split-DNS environments** route internal domains (`.corp`, `.internal`) to corporate resolvers — expect leaks for those
- **Docker bridge networks** use their own DNS resolver (127.0.0.11) — may bypass system-wide DoT/DoH
- **Chrome's built-in DoH** bypasses system DNS entirely if configured — disable `chrome://flags/#enable-dns-over-https` or point it correctly
- **VPN kill switch failure**: If VPN drops, DNS falls back to ISP — always use a kill switch (`iptables -A OUTPUT -p udp --dport 53 -j DROP`)
- **systemd-resolved stub** on 127.0.0.53 does NOT encrypt — it just forwards to configured upstream
- **WSL2** uses the Windows host's DNS — you must configure DNS in Windows, not inside WSL
- **mDNS (.local)** is multicast not unicast — won't appear in tcpdump for port 53 but still leaks network info
- **VPN provider's own DNS** may also leak — treat the VPN DNS as untrusted until verified

## Output Format

```json
{
  "skill": "anonymity-dns-leak",
  "status": "clean|leak|fail",
  "detected_leaks": {
    "ipv4_leak": false,
    "ipv6_leak": false,
    "isp_dns_visible": false,
    "real_ip_exposed": false
  },
  "resolvers_seen": ["127.0.0.1#53", "1.1.1.1#853"],
  "dnssec_valid": true,
  "doh_available": true,
  "dot_available": true,
  "active_dns_mode": "DoT|DoH|cleartext",
  "resolved_at": "2026-07-13T12:00:00Z"
}
```
