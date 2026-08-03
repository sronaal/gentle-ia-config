---
name: privesc-linux
description: Identify Linux privilege escalation paths from a low-privilege shell
version: 1.0.0
phase: post
category: privesc
tags: [linux, privesc, sudo, suid]
tools: [linpeas, linenum, sudo]
difficulty: intermediate
opsec_level: high
time_estimate: 60s
severity_if_found: high
related_skills:
  - credential-harvest
  - persistence
mitre_attack:
  - T1548.001
  - T1548.003
---

## When to Use

Use this skill after gaining a low-privilege shell to identify privilege
escalation paths including sudo misconfigs, SUID binaries, and writable paths.

## Prerequisites

- Shell access (low-privilege)
- linpeas.sh or linenum.sh
- sudo access (check sudo -l)

## Procedure

```bash
# Quick sudo check
sudo -l 2>/dev/null

# System information
uname -a
id
cat /etc/passwd | grep -v nologin | grep -v false

# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find writable directories
find / -writable -type d 2>/dev/null

# Check cron jobs
crontab -l 2>/dev/null
ls -la /etc/cron* 2>/dev/null
cat /etc/crontab 2>/dev/null

# Run linpeas (if available)
./linpeas.sh -a 2>/dev/null || echo "linpeas not found"
```

## OPSEC Rules

- **CRITICAL**: Do not modify system files or configurations
- Do not create new users or modify existing ones
- Do not install packages or services
- Do not restart services
- Document all findings before proceeding
- Stop after confirming privesc path exists

## Verification

- Verify sudo permissions are actually exploitable
- Check if SUID binaries are in standard locations
- Confirm cron jobs are writable by current user

## Pitfalls

- linpeas may take several minutes to run
- Some findings may be false positives
- SUID binaries may be in non-standard paths
- sudo configurations may have complex requirements

## Output Format

```
[PRIVESC] Sudo misconfiguration found
  Command: (ALL) NOPASSWD: /usr/bin/vim
  Exploit: sudo vim -c ':!/bin/sh'
  Severity: HIGH

[PRIVESC] SUID binary found
  Binary: /usr/local/bin/exploit
  Exploit: ./exploit
  Severity: HIGH
```
