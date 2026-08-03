---
name: persistence
description: Establish persistence mechanisms on compromised systems
version: 1.0.0
phase: post
category: persistence
tags: [persistence, cron, systemd, ssh]
tools: [crontab, systemctl, bash]
difficulty: advanced
opsec_level: high
time_estimate: 30s
severity_if_found: high
related_skills:
  - privesc-linux
  - credential-harvest
mitre_attack:
  - T1053.003
  - T1543.002
---

## When to Use

Use this skill to verify that persistence mechanisms can be established on
compromised systems. This confirms long-term access is possible.

## Prerequisites

- Shell access (preferably with sudo)
- Write access to cron directories or systemd

## Procedure

```bash
# Check current cron jobs
crontab -l 2>/dev/null
ls -la /etc/cron* 2>/dev/null
cat /etc/crontab 2>/dev/null

# Check systemd services
systemctl list-unit-files | grep enabled
ls -la /etc/systemd/system/ 2>/dev/null

# Test cron persistence (benign test)
echo "# Test persistence - remove after assessment" | crontab -

# Check SSH key persistence
ls -la ~/.ssh/authorized_keys 2>/dev/null
cat ~/.ssh/authorized_keys 2>/dev/null

# Check for writable init scripts
find /etc/init.d/ -writable 2>/dev/null
```

## OPSEC Rules

- **CRITICAL**: Do not create actual persistence mechanisms
- Document what WOULD be possible
- Do not modify system configurations
- Do not create new users or SSH keys
- Do not install packages or services
- Clean up any test modifications

## Verification

- Verify cron directories are writable
- Check if systemd services can be created
- Confirm SSH keys can be added

## Pitfalls

- Some systems have immutable file attributes
- SELinux/AppArmor may restrict modifications
- Systemd may require root access
- Cron may be restricted to specific users

## Output Format

```
[PERSISTENCE] Cron job persistence possible
  Directory: /etc/cron.d/ (writable by www-data)
  Severity: HIGH

[PERSISTENCE] Systemd service persistence possible
  Directory: /etc/systemd/system/ (writable)
  Severity: HIGH

[PERSISTENCE] SSH key persistence possible
  File: ~/.ssh/authorized_keys (writable)
  Severity: MEDIUM
```
