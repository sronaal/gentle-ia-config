---
name: ad-bloodhound-ingest
description: Collect Active Directory data for BloodHound analysis
phase: enum
category: active-directory
tags: [ad, bloodhound, ace, path, windows]
tools: [bloodhound-python, sharphound, neo4j]
difficulty: medium
opsec_level: active
time_estimate: 300s
severity_if_found: info
---

## When to Use

Use this skill when you have valid domain credentials and need to map AD
relationships — users in groups, computers as admins, ACL-based attack
paths — for BloodHound graph analysis.

## Prerequisites

```bash
# Install bloodhound-python (Linux collector)
pip install bloodhound

# neo4j + bloodhound GUI (post-processing)
apt install neo4j -y
```

## Procedure

```bash
# Step 1: BloodHound Python — collect all data
bloodhound-python -d DOMAIN -u USER -p PASS -dc DC01.DOMAIN.LOCAL \
  -c All -ns DNS_SERVER

# Step 2: Collection using LDAP (if DNS not available)
bloodhound-python -d DOMAIN -u USER -p PASS -dc DC01.DOMAIN.LOCAL \
  -c All --dns-timeout 3 --no-smb

# Step 3: Specific collection methods (faster, targeted)
bloodhound-python -d DOMAIN -u USER -p PASS -dc DC01.DOMAIN.LOCAL \
  -c Group,Session,Trusts

# Step 4: SharpHound (Windows — run on domain-joined machine)
# .\SharpHound.exe -c All --domain DOMAIN.LOCAL --ldapuser USER --ldappass PASS

# Step 5: Verify output
ls -la *_bloodhound.zip
```

## OPSEC Rules

- BloodHound collection generates significant LDAP traffic — expect EDR alerts
- Event ID 4662 (Directory Service Access) is triggered for each query
- Use `-c Group,Session` for faster, lower-noise collection
- Do NOT store BloodHound JSON files on the target machine
- Clean up SharpHound.exe and output files after transfer

## Verification

- Confirm `.zip` output file contains JSON files
- Verify `computers.json`, `users.json`, `groups.json` are non-empty
- Test import into BloodHound GUI: `neo4j console` → upload ZIP

## Pitfalls

- Large domains may generate 50-500 MB of data
- `-c All` may take 5+ minutes on domains with 10,000+ objects
- SMB collection requires port 445 access
- LDAP collection may fail if DNS resolution is incorrect
- BloodHound Python requires Python 3.7+

## Output Format

```
[BLOODHOUND] Collector: bloodhound-python (Linux)
[BLOODHOUND] Domain: domain.local — DC: dc01.domain.local
[BLOODHOUND] Users: 2,340 | Groups: 187 | Computers: 64 | OUs: 28
[BLOODHOUND] Output: 20240612_domain_local_bloodhound.zip (12.4 MB)
[BLOODHOUND] Attack paths: 45 high-value (DA equiv), 23 constrained delegation
```
