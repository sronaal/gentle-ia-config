---
name: ad-ldap-domain-dump
description: Dump Active Directory domain info via LDAP anonymous or authenticated binds
phase: enum
category: active-directory
tags: [ad, ldap, domain, windows, authentication]
tools: [ldapsearch, nmap, ad-ldap-domain-dump]
difficulty: medium
opsec_level: passive
time_estimate: 120s
severity_if_found: high
---

## When to Use

Use this skill when LDAP (389) or LDAPS (636) is open on a domain controller and
you need to extract domain objects — users, groups, computers, OUs, and password
policy — via anonymous or low-privilege binds.

## Prerequisites

```bash
# Install ldapsearch (openldap-clients)
apt install ldap-utils -y

# Install nmap for port discovery
apt install nmap -y
```

## Procedure

```bash
# Step 1: Verify LDAP port is open
nmap -p 389,636 -sV TARGET

# Step 2: Anonymous bind test and base DN discovery
ldapsearch -H ldap://TARGET -x -s base namingContexts

# Step 3: Extract domain users
ldapsearch -H ldap://TARGET -x -b "DC=domain,DC=local" \
  "(objectClass=user)" sAMAccountName mail displayName | \
  grep -E "^sAMAccountName:|^mail:|^displayName:"

# Step 4: Extract domain groups
ldapsearch -H ldap://TARGET -x -b "DC=domain,DC=local" \
  "(objectClass=group)" cn member | grep -E "^cn:|^member:"

# Step 5: Extract domain computers
ldapsearch -H ldap://TARGET -x -b "DC=domain,DC=local" \
  "(objectClass=computer)" cn operatingSystem dNSHostName

# Step 6: Extract domain policy
ldapsearch -H ldap://TARGET -x -b "DC=domain,DC=local" \
  "(objectClass=domain)" pwdHistoryLength lockoutThreshold
```

## OPSEC Rules

- Use anonymous binds only — do not guess credentials
- Do NOT modify or delete any LDAP objects
- Rate-limit queries to avoid LDAP lockout
- LDAP queries are logged on the domain controller (event ID 4662)
- Passive opsec — no authentication required

## Verification

- Confirm `namingContexts` is returned from anonymous bind
- Verify user list contains real sAMAccountName values
- Check that computer objects match known domain hosts

## Pitfalls

- Anonymous bind may be disabled on hardened DCs
- LDAPS (636) requires TLS — use `-H ldaps://TARGET -Z`
- Large domains may truncate results — use `-LLL` and pagination
- Replace `DC=domain,DC=local` with the actual base DN from Step 2

## Output Format

```
[LDAP-DUMP] DC: dc01.domain.local (10.0.1.10)
[LDAP-DUMP] Base DN: DC=domain,DC=local
[LDAP-DUMP] Users: admin, jdoe, svc_sql, backup_user (14 total)
[LDAP-DUMP] Groups: Domain Admins, Domain Users, IT, HR, SQL Admins
[LDAP-DUMP] Computers: dc01, sql01, ws001-ws050
[LDAP-POLICY] Min pwd length: 8, lockout threshold: 5
```
