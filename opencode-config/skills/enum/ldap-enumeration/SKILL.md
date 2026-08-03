---
name: ldap-enumeration
description: LDAP directory enumeration for users, groups, and policies
version: 1.0.0
phase: enum
category: network
tags: [ldap, active-directory, users, groups]
tools: [ldapsearch, windapsearch]
difficulty: intermediate
opsec_level: medium
time_estimate: 60s
severity_if_found: medium
related_skills:
  - smb-enumeration
  - snmp-enumeration
mitre_attack:
  - T1018
  - T1087.002
---

## When to Use

Use this skill when port 389/636 (LDAP/LDAPS) is open and you want to enumerate
users, groups, organizational units, and password policies from an Active Directory
or OpenLDAP instance.

## Prerequisites

- ldapsearch (openldap-clients)
- windapsearch (optional, for AD enumeration)

## Procedure

```bash
# Step 1: Anonymous bind test
ldapsearch -h TARGET -x -b "dc=example,dc=com" -s base namingContexts

# Step 2: Enumerate all users
ldapsearch -h TARGET -x -b "dc=example,dc=com" "(objectClass=person)" | grep -E "^cn:|^sAMAccountName:|^mail:"

# Step 3: Enumerate groups
ldapsearch -h TARGET -x -b "dc=example,dc=com" "(objectClass=group)" | grep -E "^cn:|^member:"

# Step 4: Enumerate OUs
ldapsearch -h TARGET -x -b "dc=example,dc=com" "(objectClass=organizationalUnit)" dn

# Step 5: Check password policy
ldapsearch -h TARGET -x -b "dc=example,dc=com" "(objectClass=domain)" pwdHistoryLength lockoutThreshold

# Step 6: Find admins
ldapsearch -h TARGET -x -b "dc=example,dc=com" "(&(objectClass=user)(adminCount=1))" sAMAccountName

# Step 7: windapsearch (AD-specific)
windapsearch -d TARGET --dc-ip TARGET -u "" --users
windapsearch -d TARGET --dc-ip TARGET -u "" --groups

# Step 8: Enumerate computers
ldapsearch -h TARGET -x -b "dc=example,dc=com" "(objectClass=computer)" cn operatingSystem
```

## OPSEC Rules

- Do NOT attempt to bind with guessed credentials
- Do NOT modify any LDAP objects
- Limit queries to 10 per second
- Use anonymous bind when possible
- Log all queries for audit trail

## Verification

- Confirm anonymous bind returns namingContexts
- Verify user listing contains real accounts
- Check if password policy is readable

## Pitfalls

- LDAPS (636) requires TLS — use `-H ldaps://TARGET`
- Some servers disable anonymous bind
- AD may require specific object class filters
- Large directories may return truncated results

## Output Format

```
[LDAP]    DC: example.com — version: LDAPv3
[LDAP]    Users: admin, john.doe, jane.smith, svc_backup
[LDAP]    Groups: Domain Admins, Domain Users, IT, HR
[LDAP]    OUs: Servers, Workstations, Users
[POLICY]  Min length: 8, lockout: 5 attempts
[ADMIN]   admin, backup_admin — adminCount=1
```
