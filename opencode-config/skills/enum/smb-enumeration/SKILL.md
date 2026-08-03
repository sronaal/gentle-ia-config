---
name: smb-enumeration
description: SMB and NetBIOS enumeration for shared folders and users
version: 1.0.0
phase: enum
category: network
tags: [smb, netbios, windows, shares]
tools: [nmap, smbclient, enum4linux]
difficulty: basic
opsec_level: medium
time_estimate: 60s
severity_if_found: medium
related_skills:
  - ldap-enumeration
  - snmp-enumeration
mitre_attack:
  - T1135
  - T1018
---

## When to Use

Use this skill when port 445/139 is open and you want to enumerate SMB shares,
users, policies, and groups on a Windows or Samba host.

## Prerequisites

- nmap with smb scripts
- smbclient
- enum4linux-ng (preferred over legacy enum4linux)

## Procedure

```bash
# Step 1: Scan for SMB with nmap scripts
nmap -p445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery TARGET -oN smb_nmap.txt

# Step 2: Check SMB version
nmap -p445 --script=smb-security-mode TARGET

# Step 3: List shares with smbclient
smbclient -L //TARGET -N
smbclient -L //TARGET -U guest%

# Step 4: Connect to accessible shares
smbclient //TARGET/ShareName -N -c "ls"
smbclient //TARGET/ShareName -U user%pass -c "ls"

# Step 5: enum4linux full enumeration
enum4linux -a TARGET | tee enum4linux_output.txt

# Step 6: Check for null session
rpcclient -U "" TARGET -N -c "enumdomusers"
rpcclient -U "" TARGET -N -c "enumdomgroups"

# Step 7: Check for anonymous access to specific shares
smbclient //TARGET/IPC$ -N -c "help"

# Step 8: List accessible files recursively
smbclient //TARGET/ShareName -N -c "recurse;ls"
```

## OPSEC Rules

- Do NOT modify or delete files on shares
- Do NOT attempt to brute-force SMB passwords
- Limit connections to 10 per minute
- Do not copy large files without authorization
- Log all connections for audit trail

## Verification

- Confirm SMB port is actually 445/139
- Verify shares are real (not honeypots)
- Check if null session actually works

## Pitfalls

- SMBv1 is disabled on modern Windows
- Some shares require domain authentication
- Firewall may allow port 445 but block SMB protocol
- Samba shares may have different permission model

## Output Format

```
[SMB]     TARGET:445 — SMBv3.1.1 — Windows Server 2019
[SMB]     Shares: Public, Finance, IT, IPC$
[SMB]     Public — READ (no auth required)
[SMB]     Finance — READ (user: guest)
[USER]    admin, backup_op, svc_sql
[POLICY]  Password history: 24, min length: 14
```
