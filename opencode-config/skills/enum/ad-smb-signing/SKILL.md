---
name: ad-smb-signing
description: Check SMB signing status across domain hosts
phase: enum
category: active-directory
tags: [ad, smb, signing, relay, windows]
tools: [nmap, smbclient, impacket]
difficulty: basic
opsec_level: passive
time_estimate: 60s
severity_if_found: medium
---

## When to Use

Use this skill to identify hosts where SMB signing is disabled — these hosts
are vulnerable to SMB relay attacks and NTLM credential forwarding.

## Prerequisites

```bash
# Install nmap for SMB script scanning
apt install nmap -y

# Install smbclient for manual verification
apt install smbclient -y

# Install impacket for advanced checks
pip install impacket
```

## Procedure

```bash
# Step 1: Scan subnet for SMB signing status via nmap
nmap -p 445 --script smb-security-mode TARGET

# Step 2: Targeted check on specific hosts
nmap -p 445 --script smb-security-mode TARGET_NETWORK/24 -oN smb-signing.txt

# Step 3: Manual smbclient verification
smbclient -L //TARGET -N

# Step 4: Impacket signing check
smbclient -L //TARGET -N | grep -i "signing"
```

## OPSEC Rules

- SMB signing checks via nmap scripts are passive (no auth required)
- Do NOT attempt to relay captured credentials without authorization
- Do NOT connect to SMB shares beyond anonymous enumeration
- Scan during off-peak hours to avoid SMB service disruption

## Verification

- `smb-security-mode` script output shows `message_signing: required` or `disabled`
- `smbclient -L //TARGET -N` success confirms SMB reachable
- Cross-check with `nmap` and `impacket` results for accuracy

## Pitfalls

- Domain controllers often require SMB signing — non-DC servers may not
- Newer Windows versions enable signing by default (Server 2019+, Win11)
- Firewalls may block SMB — scan only within the trusted network
- `smbclient -N` may hang on some hosts — set short timeout

## Output Format

```
[SMB-SIGNING] Host: dc01.domain.local (10.0.1.10)
[SMB-SIGNING] Port: 445 — SMB signing: REQUIRED (secure)
[SMB-SIGNING] Host: sql01.domain.local (10.0.1.20)
[SMB-SIGNING] Port: 445 — SMB signing: DISABLED (vulnerable to relay)
```
