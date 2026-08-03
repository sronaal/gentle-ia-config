---
name: privesc-windows
description: Identify Windows privilege escalation paths from a low-privilege shell
version: 1.0.0
phase: post
category: privesc
tags: [windows, privesc, services, registry]
tools: [WinPEAS, PowerUp]
difficulty: intermediate
opsec_level: high
time_estimate: 60s
severity_if_found: high
related_skills:
  - credential-harvest
  - persistence
mitre_attack:
  - T1548.002
  - T1574.001
---

## When to Use

Use this skill after gaining a low-privilege Windows shell to identify
privilege escalation paths including unquoted service paths, DLL hijacking,
and registry misconfigurations.

## Prerequisites

- PowerShell access (low-privilege)
- WinPEAS.exe or PowerUp.ps1
- Administrative access check: whoami /priv

## Procedure

```powershell
# Check current privileges
whoami /priv
whoami /groups
systeminfo

# Check services
sc query
wmic service list brief

# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# Check DLL hijacking
where.exe /R C:\ *.dll 2>$null

# Run WinPEAS
.\winpeas.exe

# Run PowerUp
. .\PowerUp.ps1
Invoke-AllChecks
```

## OPSEC Rules

- **CRITICAL**: Do not modify system configurations
- Do not create new users or modify existing ones
- Do not install packages or services
- Do not restart services
- Document all findings before proceeding
- Stop after confirming privesc path exists

## Verification

- Verify service permissions are actually exploitable
- Check if DLL hijacking paths are writable
- Confirm registry permissions allow modification

## Pitfalls

- WinPEAS may trigger antivirus detection
- Some findings require specific tools to exploit
- PowerShell execution policy may block scripts
- UAC may limit access to certain operations

## Output Format

```
[PRIVESC] Unquoted service path
  Service: MyApp
  Path: C:\Program Files\My App\service.exe
  Exploit: sc create ...
  Severity: HIGH

[PRIVESC] DLL Hijacking
  DLL: version.dll
  Path: C:\Program Files\My App\
  Exploit: Place malicious DLL in directory
  Severity: HIGH
```
