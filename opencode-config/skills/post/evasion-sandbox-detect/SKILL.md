---
name: evasion-sandbox-detect
description: Detección de sandboxes y entornos de análisis (VMware, VirtualBox, VMs genéricas) — MAC addresses, hardware, registry, procesos, timers diferenciales.
phase: post
---

# Evasion — Sandbox Detection

## Activation Contract

**Trigger**: El usuario pide detectar si está en una VM/sandbox, evadir análisis automatizado, adaptar comportamiento según entorno, o implementar anti-VM checks.

**Preconditions**:
- Capacidad de ejecutar código en el host target (Windows o Linux).
- Acceso a información de hardware y sistema (no necesariamente admin).

**Postconditions**:
- Diagnóstico de entorno: `sandbox`, `vm`, `bare-metal`, `indeterminado`.
- Si es sandbox: comportamiento alterado (no ejecutar payload).
- Salida JSON con checks ejecutados y veredicto.

---

## Hard Rules

1. **No asumir que es sandbox por un solo check** — correlacionar múltiples indicadores.
2. **En sandbox confirmado, no ejecutar payload intrusivo** sin preguntar.
3. **Documentar todos los checks** para que el usuario entienda el veredicto.
4. **Timers diferenciales pueden ser detectados** por el sandbox — usarlos con precaución.

---

## Decision Gates

| Pregunta | Opciones |
|----------|----------|
| ¿Adaptar comportamiento si se detecta sandbox? | `Yes - detener acción`, `No - reportar y continuar`, `Solo reportar` |
| ¿Usar timers diferenciales (RDTSC)? | `Yes`, `No - puede alertar` |
| Checks a ejecutar | `All`, `Hardware only`, `Processes only`, `Registry/FS only` |

---

## Execution Steps

### 1. MAC Address Check

```powershell
# Identificar MACs conocidas de hypervisors
$vmMacs = @(
    "00:50:56",  # VMware
    "00:0C:29",  # VMware
    "00:05:69",  # VMware
    "00:1C:42",  # Parallels
    "00:03:FF",  # MS Hyper-V
    "00:15:5D",  # Hyper-V
    "08:00:27",  # VirtualBox
    "52:54:00"   # QEMU/KVM
)

Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -eq $true } |
    ForEach-Object {
        $mac = $_.MACAddress -replace '-',':' -replace ' ',''
        $matched = $vmMacs | Where-Object { $mac.StartsWith($_) }
        if ($matched) { Write-Output "[!] VM MAC detected: $mac ($matched)" }
    }
```

```bash
# Linux: check MAC de hypervisor
ip link | grep -iE "00:50:56|00:0c:29|00:05:69|08:00:27|52:54:00" && echo "[!] VM detected via MAC"
```

### 2. Hardware Check (CPU, RAM, Disk)

```powershell
# CPU count (VMs suelen tener pocos cores)
$cpuCount = (Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors
$ramGB = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
$diskGB = (Get-WmiObject Win32_DiskDrive | Measure-Object -Property Size -Sum).Sum / 1GB

# Firmas típicas de sandbox
if ($cpuCount -le 2) { Write-Output "[!] Pocos CPUs: $cpuCount" }
if ($ramGB -lt 4GB) { Write-Output "[!] Poca RAM: $([math]::Round($ramGB,1)) GB" }
if ($diskGB -lt 80GB) { Write-Output "[!] Disco pequeño: $([math]::Round($diskGB,1)) GB" }
```

```bash
# Linux hardware check
cpu=$(nproc)
ram=$(grep MemTotal /proc/meminfo | awk '{print $2/1048576}')
disk=$(df / | tail -1 | awk '{print $2/1048576}')
echo "CPUs: $cpu, RAM: ${ram}GB, Disk: ${disk}GB"
[ "$cpu" -le 2 ] && echo "[!] Pocos CPUs"
```

### 3. Registry Artifacts (Windows)

```powershell
# Check de registry que indican VM
$checks = @(
    @{Path="HKLM:\HARDWARE\DESCRIPTION\System\BIOS"; Property="SystemManufacturer"; Value="VMware|VirtualBox|QEMU|innotek"},
    @{Path="HKLM:\HARDWARE\DESCRIPTION\System\BIOS"; Property="SystemProductName"; Value="VirtualBox|VMware|Virtual Machine"},
    @{Path="HKLM:\SOFTWARE\VMware, Inc."; Property=$null; Value=$null},                    # VMware Tools
    @{Path="HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"; Property=$null; Value=$null}, # VBox GA
    @{Path="HKLM:\SYSTEM\ControlSet001\Services\Disk"; Property="Vendor"; Value="VMware|VBOX"},
    @{Path="HKLM:\HARDWARE\ACPI\DSDT\VBOX__"; Property=$null; Value=$null}
)

foreach ($check in $checks) {
    if (Test-Path $check.Path) {
        if ($check.Property) {
            $val = (Get-ItemProperty $check.Path).$($check.Property)
            if ($val -match $check.Value) {
                Write-Output "[!] VM registry: $($check.Path)\$($check.Property) = $val"
            }
        } else {
            Write-Output "[!] VM registry key exists: $($check.Path)"
        }
    }
}
```

### 4. Filesystem Artifacts

```powershell
# Archivos de herramientas de VM
$vmFiles = @(
    "C:\Windows\System32\vmtoolsd.exe",       # VMware Tools
    "C:\Windows\System32\VBoxGuest.sys",       # VirtualBox
    "C:\Program Files\Oracle\VirtualBox Guest Additions\*",
    "C:\Program Files\VMware\VMware Tools\*",
    "C:\Windows\Drivers\VMBus\*.sys"          # Hyper-V
)

foreach ($file in $vmFiles) {
    if (Test-Path $file) { Write-Output "[!] VM artifact: $file" }
}
```

```bash
# Linux: archivos de VM tools
lsmod | grep -iE "vbox|vmw|kvm|virtio" && echo "[!] VM drivers loaded"
ls /usr/lib/virtualbox/VBoxGuestAdditions/ 2>/dev/null && echo "[!] VBox GA"
ls /usr/lib/vmware-tools/ 2>/dev/null && echo "[!] VMware Tools"
```

### 5. Procesos de Análisis (Sandbox/Security Tools)

```powershell
$analysisProcs = @(
    "procmon", "processhacker", "wireshark", "windbg", "x64dbg",
    "vmtoolsd", "vboxservice", "vboxtray",
    "procmon64", "tcpview", "fiddler", "burp",
    "dumpcap", "python*", "idag", "ida64"
)

$procs = Get-Process | Where-Object { $_.ProcessName -in $analysisProcs }
if ($procs) {
    Write-Output "[!] Sandbox processes detected:"
    $procs | Select-Object ProcessName, Id, StartTime
}
```

```bash
# Linux: procesos de análisis
ps aux | grep -iE "strace|ltrace|gdb|perf|sysdig|tcpdump|wireshark|burp" | grep -v grep && echo "[!] Analysis tools running"
```

### 6. Timers Diferenciales (RDTSC)

```csharp
// Detectar sandbox via diferencia en RDTSC
// En sandboxes el tiempo simulado tiene skew detectable

// 1. Leer RDTSC antes
// 2. Sleep(1000)
// 3. Leer RDTSC después
// 4. Si la diferencia es mucho menor (o exacta), es sandbox

ulong tsc1 = __rdtsc();
Thread.Sleep(1000);
ulong tsc2 = __rdtsc();
ulong diff = tsc2 - tsc1;
// CPU 2GHz ~ 2e9 ciclos/seg, si diff ~ 10x menor -> sandbox
```

```powershell
# PowerShell timer check
$start = Get-Date
Start-Sleep -Milliseconds 500
$elapsed = (Get-Date) - $start

# Si el sleep real es muy diferente al esperado -> sandbox
if ($elapsed.TotalMilliseconds -lt 100 -or $elapsed.TotalMilliseconds -gt 2000) {
    Write-Output "[!] Timer skew detected - possible sandbox ($($elapsed.TotalMilliseconds)ms vs 500ms)"
}
```

### 7. Veredicto Final

```powershell
# Scoring de detección (peso por check)
$score = 0
# MAC: +20, Registry: +20, Files: +20, CPU<=2: +10, RAM<4GB: +10, Procs: +20

if ($score -ge 50) {
    $veredict = "sandbox"
} elseif ($score -ge 20) {
    $veredict = "probable_vm"
} else {
    $veredict = "bare_metal"
}

# En sandbox, no ejecutar payload
if ($veredict -eq "sandbox") { exit }
```

---

## Output Contract

```json
{
  "phase": "post",
  "skill": "evasion-sandbox-detect",
  "target": {
    "host": "WIN-XXXX",
    "os": "Windows 10 Pro 22H2"
  },
  "checks": [
    {"check": "mac_address", "detected": true, "value": "00:0C:29:AB:CD:EF", "weight": 20},
    {"check": "cpu_count", "detected": true, "value": "1 core", "weight": 10},
    {"check": "ram_size", "detected": true, "value": "2.0 GB", "weight": 10},
    {"check": "registry_manufacturer", "detected": true, "value": "VMware, Inc.", "weight": 20},
    {"check": "process_vmtoolsd", "detected": true, "value": "vmtoolsd.exe", "weight": 20}
  ],
  "score": 80,
  "veredict": "sandbox",
  "action": "payload_suppressed",
  "recommendation": "Reintentar con payload ofuscado en target bare-metal"
}
```

## Referencias

- MITRE ATT&CK T1497 (Virtualization/Sandbox Evasion)
- RDTSC differential timing
- MAC OUI table: VMware, VirtualBox, Hyper-V, QEMU
