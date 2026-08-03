---
name: evasion-process-injection
description: Técnicas de inyección de procesos en Windows — CreateRemoteThread, APC, Process Hollowing, Doppelganging, Thread Hijacking. Inyección de shellcode y DLL.
phase: post
---

# Evasion — Process Injection

## Activation Contract

**Trigger**: El usuario pide inyectar un payload en un proceso remoto, ejecutar shellcode, realizar DLL injection, o evadir EDR mediante técnicas de inyección de procesos en Windows.

**Preconditions**:
- Acceso a un host Windows con privilegios administrativos (o al menos DEBUG privilege).
- Payload compilado o shellcode generado (ver `evasion-av-bypass` para preparación).
- Conocimiento del proceso target a inyectar.

**Postconditions**:
- Carga ejecutándose en el espacio de direcciones del proceso remoto.
- Salida JSON con técnica usada, PID target, resultado.

---

## Hard Rules

1. **No inyectar en procesos críticos del sistema** (`csrss.exe`, `smss.exe`, `wininit.exe`) sin autorización explícita. Pueden crashear el sistema.
2. **Nunca dejar shellcode sin limpiar** en memoria después de la prueba si no hay persistencia acordada.
3. **Cada técnica debe registrarse** en el output con técnica, PID, y resultado (success/fail).
4. **No usar técnicas de inyección en entornos de producción** sin aprobación por escrito.

---

## Decision Gates

Antes de ejecutar **cualquier** técnica, preguntar vía `question()`:

| Pregunta | Opciones |
|----------|----------|
| Proceso target para inyección | `explorer.exe`, `notepad.exe`, `svchost.exe`, `runtimebroker.exe`, `custom` |
| Tipo de payload | `shellcode` (reverse TCP), `DLL` (archivo en disco), `powershell reflection` |
| Técnica de inyección | `CreateRemoteThread`, `APC`, `ProcessHollowing`, `ProcessDoppelganging`, `ThreadHijacking` |
| Confirmar acción intrusiva | `Yes - inyectar`, `No - solo reportar` |

---

## Execution Steps

### 1. Enumerar procesos target

```powershell
# Listar procesos target viables
Get-Process | Where-Object { $_.ProcessName -in @('explorer','notepad','svchost','runtimebroker') } | Select-Object Id, ProcessName, SessionId
```

### 2. CreateRemoteThread + WriteProcessMemory

```powershell
# C# P/Invoke para inyección clásica
$code = @'
[DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
[DllImport("kernel32.dll")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
[DllImport("kernel32.dll")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
'@
# Requiere: shellcode en bytes, PID target
```

### 3. APC Injection (QueueUserAPC)

```powershell
# Inyectar en hilo existente via cola APC
# 1. OpenProcess + VirtualAllocEx + WriteProcessMemory
# 2. QueueUserAPC al hilo target
# Útil cuando el thread entra en alertable state (WaitForSingleObjectEx)
```

### 4. Process Hollowing

```c
// Crear proceso suspendido, desmapear sección original,
// escribir nuevo PE en espacio, SetThreadContext + ResumeThread
// 1. CreateProcess(..., CREATE_SUSPENDED, ...)
// 2. NtUnmapViewOfSection(hProcess, imageBase)
// 3. VirtualAllocEx + WriteProcessMemory (cabeceras + secciones)
// 4. SetThreadContext (entry point)
// 5. ResumeThread
```

### 5. Process Doppelganging (TxF)

```c
// Usar Transactional NTFS (TxF) para cargar un PE fantasma
// 1. Crear transacción con CreateTransaction
// 2. Crear archivo temporal en la transacción, escribir payload
// 3. Mapear sección del archivo en memoria
// 4. Revertir transacción (el archivo "desaparece")
// 5. Rollback -> carga el PE desde la sección fantasma
// 6. CreateProcessAsUser con la sección
```

### 6. Thread Execution Hijacking

```powershell
# Secuestrar un hilo existente
# 1. OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT)
# 2. SuspendThread
# 3. GetThreadContext (guardar contexto original)
# 4. VirtualAllocEx + WriteProcessMemory (shellcode)
# 5. SetThreadContext (RIP = shellcode)
# 6. ResumeThread
```

### 7. DLL Injection

```powershell
# Carga de DLL en proceso remoto via LoadLibrary
# VirtualAllocEx -> WriteProcessMemory(ruta DLL) -> CreateRemoteThread(LoadLibrary)
$dllPath = "C:\path\to\evil.dll"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($dllPath)
# OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread(LoadLibrary)
```

---

## Output Contract

```json
{
  "phase": "post",
  "skill": "evasion-process-injection",
  "target": {
    "host": "WIN-XXXX",
    "process": "explorer.exe",
    "pid": 1234
  },
  "technique": "CreateRemoteThread",
  "payload": {
    "type": "shellcode",
    "size_bytes": 276,
    "hash_sha256": "abc123..."
  },
  "result": {
    "success": true,
    "thread_id": 5678,
    "detection_notes": "Windows Defender alertó en el momento de WriteProcessMemory"
  },
  "indicators": [
    "CreateRemoteThread call anomalo",
    "VirtualAllocEx con PAGE_EXECUTE_READWRITE",
    "Cross-process handle en proceso no-parent"
  ],
  "cleanup": "Terminar hilo inyectado y liberar memoria virtual"
}
```

## Referencias

- MITRE ATT&CK T1055.001 (CreateRemoteThread), T1055.003 (APC), T1055.012 (Hollowing), T1055.013 (Doppelganging)
- Win32 API: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- ntdll: NtUnmapViewOfSection, NtCreateThreadEx
