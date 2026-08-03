---
name: db-oracle-enum
description: Enumerar Oracle Database — TNS listener, SID enumeration, versión, XML DB, APEX, usuarios default
phase: enum
---

# db-oracle-enum

## Activation Contract

- **Trigger**: Se detectan puertos 1521 (TNS listener), 8080 (XML DB / APEX) o 5500 (EM Express) abiertos.
- **Target**: IP o hostname con Oracle Database expuesto.
- **Dependencies**: `nmap` (scripts oracle-*), `odat` (Oracle Database Attacking Tool), `tnscmd10g.pl`, `python3`, `sqlplus`.
- **Expected outcome**: Versión de Oracle, lista de SIDs, service names, usuarios default detectables, estado de XML DB y APEX.

## Hard Rules

1. NO modificar parámetros del listener (`SET`, `STOP`, `RELOAD`).
2. NO intentar login con credenciales que no sean las default conocidas (scott/tiger, system/manager, sys/change_on_install, dbsnmp/dbsnmp).
3. Si se detecta Oracle XML DB (8080), solo hacer GET — NO hacer PUT/POST.
4. ODAT solo en modo enumeración — NO usar módulos de explotación.
5. Rate limit: 2 segundos entre intentos de SID brute force.
6. Todo hallazgo debe incluir versión de Oracle, puerto y SID/service_name.

## Decision Gates

Usar `question()` antes de:

- Ejecutar SID brute force (`oracle-sid-brute` de nmap) — genera múltiples conexiones al listener y es muy visible.
- Conectarse con `sqlplus` usando credenciales default — es una conexión activa a la base de datos.
- Escanear el puerto 8080 para Oracle XML DB — puede tener servicios HTTP colgando.
- Usar `odat` en modo `all` sobre el target.

## Execution Steps

### Paso 1: Detectar TNS listener y versión
```bash
# Escaneo de puertos Oracle
nmap -p 1521,1522,1523,1524,8080,5500 -sV --version-intensity 9 <target>

# Versión vía script de nmap
nmap -p 1521 --script oracle-tns-version <target>

# Usando tnscmd10g
tnscmd10g.pl -h <target> version
```

### Paso 2: Enumerar SIDs y service names
```bash
# Brute force de SIDs con nmap
nmap -p 1521 --script oracle-sid-brute --script-args "oraclesids=/usr/share/nmap/nselib/data/oracle-sids" <target>

# Con odat
odat sidguesser -s <target> -p 1521
```

También probar con service names conocidos:
- XE, ORCL, ORCLPDB, LISTENER, PLSExtProc, CLRExtProc.

### Paso 3: Verificar estado del listener
```bash
tnscmd10g.pl -h <target> status
tnscmd10g.pl -h <target> ping
```

### Paso 4: Probar credenciales default
```bash
# Con odat
odat passwordstealer -s <target> -p 1521 -d <SID> --accounts-files /usr/share/odat/accounts/default.txt

# Probar manualmente con sqlplus
sqlplus scott/tiger@//<target>:1521/<SID>
sqlplus system/manager@//<target>:1521/<SID>
```

### Paso 5: Detectar Oracle XML DB y APEX
```bash
# XML DB en 8080
curl -s http://<target>:8080/ | head -20
curl -s http://<target>:8080/xdb/ | head -20

# APEX (Application Express)
curl -s http://<target>:8080/apex/ | head -20
curl -s http://<target>:8080/ords/ | head -20
```

### Paso 6: Enumerar SIDs con response del listener
```bash
# Con python — script que parsea TNS responses
python3 -c "
import socket
sids = ['XE','ORCL','ORCLPDB','LISTENER','PLSExtProc']
for sid in sids:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(('<target>', 1521))
    pkt = b'\\x00\\x5a\\x00\\x00\\x01\\x00\\x00\\x00\\x01' + f'(CONNECT_DATA=(CID=(PROGRAM=)(HOST=)(USER=))(COMMAND=version)(SID={sid}))'.encode()
    s.send(pkt.ljust(91, b'\\x00'))
    resp = s.recv(1024)
    if b'(OK' in resp or b'VERSION' in resp:
        print(f'SID {sid} VÁLIDO: {resp}')
    s.close()
"
```

### Paso 7: Verificar EM Express
```bash
curl -s http://<target>:5500/em/ | head -10
```

### Paso 8: Detectar CVE-2012-1675 (TNS Poisoning)
```bash
nmap -p 1521 --script oracle-tns-poison <target>
```

## Output Contract

```json
{
  "phase": "enum",
  "skill": "db-oracle-enum",
  "target": "<target>",
  "open_ports": [
    {"port": 1521, "protocol": "TNS", "version": "Oracle Database 19c Enterprise Edition Release 19.0.0.0.0", "banner": "TNS for Linux: Version 19.0.0.0.0"},
    {"port": 8080, "protocol": "HTTP", "version": "Oracle XML DB 19c", "banner": "Oracle XML DB"}
  ],
  "valid_sids": [
    {"sid": "XE", "service_name": "XE.XDB"},
    {"sid": "ORCLPDB", "service_name": "ORCLPDB"}
  ],
  "default_creds": [
    {"user": "scott", "password": "tiger", "status": "locked"},
    {"user": "system", "password": "manager", "status": "success"}
  ],
  "xml_db": {"enabled": true, "port": 8080},
  "apex": {"enabled": false},
  "tns_poisonable": false,
  "findings": [
    {
      "title": "Oracle Database con credenciales default activas: system/manager",
      "severity": "critical",
      "category": "default-credentials",
      "cvss": 9.8,
      "cwe": "CWE-798",
      "evidence": "sqlplus system/manager@//<target>:1521/XE connect exitoso, DBA privileges confirmados vía SELECT * FROM session_roles",
      "remediation": "Cambiar contraseñas de system, sys, scott y todos los usuarios default. Implementar perfil de passwords.",
      "next_steps": ["Extraer password hashes de sys.user$", "Enumerar tablas con datos sensibles"]
    }
  ],
  "summary": "Oracle 19c con 2 SIDs válidos, credencial default system/manager activa con DBA, XML DB expuesto en 8080",
  "next_phase": "exploit",
  "recommended_skills": ["db-oracle-exploit", "hunt-sqli", "lateral-movement"]
}
```
