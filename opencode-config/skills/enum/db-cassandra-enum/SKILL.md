---
name: db-cassandra-enum
description: Enumerar bases de datos Apache Cassandra — keyspaces, tablas, auth deshabilitado, config files y JMX
phase: enum
---

# db-cassandra-enum

## Activation Contract

- **Trigger**: Se detectan puertos 9042 (CQL), 9160 (Thrift), 7000 (internode) o 7199 (JMX) abiertos en un target.
- **Target**: IP o hostname con Cassandra expuesto.
- **Dependencies**: `cqlsh`, `nmap`, `curl`, `python3`, `netcat`.
- **Expected outcome**: Listado de keyspaces, tablas, estado de autenticación, config expuesta y superficie JMX.

## Hard Rules

1. NO ejecutar `DROP`, `TRUNCATE`, `DELETE` ni ningún comando de escritura en la base de datos.
2. NO intentar hacer login con credenciales que no sean default (cassandra/cassandra).
3. Si se detecta auth habilitado, REPORTAR pero NO intentar fuerza bruta.
4. Si JMX está expuesto (7199), solo verificar accesibilidad — NO intentar RCE vía JMX.
5. Mantener rate limit de 1 request cada 2 segundos.
6. Todo hallazgo debe incluir puerto, protocolo y evidencia concreta (banner, response, error).

## Decision Gates

Usar `question()` antes de:

- Conectarse a CQLSH para enumerar keyspaces (es una acción intrusiva sobre el protocolo de datos).
- Leer cassandra.yaml vía JMX sin credenciales (puede activar alertas).
- Escanear el rango de puertos 7000-7001 (internode gossip) — puede ser visto como ataque.

## Execution Steps

### Paso 1: Detectar puertos
```bash
# Escaneo específico de puertos Cassandra
nmap -p 9042,9160,7000,7001,7199 -sV --version-intensity 5 <target>
```
Registrar que puertos están abiertos y sus banners.

### Paso 2: Probar CQLSH con auth default
```bash
cqlsh <target> 9042 -u cassandra -p cassandra
```
Si falla, probar sin autenticación:
```bash
cqlsh <target> 9042 --no-auth
```

### Paso 3: Enumerar keyspaces y tablas
Desde CQLSH:
```cql
DESCRIBE keyspaces;
DESCRIBE tables;
SELECT * FROM system_schema.keyspaces;
SELECT keyspace_name, table_name FROM system_schema.tables;
```
Si hay acceso, listar tablas en cada keyspace y contar filas:
```cql
SELECT COUNT(*) FROM <keyspace>.<table>;
```

### Paso 4: Enumerar config files vía Thrift (9160)
Si Thrift está expuesto:
```bash
# Intentar leak de cassandra.yaml vía Thrift API
curl -s http://<target>:9160/cassandra.yaml
```
O vía JMX si está disponible:
```bash
curl -s http://<target>:7199/jolokia/read/Cassandra:type=Config
```

### Paso 5: Detectar JMX expuesto
```bash
nmap -p 7199 -sV <target>
curl -s http://<target>:7199/ | head -20
```
Si JMX tiene Jolokia habilitado, enumerar beans:
```bash
curl -s http://<target>:7199/jolokia/list
```

### Paso 6: Verificar versión
```bash
# Desde cqlsh
SELECT release_version FROM system.local;
# O vía nmap
nmap -p 9042 --script cassandra-info <target>
```

### Paso 7: Detectar CQL injection surface
Si hay una aplicación web conectada a Cassandra, buscar endpoints que reflejen queries CQL en errores.

## Output Contract

```json
{
  "phase": "enum",
  "skill": "db-cassandra-enum",
  "target": "<target>",
  "open_ports": [
    {"port": 9042, "protocol": "CQL", "version": "4.0.6", "banner": ""},
    {"port": 7199, "protocol": "JMX", "version": "Jolokia 1.7.1", "banner": ""}
  ],
  "keyspaces": [
    {"name": "system", "tables": ["local", "peers", "schema_keyspaces"]},
    {"name": "system_schema", "tables": ["tables", "columns", "keyspaces"]},
    {"name": "data_app", "tables": ["users", "transactions"]}
  ],
  "auth_disabled": true,
  "default_creds_work": false,
  "jmx_exposed": true,
  "findings": [
    {
      "title": "Cassandra sin autenticación en puerto 9042",
      "severity": "critical",
      "category": "authentication-bypass",
      "cvss": 9.1,
      "cwe": "CWE-306",
      "evidence": "cqlsh conectó sin credenciales a <target>:9042, listó keyspaces: system, system_schema, data_app",
      "remediation": "Habilitar PasswordAuthenticator en cassandra.yaml y reiniciar el nodo",
      "next_steps": ["Extraer datos sensibles de keyspace data_app", "Verificar si hay credenciales en config files"]
    }
  ],
  "summary": "Cassandra 4.0.6 expuesto en 3 puertos, auth deshabilitado, acceso total a datos, JMX Jolokia expuesto",
  "next_phase": "exploit",
  "recommended_skills": ["hunt-sqli", "hunt-api-abuse"]
}
```
