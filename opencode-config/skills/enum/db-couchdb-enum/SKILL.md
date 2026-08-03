---
name: db-couchdb-enum
description: Enumerar bases de datos Apache CouchDB — databases, documentos, config expuesta, users
phase: enum
---

# db-couchdb-enum

## Activation Contract

- **Trigger**: Se detectan puertos 5984 (HTTP) o 6984 (HTTPS) abiertos y responden con el banner de CouchDB.
- **Target**: IP o hostname con CouchDB expuesto.
- **Dependencies**: `curl`, `python3`, `jq`.
- **Expected outcome**: Listado de databases, documentos, config expuesta (/_config), usuarios, versión de CouchDB.

## Hard Rules

1. SOLO operaciones GET/HEAD — NO hacer POST/PUT/DELETE.
2. NO registrar usuarios ni modificar documentos.
3. Si se detecta `/` redirigiendo a Fauxton, reportar pero NO interactuar con la UI más allá de GET.
4. Si `/_config` requiere admin party (no auth), extraer TODO pero sin modificar valores.
5. NO intentar fuerza bruta contra `/_users`.
6. Rate limit: 1 request cada 1.5 segundos.
7. Documentar el `CouchDB-Version` header o el version en `/_node/{node}/_info`.

## Decision Gates

Usar `question()` antes de:

- Acceder a `/_all_dbs` si el target está en producción — lista todas las bases de datos y puede ser considerado intrusivo en entornos monitoreados.
- Acceder a `/_config` en un servidor corporativo (expone contraseñas en texto plano).
- Enumerar documentos en databases con nombres sospechosos (pwd, pass, secret, key).

## Execution Steps

### Paso 1: Verificar CouchDB y versión
```bash
# Request básico a la raíz
curl -s http://<target>:5984/ | jq .
```
El response incluye `couchdb: "Welcome"`, `version`, `vendor`.

```bash
# Verificar headers
curl -sI http://<target>:5984/
```
Buscar `Server: CouchDB/<version>` o `CouchDB-Version`.

### Paso 2: Enumerar databases
```bash
# Listar todas las databases
curl -s http://<target>:5984/_all_dbs | jq .
```
También verificar:
```bash
# Información del nodo
curl -s http://<target>:5984/_node/_local/_info | jq .
```

### Paso 3: Enumerar documentos por database
Para cada database encontrada:
```bash
curl -s "http://<target>:5984/<db>/_all_docs?include_docs=true" | jq '.rows[]'
```
O solo contar documentos y obtener metadata:
```bash
curl -s http://<target>:5984/<db> | jq .
```

### Paso 4: Detectar config expuesta (admin party)
```bash
# Si el servidor está sin auth (admin party)
curl -s http://<target>:5984/_config | jq .
```
Esto expone passwords, claves de API, config de red:
```bash
# Secciones particularmente sensibles
curl -s http://<target>:5984/_config/couch_httpd_auth
curl -s http://<target>:5984/_config/admins
```

### Paso 5: Enumerar usuarios
Si `/_users` database existe:
```bash
curl -s http://<target>:5984/_users/_all_docs?include_docs=true | jq '.rows[].doc'
```
Los docs contienen `name`, `roles`, `password_scheme`, `iterations`, `derived_key`.

### Paso 6: Verificar Fauxton UI
```bash
curl -s http://<target>:5984/_utils/ | head -5
```
Fauxton en `/_utils/` confirma que es una instalación interactiva.

### Paso 7: Verificar replicación y bases de datos de sistema
```bash
# _replicator database
curl -s http://<target>:5984/_replicator/_all_docs | jq .
# _global_changes
curl -s http://<target>:5984/_global_changes | jq .
```

### Paso 8: Detectar CVE-2022-24706 (config leak)
```bash
# Erlang cookie leak via /_node/couch@localhost/_info
curl -s http://<target>:5984/_node/couchdb@localhost/_info | jq '.erlang_cookie'
```

## Output Contract

```json
{
  "phase": "enum",
  "skill": "db-couchdb-enum",
  "target": "<target>:5984",
  "version": "3.2.2",
  "admin_party": true,
  "databases": 12,
  "database_list": [
    {"name": "_users", "doc_count": 5},
    {"name": "_replicator", "doc_count": 2},
    {"name": "app_data", "doc_count": 1520},
    {"name": "logs", "doc_count": 34000}
  ],
  "users_found": [
    {"name": "admin", "roles": ["_admin"], "password_scheme": "pbkdf2", "iterations": 10000}
  ],
  "config_sections": ["admins", "couch_httpd_auth", "couchdb", "httpd"],
  "findings": [
    {
      "title": "CouchDB en admin party — sin autenticación",
      "severity": "critical",
      "category": "authentication-bypass",
      "cvss": 9.8,
      "cwe": "CWE-306",
      "evidence": "curl http://<target>:5984/_config devolvió todas las secciones de config sin credenciales. Admin user detection: admin (pbkdf2)",
      "remediation": "Crear cuentas admin via PUT /_node/<node>/_config/admins/username y remover admin party",
      "next_steps": ["Extraer documentos de app_data", "Verificar replicación activa en _replicator"]
    },
    {
      "title": "Config expone passwords en texto plano",
      "severity": "high",
      "category": "credentials-disclosure",
      "cvss": 8.6,
      "cwe": "CWE-312",
      "evidence": "Se accedió a /_config/couch_httpd_auth y se obtuvieron secret keys",
      "remediation": "Restringir acceso a /_config, habilitar require_valid_user = true",
      "next_steps": ["Usar credenciales para pivot a otros servicios"]
    }
  ],
  "summary": "CouchDB 3.2.2 en admin party, config expuesta con credenciales, 5 usuarios en _users, 12 databases con datos de app",
  "next_phase": "exploit",
  "recommended_skills": ["hunt-sqli", "hunt-api-abuse", "lateral-movement"]
}
```
