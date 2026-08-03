---
name: api-workflow-mapper
description: Mapeo completo de APIs REST, GraphQL y microservicios — detección de endpoints, versiones, autenticación, relaciones, rate limits y workflows multi-step
phase: recon
triggers:
  - API descubierta (Swagger, GraphQL, REST)
  - Múltiples endpoints con versiones detectadas (v1, v2, v3)
  - JS bundles con rutas de API
  - Respuestas JSON consistentes en múltiples rutas
  - Documentación de API expuesta (/swagger.json, /api-docs, /openapi.json)
  - Servicio con patrón RESTful (/api/, /v1/, /graphql)
---

# api-workflow-mapper

## Activation Contract

Se activa cuando se detectan **tres o más** de estos indicadores:
- Endpoint `/swagger.json`, `/api-docs`, `/openapi.yaml`, `/openapi.json` responde con documentación
- Endpoint `/graphql` responde a `POST` o `GET`
- JS bundles contienen rutas como `/api/v1/users`, `/api/v2/orders`
- Headers HTTP incluyen `X-API-Version`, `X-RateLimit-*`, `X-Auth-Type`
- Múltiples endpoints con el mismo patrón de recurso (`/users/`, `/posts/`, `/orders/`)
- Respuesta `401` vs `200` inconsistente entre rutas similares

Triggers automáticos desde: `tech-detection`, `js-secrets`, `hidden-endpoints`, `graphql-introspection`

## Hard Rules

1. **NUNCA** modificar datos en el target — solo `GET`, `HEAD`, `OPTIONS` para mapeo pasivo. Usar `POST` solo para queries GraphQL de lectura (`query { }`).
2. **NO** autenticarse como usuario real — detectar auth requerida pero no intentar login.
3. **RESPETAR** rate limits del servidor — usar delays de mínimo 500ms entre requests si se detectan headers `X-RateLimit-Remaining`.
4. **REPORTAR** inmediatamente si un endpoint devuelve datos de otros tenants — eso es un finding crítico por sí mismo.
5. **DOCUMENTAR** toda relación entre endpoints — no solo listar URLs, sino mapear el grafo de dependencias.
6. **NO** exceder 30 requests por minuto al target sin aprobación del operador.

## Decision Gates

| Gate | Pregunta | Qué hacer |
|------|----------|-----------|
| Documentación expuesta | ¿Hay `/swagger.json` o `/openapi.json`? | Parsear automáticamente y usar como fuente primaria |
| GraphQL | ¿`/graphql` responde con schema? | Ejecutar introspección completa si no está deshabilitada |
| Version detection | ¿Se detectaron v1, v2, v3? | Mapear diferencias entre versiones (endpoints agregados/quitados, cambios de schema) |
| Auth requerida | Endpoint devuelve 401 vs 200 | Categorizar endpoint como `authenticated`, `admin`, `public` |
| Relaciones | ¿Endpoint acepta IDs de otros recursos? | Mapear grafo de dependencias (e.g., `/users/{id}/posts/{id}`) |
| Multi-tenant | ¿Datos cambian con diferente token/header? | Señalar como potencial IDOR surface |

## Execution Steps

### Paso 1: Detectar documentación
```bash
# Probar fuentes de documentación conocidas
curl -s -o /dev/null -w "%{http_code}" "https://target.com/swagger.json"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/api-docs"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/openapi.json"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/graphql"
```

Si existe `/swagger.json` o `/openapi.json`, parsearlo completamente extrayendo:
- `paths` → endpoints y métodos
- `securityDefinitions` / `components.securitySchemes` → tipo de auth
- `parameters` → requeridos vs opcionales
- `definitions` / `components.schemas` → modelos de datos

### Paso 2: GraphQL introspection
```bash
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name kind fields { name args { name type { name kind } } } } } }"}'
```

### Paso 3: JS bundle mining
```bash
# Extraer rutas de API desde JS bundles encontrados
grep -oP '"/api/v[0-9]+/[^"]*"' bundle.js | sort -u
grep -oP "'/api/v[0-9]+/[^']*'" bundle.js | sort -u
```

### Paso 4: Version diffing
Para cada versión detectada (v1, v2, v3, beta, staging):
```bash
curl -s "https://target.com/api/v1/users" -o /dev/null -w "%{http_code}"
curl -s "https://target.com/api/v2/users" -o /dev/null -w "%{http_code}"
```
Comparar schemas de respuesta entre versiones. Endpoints que desaparecieron en v3 son candidatos a shadow API.

### Paso 5: Auth mapping por endpoint
Para cada endpoint `{method} {path}`:
```bash
# Sin auth
curl -s -o /dev/null -w "status=%{http_code}" -X GET "https://target.com/api/users"
# Con token genérico
curl -s -o /dev/null -w "status=%{http_code}" -X GET "https://target.com/api/users" \
  -H "Authorization: Bearer test"
```
Clasificar: `200` sin auth = público, `401` sin auth y `200` con auth = autenticado, `403` = admin/restringido.

### Paso 6: Mapeo de relaciones
Detectar patrones de ruta anidados:
- `/users/{id}/posts/{id}` → user → post
- `/organizations/{id}/projects/{id}/tasks` → org → project → task
- `/customers/{id}/invoices` → customer → invoice

Construir grafo dirigido de dependencias entre recursos.

### Paso 7: Rate limit detection
```bash
for i in {1..10}; do
  curl -s -D - "https://target.com/api/users" 2>&1 | grep -i "rate\|retry\|limit\|429"
done
```
Extraer: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`.

### Paso 8: Multi-tenant detection
Repetir requests clave con diferentes valores en header de tenant (ej: `X-Tenant-ID: 1`, `X-Tenant-ID: 2`) y comparar respuestas.

### Paso 9: Workflow mapping (multi-step)
Detectar secuencias de endpoints que forman un workflow:
```
POST /api/login       → token
GET  /api/users/me    → user profile
POST /api/orders      → crear orden
GET  /api/orders/{id} → ver orden
```
Mapear el grafo completo de workflows con dependencias de estado.

## Output Contract

```json
{
  "skill": "api-workflow-mapper",
  "phase": "recon",
  "target": "string",
  "discovered_docs": [
    {"type": "openapi|swagger|graphql", "url": "string", "version": "string"}
  ],
  "endpoints": [
    {
      "path": "/api/v1/users/{id}",
      "methods": ["GET", "POST", "PUT", "DELETE"],
      "auth_required": true,
      "auth_type": "bearer|api-key|cookie|none",
      "role_required": "admin|user|public",
      "rate_limits": {
        "limit": 100,
        "remaining": 50,
        "reset": 3600,
        "unit": "requests/hour"
      },
      "parameters": {
        "required": ["id"],
        "optional": ["fields", "include"]
      },
      "versions": ["v1", "v2"],
      "related_resources": ["/posts/{postId}"],
      "tenant_specific": false,
      "workflow_step": "order-creation"
    }
  ],
  "version_diff": [
    {
      "version_a": "v1",
      "version_b": "v2",
      "added": ["/api/v2/users/bulk"],
      "removed": ["/api/v1/users/deprecated"],
      "changed_schemas": ["UserResponse"]
    }
  ],
  "workflows": [
    {
      "name": "order-creation",
      "steps": [
        {"step": 1, "method": "POST", "path": "/api/auth/login", "output": "token"},
        {"step": 2, "method": "GET", "path": "/api/users/me", "auth": "token"},
        {"step": 3, "method": "POST", "path": "/api/orders", "auth": "token", "input": "cart_id"}
      ]
    }
  ],
  "shadow_endpoints": ["/api/v2/users/bulk", "/api/v3-beta/orders/export"],
  "tenant_separation": {"detected": true, "separator": "header|subdomain|path", "finding": "IDOR potencial entre tenants"},
  "findings": [
    {
      "title": "Shadow API v3 expuesta",
      "severity": "medium",
      "category": "shadow-api",
      "evidence": "v3-beta endpoints accesibles sin auth en /api/v3-beta/"
    }
  ],
  "summary": "Resumen del mapeo con endpoints totales, versiones, auth types detectados y hallazgos"
}
```
