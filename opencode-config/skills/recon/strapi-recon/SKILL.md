---
name: strapi-recon
description: Reconocimiento de Strapi CMS — versión, content types, API endpoints, admin y usuarios
phase: recon
---

## Activation Contract

Invocar cuando se detecte Strapi (headers X-Powered-By: Strapi, /admin, /content-manager, /users, o cookies strapi_*). Strapi es un CMS headless Node.js muy común.

## Hard Rules

- NO hacer POST/PUT/DELETE a la API de contenido
- NO explotar CVE-2023-22621 ni otras vulnerabilidades (es para exploit)
- NO registrar usuarios vía /api/auth/local/register
- Limitar a 60 requests totales

## Decision Gates

Antes de ejecutar, preguntar al usuario:
1. "¿Ejecutar detección de versión via /admin/init y headers?"
2. "¿Enumerar content types y API endpoints via OpenAPI/Swagger?"
3. "¿Detectar endpoints de administración (/admin, /admin/auth, /content-manager)?"
4. "¿Enumerar endpoints de usuarios (/api/users, /api/users/me)?"
5. "¿Verificar roles de admin y locales (/api/users/permissions, /api/i18n/locales)?"

## Execution Steps

```bash
# 1. Detectar Strapi
curl -skI "https://TARGET/" | grep -i "strapi\|x-powered-by"
curl -sk "https://TARGET/admin/" | head -10
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/content-manager/"

# 2. Detectar versión
curl -sk "https://TARGET/admin/init" | python3 -m json.tool 2>/dev/null
curl -sk "https://TARGET/_health" | python3 -m json.tool 2>/dev/null

# 3. OpenAPI / Swagger
for ep in documentation openapi swagger; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  echo "$ep -> $code"
done

# 4. Endpoints API (solo GET)
for ep in "api/users" "api/users/me" "api/roles" "api/i18n/locales"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  echo "GET /$ep -> $code"
done

# 5. Admin endpoints
for ep in admin/auth admin/auth/local content-manager/collection-types; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  echo "$ep -> $code"
done

# 6. Enumerar content types (comunes)
for ct in articles posts pages categories tags products; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/api/$ct")
  echo "GET /api/$ct -> $code"
done

# 7. Verificar register habilitado
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/api/auth/local/register"

# 8. Config files expuestos
for ep in .env config/environments config/database.js; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  echo "$ep -> $code"
done
```

## Output Contract

```json
{
  "phase": "recon",
  "target": "ejemplo.com",
  "skill": "strapi-recon",
  "strapi_version": "4.15.0",
  "admin_panel": {"path": "/admin", "status": 200},
  "content_types_detectados": [
    {"name": "articles", "status": 200, "auth_required": false},
    {"name": "categories", "status": 200},
    {"name": "products", "status": 401}
  ],
  "api_endpoints": [
    {"path": "/api/users", "status": 200},
    {"path": "/api/roles", "status": 403}
  ],
  "register_habilitado": false,
  "evidencia": "X-Powered-By: Strapi <strapi.io>, /admin/init responde con versión 4.15.0"
}
```
