---
name: ghost-recon
description: Reconocimiento de sitios Ghost CMS — versión, posts, authors, tags, admin y API pública
phase: recon
---

## Activation Contract

Invocar cuando se detecte Ghost CMS (headers X-Ghost-Cache-Status, /ghost/, /ghost/api/content/, o meta generator Ghost). Ghost es un CMS Node.js popular para publicaciones.

## Hard Rules

- NO hacer POST/PUT/DELETE a la API Admin
- NO intentar bypass de autenticación en /ghost/
- NO enumerar configuraciones internas (config, environment)
- Limitar a 60 requests totales para mantener perfil bajo

## Decision Gates

Antes de ejecutar, preguntar al usuario:
1. "¿Ejecutar detección de versión via headers y /package.json?"
2. "¿Enumerar posts, authors y tags via Content API pública?"
3. "¿Detectar panel admin (/ghost/, /ghost/#/signin)?"
4. "¿Enumerar rutas de API (/ghost/api/v3/content/, /ghost/api/v4/content/)?"
5. "¿Verificar archivos de configuración expuestos?"

## Execution Steps

```bash
# 1. Detectar Ghost CMS
curl -skI "https://TARGET/" | grep -i "ghost\|x-ghost"
curl -sk "https://TARGET/ghost/" | head -5
curl -sk "https://TARGET/ghost/api/v3/content/site/"
curl -sk "https://TARGET/ghost/api/v4/content/site/"

# 2. Detectar versión
curl -sk "https://TARGET/package.json" | grep -i "ghost\|version" | head -5
curl -sk "https://TARGET/ghost/api/v3/admin/site/" | python3 -m json.tool 2>/dev/null

# 3. Enumerar posts via Content API pública
curl -sk "https://TARGET/ghost/api/v3/content/posts/" | python3 -m json.tool 2>/dev/null | head -40

# 4. Enumerar authors
curl -sk "https://TARGET/ghost/api/v3/content/authors/" | python3 -m json.tool 2>/dev/null

# 5. Enumerar tags
curl -sk "https://TARGET/ghost/api/v3/content/tags/" | python3 -m json.tool 2>/dev/null

# 6. Admin panel
curl -sk -o /dev/null -w "%{http_code} %{size_download}" "https://TARGET/ghost/"
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/ghost/#/signin"

# 7. Endpoints sensibles
for ep in .env config.production.json config.development.json robots.txt sitemap.xml; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  echo "$ep -> $code"
done

# 8. Intentar API Admin sin auth
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/ghost/api/v3/admin/posts/"
```

## Output Contract

```json
{
  "phase": "recon",
  "target": "ejemplo.com",
  "skill": "ghost-recon",
  "ghost_version": "5.45.0",
  "admin_panel": {"path": "/ghost/", "status": 200, "login_form": true},
  "api_content": {"path": "/ghost/api/v3/content/site/", "status": 200},
  "posts_publicos": [
    {"id": "abc123", "title": "Hello Ghost", "published": true},
    {"id": "def456", "title": "Second Post", "published": true}
  ],
  "authors": [
    {"slug": "admin", "name": "Admin User", "count_posts": 12}
  ],
  "tags": [
    {"slug": "news", "name": "News", "count_posts": 5}
  ],
  "evidencia": "X-Ghost-Cache-Status: Miss, /ghost/ responde 200"
}
```
