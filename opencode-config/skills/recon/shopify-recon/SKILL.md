---
name: shopify-recon
description: Reconocimiento de tiendas Shopify — productos, colecciones, API pública, temas y webhooks
phase: recon
---

## Activation Contract

Invocar cuando se detecte Shopify (headers X-ShopId, X-Shopify-Shop, dominio .myshopify.com, o /collections/, /products/). También para tiendas custom con Shopify headless.

## Hard Rules

- NO hacer POST/PUT/DELETE a la API Storefront ni Admin
- NO intentar escalar scopes de API
- NO interactuar con webhooks (solo detectarlos)
- No exceder 80 requests/minuto (Shopify rate limita agresivamente)

## Decision Gates

Antes de ejecutar, preguntar al usuario:
1. "¿Enumerar productos y colecciones públicas via Storefront API?"
2. "¿Descubrir API GraphQL pública (/api/2024-01/graphql.json)?"
3. "¿Enumerar blogs y artículos via /blogs/?"
4. "¿Detectar temas y apps via /admin URL patterns?"
5. "¿Verificar proxy pages y webhook discovery?"

## Execution Steps

```bash
# 1. Detectar Shopify
curl -skI "https://TARGET/" | grep -i "x-shopify\|x-shopid\|x-frame-options"
curl -sk "https://TARGET/.well-known/shopify" | head -5

# 2. Enumerar collections
curl -sk "https://TARGET/collections.json" | python3 -m json.tool 2>/dev/null
curl -sk "https://TARGET/collections/all/products.json?limit=10"

# 3. Enumerar productos
curl -sk "https://TARGET/products.json?limit=20" | python3 -m json.tool 2>/dev/null | head -50

# 4. API GraphQL pública
curl -sk "https://TARGET/api/2024-01/graphql.json" -o /dev/null -w "%{http_code}"
curl -sk "https://TARGET/api/graphql" -o /dev/null -w "%{http_code}"

# 5. Blogs y artículos
curl -sk "https://TARGET/blogs.json" | python3 -m json.tool 2>/dev/null
curl -sk "https://TARGET/blogs/"

# 6. Proxy pages y endpoints
for ep in a/apps apps proxy pages password; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  echo "$ep -> $code"
done

# 7. Admin panel (custom domains)
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/admin"
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/admin/settings"

# 8. Detectar tema activo
curl -sk "https://TARGET/collections/all" | grep -i "theme\|shopify-theme" | head -5
```

## Output Contract

```json
{
  "phase": "recon",
  "target": "ejemplo.myshopify.com",
  "skill": "shopify-recon",
  "es_shopify": true,
  "shop_id": "1234567",
  "api_graphql": {"path": "/api/2024-01/graphql.json", "status": 200},
  "productos_publicos": 150,
  "colecciones": [
    {"handle": "frontpage", "title": "Home"},
    {"handle": "all", "title": "All Products"}
  ],
  "blogs_detectados": [
    {"handle": "news", "title": "News"}
  ],
  "evidencia": "X-ShopId: 1234567, /collections.json responde con 10 colecciones"
}
```
