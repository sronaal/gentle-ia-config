---
name: magento-recon
description: Reconocimiento de tiendas Magento — versión, temas, módulos, API endpoints y panel admin
phase: recon
---

## Activation Contract

Invocar cuando se detecte Magento (cookies PHPSESSID de Magento, headers X-Magento-*, /static/version, /skin/). Distingue entre Magento 1.x y 2.x automáticamente.

## Hard Rules

- NO hacer requests de escritura a la API REST (/rest/V1/* con POST)
- NO enumerar customer data sin autorización explícita
- NO explotar deserialización (CVE-2016-4010) — es para exploit
- Limitar a 80 requests totales

## Decision Gates

Antes de ejecutar, preguntar al usuario:
1. "¿Detectar versión Magento (1.x vs 2.x) via /static/version, /js/?"
2. "¿Enumerar API REST endpoints (/rest/V1/products, /rest/V1/categories)?"
3. "¿Detectar panel admin (/admin, /backend, /index.php/admin)?"
4. "¿Enumerar themes y módulos via URL detection?"
5. "¿Verificar SOAP API (/soap/?, /api/v2_soap/)?"

## Execution Steps

```bash
# 1. Detectar versión y plataforma
curl -sk "https://TARGET/static/version/" | head -5
curl -sk "https://TARGET/js/" 2>/dev/null | head -5
curl -skI "https://TARGET/" | grep -i "magento\|x-magento"
curl -sk "https://TARGET/static/version" -o /dev/null -w "%{redirect_url}"

# 2. Detectar Magento 1 vs 2
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/api/rest"
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/rest/V1"
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/soap/"

# 3. Panel admin
for path in admin backend index.php/admin admin_ admin/dashboard; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$path")
  echo "$path -> $code"
done

# 4. API REST endpoints (solo GET)
for ep in products categories customers orders; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/rest/V1/$ep")
  echo "GET /rest/V1/$ep -> $code"
done

# 5. Enumerar temas (URL paths comunes)
for theme in base default luma magento blank; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/static/frontend/Magento/$theme/en_US/css/styles-l.css")
  echo "Theme $theme -> $code"
done

# 6. Endpoints sensibles
for ep in downloader/ index.php/install downloader/index.php var/log/system.log; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  echo "$ep -> $code"
done
```

## Output Contract

```json
{
  "phase": "recon",
  "target": "ejemplo.com",
  "skill": "magento-recon",
  "magento_version": "2.4.5-p1",
  "plataforma": "Magento 2.x",
  "panel_admin": {"path": "/admin", "status": 200, "login_form": true},
  "api_endpoints": [
    {"path": "/rest/V1/products", "status": 401, "auth_required": true},
    {"path": "/rest/V1/categories", "status": 401}
  ],
  "temas_detectados": [
    {"name": "luma", "status": 200},
    {"name": "blank", "status": 200}
  ],
  "evidencia": "X-Magento-Tags detected, /static/frontend/Magento/luma responds"
}
```
