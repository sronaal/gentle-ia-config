---
name: joomla-recon
description: Reconocimiento de sitios Joomla — versión, extensiones, usuarios y endpoints sensibles
phase: recon
---

## Activation Contract

Invocar cuando se detecte Joomla (cookies 4f8f9b0f5c8c, headers X-Content-Encoded-By: Joomla!, o /administrator/). Se recomienda ejecutar después del subdomain-discovery y tech-detection.

## Hard Rules

- NO ejecutar requests de escritura ni modificar contenido
- NO explotar SQLi ni deserialización (eso es para exploit)
- NO hacer fuerza bruta sobre /administrator/index.php sin autorización
- Máximo 60 requests en total para mantener perfil bajo

## Decision Gates

Antes de ejecutar, preguntar al usuario:
1. "¿Ejecutar detección de versión via XML, README, templates?"
2. "¿Enumerar extensiones (components, modules, plugins)?"
3. "¿Enumerar usuarios via com_users & index.php?option=com_users&view=users?"
4. "¿Detectar endpoints sensibles (configuration.php, htaccess.txt)?"
5. "¿Verificar panel de admin (/administrator/)?"

## Execution Steps

```bash
# 1. Detectar versión Joomla
curl -sk "https://TARGET/administrator/manifests/files/joomla.xml" | grep -E "<version>|<name>"
curl -sk "https://TARGET/LICENSES/README.txt" | head -10
curl -sk "https://TARGET/templates/system/css/system.css" | head -5
curl -skI "https://TARGET/" | grep -i "joomla\|x-content-encoded"

# 2. Detectar panel admin
curl -sk -o /dev/null -w "%{http_code} %{size_download}" "https://TARGET/administrator/"

# 3. Enumerar usuarios via com_users
curl -sk "https://TARGET/index.php?option=com_users&view=users"
curl -sk "https://TARGET/?option=com_users&view=users"

# 4. Enumerar componentes populares
for comp in com_content com_fields com_users com_contact com_search com_weblinks; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/index.php?option=$comp")
  echo "$comp -> $code"
done

# 5. Endpoints sensibles
for ep in configuration.php htaccess.txt robots.txt administrator/index.php language/en-GB/en-GB.xml; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  echo "$ep -> $code"
done

# 6. Detectar módulos/plugins populares
for ext in com_jce com_akeeba com_virtuemart com_k2 com_hikashop; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/index.php?option=$ext")
  echo "$ext -> $code"
done
```

## Output Contract

```json
{
  "phase": "recon",
  "target": "ejemplo.com",
  "skill": "joomla-recon",
  "joomla_version": "3.9.28",
  "panel_admin": {"path": "/administrator/", "status": 200},
  "extensiones_detectadas": [
    {"name": "com_content", "status": 200},
    {"name": "com_jce", "status": 200}
  ],
  "endpoints_sensibles": [
    {"path": "configuration.php", "status": 200, "severity": "critical"},
    {"path": "htaccess.txt", "status": 200}
  ],
  "evidencia": "Joomla! 3.9.28 via joomla.xml, /administrator/ detectado"
}
```
