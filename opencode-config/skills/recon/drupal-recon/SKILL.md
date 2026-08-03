---
name: drupal-recon
description: Reconocimiento de sitios Drupal — versión, módulos, usuarios, nodos y endpoints sensibles
phase: recon
---

## Activation Contract

Invocar este skill cuando se detecte un sitio Drupal (por headers X-Generator, X-Drupal-*, o cookies Drupal.xxx). También se puede activar manualmente durante la fase de reconocimiento de CMS.

## Hard Rules

- NO ejecutar acciones de escritura (crear/editar contenido, registrar usuarios)
- NO hacer fuerza bruta sobre /user/login sin autorización explícita
- NO acceder a páginas de administración que requieran autenticación
- Limitar a 50 requests por minuto para evitar rate limiting

## Decision Gates

Antes de ejecutar, preguntar al usuario:
1. "¿Ejecutar enumeración de usuarios via /user/X (1-50)?"
2. "¿Escáner automático de versión via CHANGELOG.txt, core/CHANGELOG.txt?"
3. "¿Enumerar nodos públicos (node/1..20)?"
4. "¿Detectar endpoints sensibles (install.php, update.php, devel)?"
5. "¿Verificar Ruta de Admin (/admin, /user/login)?"

## Execution Steps

```bash
# 1. Detectar versión via headers y meta
curl -skI "https://TARGET/" | grep -i "X-Drupal\|X-Generator\|drupal"
curl -sk "https://TARGET/CHANGELOG.txt" | head -20
curl -sk "https://TARGET/core/CHANGELOG.txt" | head -20
curl -sk "https://TARGET/core/RELEASE.txt"

# 2. Detectar endpoints sensibles
for ep in install.php update.php devel/php devel devel/session; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$ep")
  echo "$ep -> $code"
done

# 3. Enumerar usuarios (IDs 1-20)
for id in $(seq 1 20); do
  resp=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/user/$id")
  echo "User $id -> $resp"
done

# 4. Enumerar nodos públicos
for n in $(seq 1 15); do
  curl -sk -o /dev/null -w "%{http_code} %{redirect_url}" "https://TARGET/node/$n"
done

# 5. Detectar Ruta de Admin
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/admin"
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/user/login"
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/user/register"

# 6. Enumerar módulos (check de rutas contrib comunes)
for mod in devel coder views ctools panels token pathauto pathauto_aliases; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$mod")
  echo "Módulo $mod -> $code"
done
```

## Output Contract

```json
{
  "phase": "recon",
  "target": "ejemplo.com",
  "skill": "drupal-recon",
  "drupal_version": "7.78",
  "endpoints_sensibles": [
    {"path": "install.php", "status": 200, "severity": "critical"},
    {"path": "devel/php", "status": 403, "severity": "info"}
  ],
  "usuarios": [
    {"uid": 1, "status": 200, "name": "admin"},
    {"uid": 2, "status": 404}
  ],
  "modulos_detectados": [
    {"name": "devel", "status": 200},
    {"name": "ctools", "status": 200}
  ],
  "nodos_publicos": [
    {"nid": 1, "status": 200, "title": "Welcome to Drupal"},
    {"nid": 2, "status": 403}
  ],
  "evidencia": "X-Generator: Drupal 7.78, /CHANGELOG.txt accesible"
}
```
