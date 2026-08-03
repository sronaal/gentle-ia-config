---
name: symfony-recon
description: Reconocimiento de aplicaciones Symfony — profiler, routes, versión y exposición de archivos de configuración
phase: recon
---

# symfony-recon — Reconocimiento de Symfony

## Contrato de Activación

Activás esta skill CUANDO:
- Detectás headers `X-Symfony` o `X-Debug-Token` en respuestas
- Encontrás `_profiler/` accesible en el sitio
- Las URLs contienen `app_dev.php` o `app.php`
- Detectás cookies de sesión de Symfony (con prefijo `symfony` o `PHPSESSID` en contexto Symfony)
- Los estilos CSS incluyen rutas `/bundles/framework/css/`

No la activés para Laravel, CakePHP o sitios sin señales de Symfony.

## Reglas Firmes

1. **Profiler expuesto es crítico**: expone DB credentials, tokens CSRF, sesiones activas
2. **No modificar perfiles existentes**: solo lectura de profiler público
3. **/config.php y /app_dev.php en prod son severos**: documentar inmediatamente
4. **Evidencia**: cada hallazgo requiere URL, código HTTP y contenido relevante

## Compuertas de Decisión

- "Se detectó Symfony con profiler expuesto (_profiler/). ¿Procedo a enumerar perfiles? (expone tokens y creds)"
- "¿Querés que verifique si /config.php o /app_dev.php están accesibles en producción?"
- "Se detectó X-Debug-Token. ¿Procedo con enumeración de rutas via Web Profiler Toolbar?"
- "¿Intento acceder al panel de administración de Doctrine (/_doctrine/)?"

## Pasos de Ejecución

### Fase 1 — Fingerprinting pasivo

```bash
# 1. Headers Symfony
curl -sI "https://target.com/" | grep -iE "x-symfony|x-debug-token|x-debug-token-link"

# 2. Web Profiler Toolbar en HTML
curl -s "https://target.com/" | grep -iE "sfToolbar|symfony/web-profiler|wdt/"

# 3. Detectar app_dev.php
curl -sI "https://target.com/app_dev.php"
```

### Fase 2 — Profiler y rutas

```bash
# 4. Profiler principal
curl -sI "https://target.com/_profiler/"
curl -s "https://target.com/_profiler/" | grep -iE "profiler|token|search"

# 5. Enumerar tokens de profiler
curl -s "https://target.com/_profiler/search" | grep -oE 'token=[a-zA-Z0-9]+' | sort -u

# 6. Web Profiler Toolbar data (con token de ejemplo)
curl -s "https://target.com/_wdt/TOKEN_AQUI"
```

### Fase 3 — Versión y tecnologías

```bash
# 7. Buscar versión en assets
curl -sI "https://target.com/bundles/framework/css/structure.css" | \
  grep -iE "symfony|sf-version"

# 8. Version via composer.lock leaks
curl -s "https://target.com/composer.lock" | grep -E '"name": "symfony/symfony"|"version":'

# 9. Archivos de configuración expuestos
curl -sI "https://target.com/config.php"
curl -sI "https://target.com/var/cache/dev/"

# 10. Doctrine profiler
curl -sI "https://target.com/_profiler/doctrine"
curl -sI "https://target.com/_doctrine/"
```

### Fase 4 — Enumeración de endpoints

```bash
# 11. Rutas comunes Symfony
for path in login logout admin api register profile account \
  _error _fragment _wdt _profiler config app_dev; do
  echo "$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path") - /$path"
done

# 12. Security / login
curl -sI "https://target.com/login"
curl -sI "https://target.com/logout"
curl -sI "https://target.com/security/login"
```

## Contrato de Salida

```json
{
  "skill": "symfony-recon",
  "target": "ejemplo.com",
  "symfony_detected": true,
  "version": "5.4.21",
  "cpes": ["cpe:/a:sensiolabs:symfony:5.4.21"],
  "profiler_accessible": true,
  "debug_tokens": ["abc123", "def456"],
  "env": "dev",
  "exposed_configs": ["app_dev.php", "_profiler"],
  "profiler_tokens_available": 15,
  "findings": [
    {
      "title": "Symfony Profiler expuesto sin autenticación",
      "severity": "crítico",
      "evidence": "GET /_profiler/ → 200 OK listando tokens. Primer token abc123 expone DB credentials y parámetros de request",
      "cwe": "CWE-200",
      "next_steps": [
        "Extraer credenciales de base de datos del profiler",
        "Analizar parámetros de requests almacenados"
      ]
    }
  ]
}
```
