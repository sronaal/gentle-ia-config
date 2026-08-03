---
name: django-recon
description: Reconocimiento de aplicaciones Django — DEBUG, admin panel, rutas, API endpoints y versión
phase: recon
---

# django-recon — Reconocimiento de Django

## Contrato de Activación

Activás esta skill CUANDO:
- Detectás cookies `csrftoken`, `sessionid` o `messages` en respuestas
- El header `Server` contiene `WSGIServer` o `gunicorn`
- La página de error 404 de Django aparece (con círculos verdes/grises del debug)
- Encontrás `/admin/` con login de Django
- Detectás `X-Frame-Options: DENY` (middleware por defecto) o `X-Content-Type-Options: nosniff`

No la activés para Flask, FastAPI o aplicaciones PHP.

## Reglas Firmes

1. **/admin/ es solo detección**: no intentés autenticarte ni bruteforcear
2. **DEBUG=True es crítico**: si hay tracebacks completos con settings, reportar inmediatamente
3. **No ejecutar migrations ni management commands**
4. **Evidencia obligatoria**: cada endpoint listado debe incluir código de estado

## Compuertas de Decisión

- "Se detectó Django. ¿Querés que verifique si DEBUG está activo? (tracebacks con settings expuestos)"
- "¿Procedo con enumeración de endpoints /api/, /graphql y /rest? (puede exponer la API completa)"
- "Se detectó el admin panel en /admin/. ¿Procedo con fingerprinting de versión via login page?"
- "¿Querés que intente detectar endpoints via URLs.py leaks en archivos estáticos?"

## Pasos de Ejecución

### Fase 1 — Fingerprinting pasivo

```bash
# 1. Cookies Django
curl -sI "https://target.com/" | grep -iE "csrftoken|sessionid|messages"

# 2. Headers de seguridad Django
curl -sI "https://target.com/" | grep -iE "x-frame-options|x-content-type|x-xss-protection"

# 3. Detectar administración
curl -sI "https://target.com/admin/"
```

### Fase 2 — DEBUG y error pages

```bash
# 4. Probar DEBUG=True con URL inválida
curl -s "https://target.com/__django_does_not_exist_12345__" | grep -iE \
  "Traceback|DJANGO_SETTINGS_MODULE|SECRET_KEY|DATABASES|DEBUG.*True|ALLOWED_HOSTS"

# 5. Version via admin login HTML
curl -s "https://target.com/admin/login/" | grep -iE "django|Django version|v[0-9]+\.[0-9]+"

# 6. Static files
curl -sI "https://target.com/static/admin/css/base.css"
curl -sI "https://target.com/static/admin/css/login.css"
```

### Fase 3 — Enumeración de endpoints

```bash
# 7. Endpoints REST/API
curl -sI "https://target.com/api/"
curl -sI "https://target.com/api/v1/"
curl -sI "https://target.com/graphql"
curl -sI "https://target.com/graphql/"
curl -sI "https://target.com/rest-auth/"

# 8. URLs comunes Django
for path in admin api api/v1 rest graphql swagger schema \
  accounts accounts/login accounts/password-reset \
  static media files upload users; do
  echo "$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path") - /$path"
done

# 9. Robots.txt con rutas
curl -s "https://target.com/robots.txt"
```

### Fase 4 — Config leaks y exposición

```bash
# 10. Archivos sensibles
curl -sI "https://target.com/settings.py"
curl -sI "https://target.com/.env"
curl -sI "https://target.com/db.sqlite3"
curl -sI "https://target.com/manage.py"

# 11. Fixtures y migraciones
curl -sI "https://target.com/fixtures/"
curl -sI "https://target.com/migrations/"
```

## Contrato de Salida

```json
{
  "skill": "django-recon",
  "target": "ejemplo.com",
  "django_detected": true,
  "version": "4.2.6",
  "cpes": ["cpe:/a:djangoproject:django:4.2.6"],
  "debug_mode": false,
  "admin_login": {"accessible": true, "auth_required": true},
  "csrf_cookie": "csrftoken",
  "session_cookie": "sessionid",
  "webserver": "gunicorn 20.1",
  "endpoints": [
    {"path": "/admin/", "code": 200, "description": "Login panel"},
    {"path": "/api/", "code": 200, "description": "API root"},
    {"path": "/graphql", "code": 404, "description": "No GraphQL"}
  ],
  "findings": [
    {
      "title": "Admin panel expuesto",
      "severity": "medio",
      "evidence": "GET /admin/ → 200 OK con login de Django",
      "cwe": "CWE-306",
      "mitigation": "Restringir /admin/ por IP o VPN"
    }
  ]
}
```
