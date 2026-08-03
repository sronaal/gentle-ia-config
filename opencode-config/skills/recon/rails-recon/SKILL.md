---
name: rails-recon
description: Reconocimiento pasivo y activo de aplicaciones Ruby on Rails — detección de versión, rutas, configuraciones expuestas y superficie de ataque
phase: recon
---

# rails-recon — Reconocimiento de Ruby on Rails

## Contrato de Activación

Activás esta skill CUANDO:
- Detectás cookies `_session_id` o `SESSION_ID` en respuestas HTTP
- El header `X-Powered-By` o `Server` contiene `Phusion`, `Puma`, `Unicorn` o `WEBrick`
- La respuesta HTML incluye etiquetas `<meta name="csrf-param"` o `<meta name="csrf-token"`
- Encontrás rutas como `/rails/info/routes`, `/500.html` o `/assets/rails-`

No la activés para sitios PHP, Node.js o ASP.NET sin señales de Rails.

## Reglas Firmes

1. **Pasivo siempre primero**: no enviés requests intrusivos hasta haber analizado headers, cookies y HTML estático
2. **No modificar sesión**: no alterés cookies de sesión ajenas. Solo lectura
3. **Documentar versión exacta**: si detectás versión (ej. Rails 6.1.7), registrala con CPE
4. **No bruteforcear secretos**: no intentés forzar SECRET_KEY_BASE. Eso es de exploit
5. **Evidencia obligatoria**: cada hallazgo necesita el request y response que lo confirma

## Compuertas de Decisión

Antes de ejecutar skills intrusivas (enumeración activa de rutas, fuzzing) preguntar:
- "Se detectó Rails en el target. ¿Procedo con enumeración activa de rutas vía fuzzing?"
- "¿Querés que intente acceder a /rails/info/routes para mapear endpoints?"

## Pasos de Ejecución

### Fase 1 — Fingerprinting pasivo (sin contacto directo con rutas dinámicas)

```bash
# 1. Analizar headers de respuesta
curl -sI "https://target.com/" | grep -iE "x-powered-by|server|x-request-id|x-runtime"

# 2. Detectar cookies de sesión Rails
curl -sI "https://target.com/" | grep -iE "session_id|_session"

# 3. Detectar CSRF tokens en HTML
curl -s "https://target.com/" | grep -iE "csrf-param|csrf-token|csrf_meta_tags"
```

### Fase 2 — Detección de versión

```bash
# 4. Leer /500.html (cambia entre versiones)
curl -s "https://target.com/500.html" | grep -iE "rails|generator"

# 5. Leer asset pipeline fingerprint
curl -sI "https://target.com/assets/application-$(curl -s "https://target.com/assets/application.js" | md5sum | cut -d' ' -f1).js"

# 6. Buscar Gemfile.lock leaks
curl -s "https://target.com/Gemfile.lock" | grep -E "^RAILS|^  rails \([0-9]"
```

### Fase 3 — Enumeración de superficie

```bash
# 7. Routes expuestas (entorno dev)
curl -s "https://target.com/rails/info/routes"

# 8. Assets pipeline y webpack
curl -sI "https://target.com/assets/application.js"
curl -sI "https://target.com/packs/js/application.js"
curl -sI "https://target.com/assets/rails.png"

# 9. Sidekiq / administración
curl -sI "https://target.com/sidekiq"
curl -sI "https://target.com/admin"
curl -sI "https://target.com/rails/db"

# 10. Detectar Webpacker/Importmap/esbuild
curl -s "https://target.com/" | grep -iE "webpack|importmap|esbuild|vite"
```

### Fase 4 — Debug y exposición

```bash
# 11. Consola Rails expuesta
curl -sI "https://target.com/rails/console"
curl -sI "https://target.com/console"

# 12. Logs expuestos
curl -sI "https://target.com/log/development.log"
curl -sI "https://target.com/log/production.log"
```

## Contrato de Salida

```json
{
  "skill": "rails-recon",
  "target": "ejemplo.com",
  "rails_detected": true,
  "version": "6.1.7",
  "cpes": ["cpe:/a:rubyonrails:rails:6.1.7"],
  "server": "Phusion Passenger 6.0",
  "session_cookie": "_session_id",
  "csrf_protection": true,
  "asset_pipeline": "sprockets",
  "js_bundler": "webpack",
  "exposed_endpoints": [
    {"path": "/rails/info/routes", "accessible": true, "risk": "alto"},
    {"path": "/sidekiq", "accessible": false, "risk": "medio"},
    {"path": "/admin", "accessible": true, "risk": "alto"}
  ],
  "findings": [
    {
      "title": "Rutas expuestas en /rails/info/routes",
      "severity": "alto",
      "evidence": "GET /rails/info/routes → 200 OK con listado completo de rutas"
    }
  ]
}
```
