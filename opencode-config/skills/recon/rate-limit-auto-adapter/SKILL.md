---
name: rate-limit-auto-adapter
description: Detecta, analiza y auto-adapta el tráfico para evadir rate limiting en aplicaciones web y APIs. Aplica backoff exponencial, rotación de IP/headers y distribución temporal.
phase: recon
triggers: [HTTP 429/503/403, connection timeouts, latencia incremental en respuestas, "Too Many Requests" en body/cabeceras, headers X-RateLimit-* visibles, retry-after presente]
---

# Rate Limit Auto-Adapter

## Activation Contract

Ejecutar automáticamente cuando:
- Tres o más requests consecutivos devuelvan **429**, **503** o **403** con indicios de rate limit
- Response time aumente >30% entre requests consecutivos idénticos
- Aparezcan headers `Retry-After`, `X-RateLimit-Remaining: 0`, `X-RateLimit-Reset`
- El body contenga frases como `"Too Many Requests"`, `"rate limit"`, `"slow down"`, `"try again later"`
- Conexiones fallen con timeout en endpoints previamente accesibles
- Se detecte un bloqueo repentino después de N requests exitosos

## Hard Rules

1. **NUNCA ignorar un 429/Retry-After**. Si el servidor indica un tiempo de espera, respetarlo exactamente + 1s de margen.
2. **Backoff mínimo obligatorio**: tras el primer rate limit, esperar el doble del tiempo sugerido o 5s si no hay sugerencia. Incrementar exponencialmente con cada bloqueo.
3. **Limitar paralelismo**: máx 3 conexiones concurrentes por endpoint durante fase de detección.
4. **No saturar**: si se detecta rate limit global (afecta todos los endpoints), detener todo el escaneo y escalar a humano.
5. **Respetar robots.txt** si el target lo exige y estamos en modo pasivo.
6. **Registrar cada evento de rate limit** con timestamp, endpoint, headers de respuesta y estrategia aplicada.

## Decision Gates

| Pregunta | Acción |
|----------|--------|
| ¿429 específico de endpoint o global? | Si endpoint-specific: backoff local y continuar otros endpoints. Si global: detener y escalar. |
| ¿Hay `Retry-After` header? | Respetar el valor exacto. Si no hay, calcular ventana incremental. |
| ¿Disponemos de pool de proxies? | Si sí: rotar IP tras 3 backoffs fallidos. Si no: seguir backoff local. |
| ¿La ventana es sliding o fija? | Hacer 5 requests espaciados y medir dónde cae el bloqueo. Patrón = ventana deslizante si el bloqueo ocurre en distintos números de request. |
| ¿El rate limit es por IP, cookie o token? | Probar con/sin cookie, cambiar token, cambiar IP. El que elimine el bloqueo revela el binding. |

## Execution Steps

### 1. Detectar rate limit

```bash
# Enviar requests progresivos midiendo status y response time
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64)" \
    "$TARGET_URL"
  sleep 0.5
done
```

Identificar:
- Umbral de requests antes del bloqueo (`max_requests`)
- Tiempo de ventana midiendo cuándo se reanuda el acceso
- Headers de rate limit presentes

### 2. Calcular ventana

```bash
# Medir ventana: esperar y probar cada 5s
for wait in 5 10 30 60 120; do
  sleep $wait
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL")
  if [ "$STATUS" = "200" ]; then
    echo "Ventana detectada: ~${wait}s"
    break
  fi
done
```

### 3. Calibrar delay óptimo

```javascript
// Estrategia: delay = ventana / (max_requests * safety_factor)
const delay = Math.max(windowSec / maxRequests * 1.5, 1);
const backoff = retryCount => delay * Math.pow(2, retryCount);
```

### 4. Rotar IP (si aplica)

```bash
# Ejemplo con Tor
torsocks curl -s "$TARGET_URL"
# O con proxy rotatorio
curl -s --proxy "http://user:pass@proxy:port" "$TARGET_URL"
```

### 5. Jitter y distribución

Añadir jitter aleatorio de ±20% al delay calculado para evitar patrones detectables:

```javascript
const actualDelay = delay * (0.8 + Math.random() * 0.4);
```

## Output Contract

```json
{
  "skill": "rate-limit-auto-adapter",
  "target": "ejemplo.com",
  "rate_limit_detected": true,
  "detection_evidence": {
    "status_codes": [200, 200, 200, 429, 429, 429],
    "response_times": [0.3, 0.4, 0.5, 1.2, null, null],
    "rate_limit_headers": {
      "retry_after": "60",
      "x_rate_limit_remaining": "0",
      "x_rate_limit_reset": "1700000000"
    }
  },
  "window_seconds": 60,
  "max_requests_per_window": 10,
  "rate_limit_type": "sliding",
  "binding": "ip",
  "optimal_delay": 6.0,
  "strategy_applied": {
    "delay": 6.0,
    "backoff": "exponential",
    "jitter": 0.2,
    "ip_rotation": true,
    "user_agent_rotation": true,
    "proxy_pool": ["tor", "residential"],
    "parallel_requests": 1
  },
  "affected_endpoints": ["/api/login", "/api/search"],
  "recommendation": "Usar delay de 6-8s con jitter. Rotar IP cada 15 requests. Escalar a rate-limit-bypass si persiste.",
  "chainable_with": ["evasion-rate-limit-bypass", "evasion-ip-rotation"]
}
```
