---
name: waf-fingerprint-auto
description: Fingerprinting automático de WAF — detecta y perfila cualquier WAF por headers, cookies, IP ranges y comportamiento
version: 1.0.0
phase: recon
category: waf-detection
tags: [waf, fingerprint, detection, recon, profiling]
tools: [curl, python3, dig, wafw00f]
difficulty: basic
opsec_level: low
time_estimate: 60s
severity_if_found: info
triggers:
  - "Se inicia recon en cualquier target web"
  - "Se detecta CDN o proxy inverso en la respuesta"
  - "Requests devuelven 403, 406, 401 bloqueando testing"
  - "Headers inusuales en respuesta HTTP"
  - "Comportamiento de rate limiting sospechoso"
related_skills:
  - waf-cloudflare-bypass
  - waf-fortiadc-bypass
  - waf-akamai-bypass
  - waf-generic-bypass
mitre_attack: [T1592.002, T1087.004]
---

## Activation Contract

Se activa AUTOMÁTICAMENTE al inicio de recon en **cualquier target web**.
Triggers: nuevo target HTTP/HTTPS; resolución DNS a rangos CDN conocidos;
códigos 403/406/401/429; headers `cf-ray`, `x-amzn-*`, `x-akamai-*`,
`x-sucuri-*`, `x-iinfo`; o Retry-After/tiempos >3s.

Corre UNA VEZ por target y cachea el resultado.

## Hard Rules

| Regla | Razón |
|-------|-------|
| No enviar payloads maliciosos en fingerprint inicial | Solo requests benignos |
| Máximo 10 requests por target | Suficiente para identificar cualquier WAF conocido |
| No activar bypass skills sin fingerprint confirmado | Bypass incorrecto quema la IP |
| Cachear resultado para no re-fingerprintear | Evita ruido redundante |
| Si wafw00f falla, pasar a fingerprint manual por comportamiento | wafw00f falla con WAFs custom |

## Decision Gates

Preguntar antes de:
1. **Fingerprinting invasivo** (enviar payloads trigger si falló pasivo)
2. **Rate limiting profiling** (ráfagas para medir umbrales)
3. **Multi-layer WAF profiling** (Cloudflare + ModSecurity detectados)

## Execution Steps

```bash
# 1. Header analysis (1 request)
curl -skI "https://TARGET/" | tee /tmp/waf_headers.txt
python3 /dev/stdin << 'EOF'
import re
h = open('/tmp/waf_headers.txt').read().lower()
sigs = {
  'Cloudflare':  ['cf-ray','server: cloudflare','__cf_bm'],
  'Akamai':      ['x-akamai','server: akamaighost','x-cache: akamai'],
  'FortiADC':    ['x-as_forwarded','server: fortiadc'],
  'AWS WAF':     ['x-amzn-','x-amz-cf-id'],
  'Fastly':      ['x-served-by','x-cache: fastly','x-timer'],
  'Imperva':     ['x-iinfo','x-cdn: incapsula'],
  'Sucuri':      ['x-sucuri-id','server: sucuri'],
  'ModSecurity': ['x-modsecurity'],
  'F5 BIG-IP':   ['x-connection-hash','server: bigip'],
  'Varnish':     ['x-varnish','x-cache-status'],
}
for w,s in sigs.items():
  if any(x in h for x in s):
    print(f"DETECTED: {w}")
    break
else:
  print("DETECTED: unknown")
EOF

# 2. Cookie analysis
curl -sk -D - -o /dev/null "https://TARGET/" | grep -iE "^set-cookie:" | \
  grep -iE "__cf|ak_bmsc|incap_ses|sucuri|AWSALB|x-mapping-"

# 3. Trigger analysis (payloads benignos)
for desc,p in \
  "SQLi 1' OR '1'='1" \
  "XSS <script>alert(1)</script>" \
  "PT ../../etc/passwd" \
  "CMDI ;id"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$p'))")")
  echo "$desc → $code"
done

# 4. Rate limiting profile
for i in $(seq 1 10); do
  curl -sk -o /dev/null -w "Req $i → %{http_code}\n" "https://TARGET/?i=$i"
  sleep 0.3
done

# 5. Recomendar bypass según WAF
python3 /dev/stdin << 'EOF'
m = {"Cloudflare": "waf-cloudflare-bypass | origin IP + encoding",
     "Akamai":     "waf-akamai-bypass | X-Forwarded-Host + CT",
     "FortiADC":   "waf-fortiadc-bypass | UA rotation + path norm",
     "unknown":    "waf-generic-bypass | encoding matrix"}
waf = "Cloudflare"  # del paso 1
rec = m.get(waf, m["unknown"])
print(f"RECOMMENDED: {rec}")
EOF
```

## Output Contract

```json
{
  "skill": "waf-fingerprint-auto",
  "target": "ejemplo.com",
  "waf_detected": "Cloudflare",
  "confidence": "high",
  "evidence": {
    "headers": ["cf-ray: 1a2b3c4d-MIA", "server: cloudflare"],
    "cookies": ["__cf_bm", "__cfduid"],
    "trigger_responses": {"normal": 200, "sqli": 403, "xss": 403}
  },
  "rate_limit_profile": {"req_per_min_before_block": 30, "block_code": 429},
  "recommended_skill": "waf-cloudflare-bypass",
  "recommended_technique": "origin IP discovery + Unicode encoding bypass",
  "fallback_skill": "waf-generic-bypass"
}
```
