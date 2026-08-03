---
name: cdn-origin-discovery
description: Descubre la IP real del servidor de origen cuando un target está protegido por CDN o WAF. Combina DNS history, SSL certificates, subdomain bruteforce, SPF records y ASN scanning.
phase: recon
triggers: [WAF detectado en respuesta, CDN headers presentes (cf-ray, x-amz-cf-id, x-sucuri-id, server: cloudflare), CNAME apuntando a CDN, múltiples IPs resolviendo el mismo hostname, cambios históricos de IP en DNS]
---

# CDN Origin Discovery

## Activation Contract

Ejecutar automáticamente cuando:
- Los headers HTTP revelen CDN: `CF-RAY`, `Server: cloudflare`, `X-Amz-Cf-*`, `X-Sucuri-ID`, `Fastly-*`, `Akamai-*`
- El CNAME del dominio apunte a `*.cloudflare.net`, `*.cloudfront.net`, `*.akamai.net`, `*.fastly.net`, `*.edgesuite.net`
- `nslookup` resuelva 3+ IPs distintas que pertenezcan a rangos de CDN
- `whatweb` o `wappalyzer` detecten "Cloudflare", "CloudFront", "Akamai", "Fastly"
- Se detecte un WAF (403 con `Blocked by` o `Security Firewall`)

## Hard Rules

1. **NUNCA atacar la IP de origen directamente sin verificación**. Primero confirmar que es el servidor real comparando respuestas.
2. **Verificar origen por 3 métodos distintos** antes de reportar como hallazgo. Falsos positivos abundan.
3. **No escanear la IP de origen agresivamente**. Un solo probe de confirmación basta en fase de recon.
4. **Si el origen respota diferente al CDN** (discrepancia en headers, body, TTL), documentar ambas respuestas.
5. **Priorizar fuentes pasivas** (DNS history, CRT logs, SPF) antes que probes directos.

## Decision Gates

| Pregunta | Acción |
|----------|--------|
| ¿El dominio estuvo en otra IP en Wayback/CRT? | Buscar en SecurityTrails, CRT.sh, DNSDumpster. Las IPs históricas suelen ser el origen. |
| ¿El SPF record incluye IPs explícitas? | Extraer IPs del SPF — suelen ser los servidores de origen reales. |
| ¿El certificado SSL aparece en Censys/Shodan en otra IP? | Consultar por SHA-1 fingerprint. IPs alternativas con mismo cert = probable origen. |
| ¿Subdominios resuelven directamente? | Subdominios olvidados (dev., admin., mail.) suelen estar fuera del CDN. |
| ¿El ASN del target tiene rangos propios? | Escanear rangos IPv4/IPv6 del ASN y comparar respuestas con el CDN. |
| ¿Responden igual por IP directa + Host header? | Si la IP responde con el mismo contenido al enviar `Host: target.com`, es el origen. |

## Execution Steps

### 1. DNS History (passivo)

```bash
# SecurityTrails API
curl -s "https://api.securitytrails.com/v1/history/$DOMAIN/dns/a" \
  -H "APIKEY: $API_KEY" | jq '.records[].values[].ip'

# CRT.sh - certificados históricos
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq '.[].name_value' | sort -u
```

### 2. SSL Certificate Search

```bash
# Obtener SHA-1 del certificado actual
SHA1=$(echo | openssl s_client -connect $DOMAIN:443 2>/dev/null | \
  openssl x509 -fingerprint -noout -sha1 | cut -d= -f2)

# Buscar en Censys por mismo SHA-1
curl -s -H "Accept: application/json" \
  "https://search.censys.io/api/v2/certificates/$SHA1" | \
  jq '.parsed.subject.common_name'
```

### 3. SPF y Registros MX

```bash
# SPF puede contener IPs del origen
dig +short TXT $DOMAIN | grep -oE 'ip[46]:[0-9./]+' | cut -d: -f2

# Headers de email (si se consigue uno real)
# Received: from [ORIGIN_IP]
```

### 4. Subdomain Bruteforce con Resolución Directa

```bash
# Subfinder + filtrar IPs que NO sean CDN
subfinder -d $DOMAIN -silent | \
  while read sub; do
    IP=$(dig +short "$sub" | head -1)
    # Verificar si la IP pertenece a rango CDN
    if ! is_cdn_ip "$IP"; then
      echo "$sub -> $IP (potencial origen)"
    fi
  done
```

### 5. Comparación CDN vs Directo

```bash
# Conectar directo a IP con Host header
IP_CANDIDATA="X.X.X.X"
curl -sv -H "Host: $DOMAIN" "http://$IP_CANDIDATA" 2>&1 | \
  grep -E "< (Server|X-Powered-By|Content-Length|HTTP/)"

# vs via CDN
curl -sv "https://$DOMAIN" 2>&1 | \
  grep -E "< (Server|X-Powered-By|Content-Length|HTTP/)"

# Comparar discrepancias. Si coinciden contenido y headers, confirmado.
```

### 6. Wayback Machine

```bash
# Buscar IPs históricas antes del CDN
curl -s "http://web.archive.org/cdx/search/cdx?url=$DOMAIN&output=json" | \
  jq '.[] | select(.[4] | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))' | \
  sort -u
```

## Output Contract

```json
{
  "skill": "cdn-origin-discovery",
  "target": "ejemplo.com",
  "cdn_detected": {
    "provider": "cloudflare",
    "cdn_ips": ["104.16.0.1", "104.16.0.2"],
    "detection_evidence": ["header: cf-ray", "header: server: cloudflare", "CNAME: ejemplo.com.cdn.cloudflare.net"]
  },
  "origin_candidates": [
    {
      "ip": "203.0.113.10",
      "confidence": 0.95,
      "method": "dns_history",
      "evidence": "SecurityTrails mostró esta IP como registro A del dominio entre 2022-03 y 2023-01",
      "verification": {
        "host_header_response": true,
        "ssl_match": true,
        "http_diff": false,
        "server_header": "nginx/1.24.0"
      }
    },
    {
      "ip": "203.0.113.45",
      "confidence": 0.75,
      "method": "spf_record",
      "evidence": "SPF incluye ip4:203.0.113.45/32",
      "verification": {
        "host_header_response": false,
        "ssl_match": false,
        "http_diff": true
      }
    }
  ],
  "origin_confirmed": "203.0.113.10",
  "techniques_succeeded": [
    "dns_history",
    "ssl_certificate_search",
    "spf_record_analysis",
    "host_header_bypass"
  ],
  "techniques_failed": [
    "subdomain_bruteforce",
    "wayback_machine"
  ],
  "next_steps": [
    "Escanear puertos en 203.0.113.10",
    "Enumerar servicios directamente sin CDN"
  ],
  "chainable_with": ["origin-ip-discovery", "port-scan", "waf-detection"]
}
```
