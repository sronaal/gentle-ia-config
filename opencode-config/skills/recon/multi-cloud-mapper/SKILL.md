---
name: multi-cloud-mapper
description: Mapea toda la infraestructura multi-cloud del target identificando proveedores, regiones, servicios CDN frontales, backends, y relaciones entre componentes. Genera un diagrama de infraestructura.
phase: recon
triggers: [múltiples rangos IP en scan inicial, 3+ ASNs diferentes asociados al target, headers de cloud providers variados, CNAMEs apuntando a distintos clouds, respuestas con diferentes TTL/Server según región]
---

# Multi-Cloud Mapper

## Activation Contract

Ejecutar automáticamente cuando:
- `whois` o `dig +short` revelen IPs en **3 o más ASNs diferentes**
- Los CNAMEs del dominio apunten a servicios de distintos clouds (ej: `cloudfront.net` + `azureedge.net`)
- Los headers HTTP (`via:`, `x-forwarded-for`, `x-amz-*`, `x-azure-*`, `x-guploader-*`) indiquen proxies múltiples
- `whatweb` detecte tecnologías de más de un cloud provider
- Se identifique un CDN frontal + servidor de origen en nube distinta
- El target entregue contenido diferente desde distintas geolocalizaciones

## Hard Rules

1. **NO asumir que un solo dominio = un solo proveedor**. Los targets modernos distribuyen servicios en múltiples clouds.
2. **Clasificar cada IP por provider** usando rangos oficiales (AWS, Azure, GCP, OVH, Oracle, DigitalOcean, Hetzner, Linode).
3. **Documentar la cadena completa**: Cliente → CDN → WAF → Load Balancer → Backend → DB/Auth.
4. **Confirmar servicios por fingerprint** (headers, banners, TTL, puertos), no solo por IP.
5. **No escanear agresivamente** rangos enteros de cloud provider. Usar un probe por IP/servicio.
6. **Diferenciar entre hosted y self-hosted**: un servicio en EC2 no es "AWS" como provider — es "AWS (IaaS)" y el software corre en el target.

## Decision Gates

| Pregunta | Acción |
|----------|--------|
| ¿La IP pertenece a un cloud conocido? | Usar `curl ifconfig.co/org` o consultar rangos oficiales vía API (aws ip-ranges.json, azure public ips). |
| ¿Hay CDN frontal + backend separado? | Seguir la cadena de CNAMEs. El último CNAME antes de la IP es el provider real del backend. |
| ¿Es multi-región? | Resolver desde diferentes geolocalizaciones (usar `dig @resolver1-<region>.opendns.com` o proxies geo-distribuidos). |
| ¿El servicio de email está en cloud distinto? | Revisar registros MX — a menudo señalan un provider separado (Google Workspace, M365, Zoho). |
| ¿Hay proveedores de identidad externos? | Buscar en headers `x-auth-*`, cookies `okta-session`, dominios `auth0.com`, `okta.com`. |
| ¿La CDN y el origen comparten ASN? | Si comparten ASN, probablemente es todo del mismo proveedor (ej: AWS CloudFront + ALB + EC2). |

## Execution Steps

### 1. Recopilar todas las IPs y ASNs

```bash
# Resolver A, AAAA, MX, NS, CNAME
TARGET="ejemplo.com"
for type in A AAAA MX NS CNAME; do
  dig +short "$TARGET" "$type" >> "/tmp/cloudmap_${TARGET}_dns.txt"
done

# Extraer IPs únicas
sort -u "/tmp/cloudmap_${TARGET}_dns.txt" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
```

### 2. Identificar cloud provider por IP

```bash
# Usar whois para determinar ASN y org
for ip in $(cat /tmp/cloudmap_ips.txt); do
  whois "$ip" | grep -iE "OrgName|ASNumber|NetName" | head -3
done

# o consultar rangos cloud conocidos
# AWS: curl -s https://ip-ranges.amazonaws.com/ip-ranges.json
# Azure: curl -s https://download.microsoft.com/download/.../PublicIPs.xml
# GCP: curl -s https://www.gstatic.com/ipranges/cloud.json
```

### 3. Mapear cadena DNS/CDN

```bash
# Seguir cadena de CNAME hasta la IP final
resolve_chain() {
  local domain=$1
  local cname=$(dig +short CNAME "$domain")
  if [ -n "$cname" ]; then
    echo "$domain -> $cname"
    resolve_chain "$cname"
  else
    local ip=$(dig +short A "$domain" | head -1)
    echo "$domain -> $ip"
    echo "IP final: $ip"
    whois "$ip" | grep -i "OrgName\|NetName"
  fi
}
resolve_chain "$TARGET"
```

### 4. Comparar respuestas por región

```bash
# Usar resolvers DNS regionales
for region in "resolver1.opendns.com" "dns.google" "208.67.222.222"; do
  echo "=== Resolviendo via $region ==="
  dig @$region +short "$TARGET" A
done

# Probar desde proxies regionales si están disponibles
# curl --proxy "http://proxy-us-east:port" $TARGET
# curl --proxy "http://proxy-eu-west:port" $TARGET
```

### 5. Detectar separación CDN/Origin

```bash
# Diferencia TTL entre CDN y origen
curl -sI "https://$TARGET" | grep -iE "server|x-cache|age|cf-cache"

# Buscar origin en Shodan (mismos servicios, IP diferente)
shodan search "hostname:$TARGET ssl.cert.subject.cn:$TARGET"
```

### 6. Clasificar servicios

| Servicio | Cómo detectar |
|----------|---------------|
| Email | MX → Google, M365, Zoho, Proveedor propio |
| DNS | NS → Route53, CloudDNS, Azure DNS, Cloudflare |
| Auth | Headers/Cookies → Okta, Auth0, Azure AD |
| CDN | CNAME → CloudFront, Cloudflare, Fastly, Akamai |
| Backend | IP final + header `Server:` |
| DB-as-a-Service | RDS, Cloud SQL, CosmosDB (por TTL/puertos) |

## Output Contract

```json
{
  "skill": "multi-cloud-mapper",
  "target": "ejemplo.com",
  "infrastructure_summary": {
    "total_ips": 12,
    "total_asns": 4,
    "cloud_providers": ["aws", "cloudflare", "google", "azure"],
    "regions_detected": ["us-east-1", "eu-west-1", "global-cdn"],
    "frontend_cdn": "cloudflare",
    "backend_cloud": "aws"
  },
  "components": [
    {
      "service": "cdn",
      "provider": "Cloudflare",
      "cname": "ejemplo.com.cdn.cloudflare.net",
      "ips": ["104.16.0.1", "104.16.0.2"],
      "regions": "global",
      "asn": "AS13335"
    },
    {
      "service": "backend",
      "provider": "AWS (EC2)",
      "origin_ip": "52.84.120.50",
      "region": "us-east-1",
      "asn": "AS14618",
      "fingerprint": "nginx/1.24.0, Node.js",
      "via_cdn": true
    },
    {
      "service": "email",
      "provider": "Google Workspace",
      "mx_record": "aspmx.l.google.com",
      "priority": 1
    },
    {
      "service": "auth",
      "provider": "Okta",
      "domain": "ejemplo.okta.com",
      "detection": "cookie: okta-session, header: x-okta-*"
    },
    {
      "service": "dns",
      "provider": "AWS Route53",
      "ns_records": ["ns-123.awsdns-45.net"],
      "asn": "AS16509"
    }
  ],
  "infrastructure_chain": [
    "Usuario → Cloudflare (CDN/WAF) → AWS ALB → EC2 (nginx) → RDS (MySQL)",
    "Email → Google Workspace MX",
    "Auth → Okta (externo)",
    "DNS → Route53"
  ],
  "critical_findings": [
    "Backend en AWS EC2 con origen IP 52.84.120.50 expuesto via SPF y CRT.sh",
    "Auth externalizado a Okta — posible SSO bypass si no hay MFA",
    "Email en Google Workspace — posible phishing vector"
  ],
  "diagram": "
                  +------------------+
                  |   Cloudflare CDN |
                  +--------+---------+
                           |
                  +--------+---------+
                  |   AWS ALB (NLB)  |
                  +--------+---------+
                           |
                  +--------+---------+
                  |   EC2 (nginx)    |
                  +--+------------+--+
                     |            |
            +--------+---+  +----+-------+
            | RDS MySQL  |  | Okta Auth  |
            +------------+  +------------+
  ",
  "recommended_skills": ["origin-ip-discovery", "cdn-origin-discovery", "cloud-metadata", "cloud-iam-enum"],
  "chainable_with": ["cloud-provider-detect", "asn-mapping", "port-scan", "hunt-ssrf-cloud"]
}
```
