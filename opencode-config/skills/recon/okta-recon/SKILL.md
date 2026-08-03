---
name: okta-recon
description: Reconocimiento pasivo y activo de tenants Okta — detección de dominio, endpoints SAML/OIDC/SCIM, enumeración de usuarios, aplicaciones SSO, políticas de MFA y configuraciones de identidad
phase: recon
---

# okta-recon — Reconocimiento de Okta Identity

## Activation Contract

**Trigger**: dominio sospechoso de Okta, URL con `okta.com`, `oktapreview.com`, `okta-emea.com`, o cualquier login que muestre "Okta Sign-In". También se activa si se encuentra un subdominio como `login.example.com` que redirige a Okta o incluye `okta-hosted-login`.

**Tools**: `curl`, `whatweb`, `dig`, `openssl`, `python3`, `jq`, `okta-cli` (si está instalado)

**Dependencias**: ningún otro skill. Corre como Phase 0/1 de recon.

## Hard Rules

1. NO enviar credenciales reales a ningún endpoint — solo probing informativo.
2. NO intentar login — ni siquiera con credenciales por defecto o encontradas. Usar solo endpoints públicos.
3. NO modificar configuraciones del tenant — esto es recon puro.
4. Si el tenant bloquea (403, 429, WAF), detener la skill y reportar el rate limiting.
5. Respetar `User-Agent` estándar de navegador (Mozilla/5.0) para evitar fingerprinting.
6. No exceder 10 requests por minuto al mismo host para evitar rate limiting.

## Decision Gates

| Acción | Preguntar |
|--------|-----------|
| Ejecutar búsqueda de usuarios con `/api/v1/users?search=` | Sí — es activo y puede alertar al tenant |
| Usar `okta-cli` con autenticación | Sí — requiere API token, riesgo alto |
| Probar subdominios de Okta (brute force) | Sí — puede generar alto volumen de requests |
| Enumerar Workflows/API endpoints internos | No — si son públicos, sigue siendo recon |

## Execution Steps

### 1. Detectar Tenant Okta

```bash
# Verificar redirección Okta
curl -sI "https://$TARGET" | grep -i "okta\|okta-hosted\|x-okta-request-id"
# DNS CNAME a okta.com
dig CNAME "$TARGET" | grep -i "okta"
# whatweb para fingerprint
whatweb "https://$TARGET" | grep -i okta
```

Buscar también: `subdomain.okta.com`, `subdomain.oktapreview.com`, `subdomain.okta-emea.com`.

### 2. Enumerar Endpoints Públicos

```bash
# OIDC Discovery
curl -s "https://$TARGET/.well-known/openid-configuration"
# SAML Metadata
curl -s "https://$TARGET/app/$APP_ID/sso/saml/metadata"
# SCIM Base URL (si se expone)
curl -sI "https://$TARGET/scim/v2/"
# OAuth Authorization Server metadata
curl -s "https://$TARGET/oauth2/default/.well-known/oauth-authorization-server"
# JWKS endpoint (riesgo si es accesible sin auth)
curl -s "https://$TARGET/oauth2/default/v1/keys"
```

### 3. User Enumeration (requiere aprobación)

```bash
# Probar si /api/v1/users es accesible sin auth
curl -s "https://$TARGET/api/v1/users?search=admin&limit=1"
# Buscar en páginas públicas de login si revela "unknown user" vs "invalid password"
```

### 4. Enumerar Aplicaciones SSO

```bash
# Intentar descubrir aplicaciones configuradas
curl -s "https://$TARGET/app/UserHome"
# Buscar en páginas públicas de catálogo de apps
```

### 5. Detectar MFA y Políticas

```bash
# Endpoint de políticas de autenticación
curl -s "https://$TARGET/api/v1/policies" | jq .
# Detectar si MFA es obligatorio por headers o respuesta
```

### 6. Okta Workflows y Access Gateway

```bash
# Workflows console (si está expuesto)
curl -sI "https://$TARGET/workflows/"
# Okta Access Gateway (subdominio OAG)
curl -sI "https://oag-$SUBDOMAIN.$TARGET/"
```

## Output Contract

```json
{
  "phase": "recon",
  "skill": "okta-recon",
  "target": "example.okta.com",
  "tenant_found": true,
  "endpoints": {
    "oidc": "https://example.okta.com/.well-known/openid-configuration",
    "saml": "discovered",
    "scim": null,
    "jwks": "https://example.okta.com/oauth2/default/v1/keys",
    "oauth_servers": ["default", "custom"]
  },
  "user_enumeration": {
    "possible": true,
    "method": "/api/v1/users?search= returns 401 vs 404 difference",
    "risk": "medium"
  },
  "sso_apps_discovered": ["slack", "aws", "github"],
  "mfa_detected": {
    "required": true,
    "factors": ["okta_verify", "sms", "totp"]
  },
  "workflows_detected": false,
  "access_gateway_detected": false,
  "findings": [
    {
      "title": "JWKS endpoint públicamente accesible",
      "severity": "medium",
      "category": "information_disclosure",
      "evidence": "https://example.okta.com/oauth2/default/v1/keys retornó claves públicas"
    },
    {
      "title": "User enumeration posible",
      "severity": "medium",
      "category": "enumeration",
      "evidence": "Diferencia en respuesta entre usuario existente e inexistente en /api/v1/users"
    }
  ],
  "summary": "Tenant Okta detectado con OIDC, SAML, JWKS expuesto, MFA con factores múltiples",
  "next_phase": "exploit",
  "recommended_skills": ["okta-exploit", "hunt-jwt-attacks", "hunt-oauth-flow"]
}
```
