---
name: auth0-recon
description: Auth0 tenant reconnaissance — domain discovery, tenant metadata, rule/action audit, social login misconfig, token config review, and custom DB enumeration
version: 1.0.0
phase: recon
category: identity
tags: [auth0, sso, oidc, oauth, identity-provider, jwt]
tools: [curl, python3, jq, nmap]
difficulty: intermediate
opsec_level: high
time_estimate: 120s
severity_if_found: high
related_skills:
  - hunt-oauth-flow
  - hunt-oauth-misconfig
  - hunt-jwt-attacks
  - hunt-account-takeover
mitre_attack:
  - T1525
  - T1556
  - T1606
---

## When to Use

Use this skill when the target uses Auth0 for authentication/authorization. Auth0 tenants
expose multiple endpoints that can leak configuration, enable user enumeration, and reveal
misconfigurations in rules, connections, and token settings.

## Prerequisites

- Auth0 tenant domain (e.g., tenant.auth0.com or custom domain)
- curl with cookie jar, jq for JSON parsing
- python3 with requests library

## What It Does

Auth0 recon covers:

1. **Tenant discovery** — find Auth0 domains, custom domains, cloud regions
2. **OIDC metadata** — OAuth/OIDC configuration, JWKS, public keys
3. **Connection enumeration** — social login, SAML, OIDC, email/password connections
4. **Rule/Action audit** — detect custom rules that may leak data or have vulns
5. **User enumeration** — signup, forgot password, login flow differentials
6. **Token config** — algorithm, expiry, signing key info leakage
7. **Known CVEs** — version-specific vulnerabilities

## Methodology

### 1. Tenant Discovery

```bash
# Find Auth0 tenant domains (common patterns)
for tenant in TARGET dev-test app-test target-dev app-prod; do
  echo "=== $tenant ==="
  curl -sk -o /dev/null -w "%{http_code}" "https://$tenant.auth0.com/.well-known/openid-configuration"
  echo ""
done

# Custom domain check
curl -sk -D - -o /dev/null "https://TARGET/login" 2>&1 | grep -i "auth0\|tenant"
curl -sk -D - -o /dev/null "https://TARGET/auth/login" 2>&1 | grep -i "auth0\|tenant"
curl -sk -D - -o /dev/null "https://TARGET/api/auth/callback" 2>&1 | grep -i "auth0\|tenant"

# Cloud region detection (from response headers or URLs)
curl -sk -v "https://TARGET/.well-known/openid-configuration" 2>&1 | grep -i "region\|eu\|us\|au"
```

### 2. OIDC Configuration & JWKS

```bash
# Standard endpoints
curl -sk "https://TARGET/.well-known/openid-configuration" | jq .
curl -sk "https://TARGET/.well-known/oauth-authorization-server" | jq .

# Extract key endpoints
ISSUER=$(curl -sk "https://TARGET/.well-known/openid-configuration" | jq -r '.issuer')
JWKS_URI=$(curl -sk "https://TARGET/.well-known/openid-configuration" | jq -r '.jwks_uri')
AUTH_URL=$(curl -sk "https://TARGET/.well-known/openid-configuration" | jq -r '.authorization_endpoint')
TOKEN_URL=$(curl -sk "https://TARGET/.well-known/openid-configuration" | jq -r '.token_endpoint')
echo "Issuer: $ISSUER"
echo "JWKS: $JWKS_URI"

# Fetch public keys — check algorithm
curl -sk "$JWKS_URI" | jq '.keys[] | {alg: .alg, kty: .kty, use: .use}'

# Check for algorithm confusion opportunities
curl -sk "$JWKS_URI" | jq '.keys[].alg' | sort -u
```

### 3. Connection Enumeration

```bash
# Check for social login connections from login page
curl -sk "https://TARGET/login" | grep -oiP 'google|facebook|github|apple|twitter|linkedin|microsoft|saml|oidc' | sort -u

# Check signup page for enabled connections
curl -sk "https://TARGET/signup" | grep -oiP 'google|facebook|github|apple|twitter|linkedin|microsoft' | sort -u

# SAML connection metadata
curl -sk "https://TARGET/saml/metadata" | head -50
curl -sk "https://TARGET/auth/saml/metadata" | head -50

# Check if SAML ACS endpoint is exposed
curl -sk -D - -o /dev/null "https://TARGET/login/callback"
```

### 4. User Enumeration

```bash
# Signup — check if user exists
for email in admin@test.com root@test.com user@test.com; do
  RESP=$(curl -sk -X POST "https://TARGET/dbconnections/signup" \
    -H "Content-Type: application/json" \
    -d "{\"client_id\":\"TEST\",\"email\":\"$email\",\"password\":\"Test123!\",\"connection\":\"Username-Password-Authentication\"}" \
    -w "\n%{http_code}")
  echo "$email: $RESP"
done

# Forgot password — user enumeration via response difference
for email in valid@test.com invalid@test.com; do
  curl -sk -X POST "https://TARGET/lo/reset" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\"}" -w " [%{http_code}]\n" -o /dev/null
done

# Login timing attack
for email in valid@test.com invalid@test.com; do
  time curl -sk -X POST "https://TARGET/oauth/token" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$email\",\"password\":\"wrong\",\"grant_type\":\"password\",\"client_id\":\"TEST\"}" 2>&1 | grep real
done
```

### 5. Token Configuration Review

```bash
# Check token endpoint CORS
curl -sk -D - -o /dev/null \
  -H "Origin: https://evil.com" \
  "https://TARGET/oauth/token"

# Check if HS256 signed tokens might be forged (if RSA public key exposed)
curl -sk "https://TARGET/pem" | head -5
curl -sk "https://TARGET/certs" | head -5

# Check for id_token leakage in URLs (response_mode)
curl -sk -D - -o /dev/null \
  "https://TARGET/authorize?response_type=id_token%20token&client_id=TEST&redirect_uri=https://localhost&nonce=123&scope=openid%20profile"

# Auth0 delegation endpoint (deprecated but may be enabled)
curl -sk -X POST "https://TARGET/delegation" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

### 6. Known Issues & CVEs

```bash
# Misconfigured CORS on token endpoint
curl -sk -D - -o /dev/null \
  -H "Origin: null" \
  "https://TARGET/oauth/token" 2>&1 | grep -i "access-control"

# Check if refresh token rotation is disabled
curl -sk -X POST "https://TARGET/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"refresh_token\",\"client_id\":\"TEST\",\"refresh_token\":\"TEST\"}" | jq '.refresh_token'

# Check if MFA can be bypassed via API
curl -sk -D - -o /dev/null -X POST "https://TARGET/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"test@test.com\",\"password\":\"test123\",\"grant_type\":\"password\",\"client_id\":\"TEST\",\"scope\":\"openid profile email offline_access\"}" 2>&1

# Check for Legacy Lock API (older deployments)
curl -sk "https://TARGET/usernamepassword/login" -D - -o /dev/null 2>&1
```

### 7. Custom Domain & CDN Misconfig

```bash
# Check tenant's CDN asset URL for info disclosure
for cdn_url in "https://TARGET.auth0.com" "https://cdn.auth0.com/tenant/TARGET"; do
  curl -sk "$cdn_url" | grep -oiP "version|release|build" | head -5
done
```

## OPSEC

- **Rate limiting**: Auth0 enforces rate limits aggressively (1000 req/min per IP). Distribute requests.
- **Account lockout**: Login attempts trigger account lockout after configurable attempts.
- **Tenant isolation**: Different tenants may share IPs. Confirm target tenant before reporting.
- **Evidence**: Save full OIDC config, JWKS response, and login page HTML for evidence.

## Verification Checklist

- [ ] Tenant domain identified
- [ ] OIDC configuration retrieved
- [ ] JWKS public keys fetched
- [ ] Enabled connections enumerated (social, SAML, OIDC, DB)
- [ ] User enumeration tested
- [ ] Token endpoint CORS checked
- [ ] MFA bypass tested
- [ ] Known CVEs assessed

## Output Format

```json
{
  "skill": "auth0-recon",
  "target": "TARGET",
  "status": "completed",
  "tenant": "target-dev.auth0.com",
  "issuer": "https://target-dev.auth0.com/",
  "jwks_uri": "https://target-dev.auth0.com/.well-known/jwks.json",
  "connections": ["google", "github", "Username-Password-Authentication"],
  "user_enum_possible": true,
  "cors_misconfig": false,
  "evidence": ["oidc-config.json", "jwks.json", "login-page.html"]
}
```

## References

- [Auth0 API Documentation](https://auth0.com/docs/api)
- [Auth0 Security Bulletins](https://auth0.com/docs/security/bulletins)
- [Auth0 OIDC Discovery](https://auth0.com/docs/authenticate/login/auth0-universal-login/oidc-discovery)
- [HackTricks: Auth0](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/auth0)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheat_sheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
