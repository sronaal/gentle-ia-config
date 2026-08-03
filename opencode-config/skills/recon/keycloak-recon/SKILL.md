---
name: keycloak-recon
description: Keycloak reconnaissance — realm discovery, version fingerprint, client enumeration, misconfiguration detection, default endpoints, and known CVE mapping
version: 1.0.0
phase: recon
category: identity
tags: [keycloak, sso, oidc, saml, identity-provider, iam]
tools: [curl, nmap, python3, jq, metasploit]
difficulty: intermediate
opsec_level: high
time_estimate: 120s
severity_if_found: high
related_skills:
  - hunt-oauth-flow
  - hunt-saml-testing
  - hunt-jwt-attacks
  - auth-bypass
mitre_attack:
  - T1525
  - T1556
  - T1606
---

## When to Use

Use this skill when the target uses Keycloak for SSO/identity management. Keycloak exposes
multiple endpoints that leak realm configuration, user enumeration possibilities, and
version-specific CVEs. Run this after initial tech detection identifies Keycloak.

## Prerequisites

- Target domain or IP where Keycloak is hosted
- curl with cookie jar, jq for JSON parsing
- python3 with requests library
- nmap for service detection (optional)

## What It Does

Keycloak recon covers:

1. **Realm discovery** — enumerate realms, version fingerprint, default realms
2. **Open endpoints** — well-known configs, public keys, user registration
3. **Client enumeration** — public clients, redirect URIs, auth flows
4. **User enumeration** — registration flows, forgot password, timing attacks
5. **Version detection** — specific CVEs per version (CVE-2022-1248, CVE-2023-0264, etc.)
6. **Misconfiguration** — default credentials, weak token settings, excessive session

## Methodology

### 1. Realm Discovery & Version

```bash
# Default base paths
KEYCLOAK_BASE="https://TARGET"
for path in /auth /realms /auth/realms /master; do
  curl -sk -o /dev/null -w "%{http_code} %{redirect_url}\n" "$KEYCLOAK_BASE$path"
done

# Well-known OpenID configuration
curl -sk "$KEYCLOAK_BASE/realms/master/.well-known/openid-configuration" | jq .

# Check for common realms
for realm in master test admin internal external app dev qa; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$KEYCLOAK_BASE/realms/$realm")
  echo "Realm $realm: $code"
done

# Version from error messages
curl -sk "$KEYCLOAK_BASE/auth/realms/master" 2>&1 | grep -oiP 'keycloak[\s/][\d.]+'

# Version via theme resource
curl -sk -D - "$KEYCLOAK_BASE/resources/" 2>&1 | grep -i "server\|version\|x-keycloak"
```

### 2. OpenID Configuration & Public Keys

```bash
# OIDC discovery for each realm
for realm in master test admin; do
  echo "=== Realm: $realm ==="
  curl -sk "$KEYCLOAK_BASE/realms/$realm/.well-known/openid-configuration" | jq '.issuer, .authorization_endpoint, .token_endpoint, .jwks_uri, .registration_endpoint' 2>/dev/null
done

# Public JWKS keys
curl -sk "$KEYCLOAK_BASE/realms/master/protocol/openid-connect/certs" | jq .

# Check if keys can be used for token forgery (algorithm confusion)
curl -sk "$KEYCLOAK_BASE/realms/master/protocol/openid-connect/certs" | jq '.keys[].alg'
```

### 3. Client Enumeration

```bash
# Check for public clients with implicit flow
for realm in master test; do
  echo "=== Realm $realm ==="
  # Try common client IDs
  for client in account admin-broker security-admin-console test-app app; do
    curl -sk -D - -o /dev/null \
      "$KEYCLOAK_BASE/realms/$realm/protocol/openid-connect/auth?client_id=$client&response_type=token&redirect_uri=http://localhost" 2>&1 | grep -i "location\|error"
  done
done

# Check if /auth endpoint exposes client registration
curl -sk -X POST "$KEYCLOAK_BASE/realms/master/clients-registrations/default" \
  -H "Content-Type: application/json" \
  -d '{"clientId": "test-client"}' | jq .
```

### 4. User Enumeration

```bash
# Registration endpoint check
curl -sk -D - -o /dev/null "$KEYCLOAK_BASE/realms/master/login-actions/registration"

# Forgot password — user enumeration via timing
time curl -sk -X POST "$KEYCLOAK_BASE/realms/master/login-actions/reset-credentials" \
  -d "username=valid@test.com" 2>&1 | grep real

time curl -sk -X POST "$KEYCLOAK_BASE/realms/master/login-actions/reset-credentials" \
  -d "username=invalid@test.com" 2>&1 | grep real

# Login timing — check if valid users have different response times
for user in admin root test valid@test.com; do
  time curl -sk -X POST "$KEYCLOAK_BASE/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli&username=$user&password=wrong&grant_type=password" 2>&1 | grep real
done
```

### 5. Known CVEs by Version

```bash
# Check for specific CVEs
# Keycloak versions and associated CVEs:
# < 18.0.0 — CVE-2022-1248 (information disclosure)
# < 20.0.0 — CVE-2023-0264 (open redirect)
# < 21.1.0 — CVE-2023-6134 (privilege escalation)
# < 22.0.5 — CVE-2024-1234 (request smuggling)

# Check for redirect URI validation bypass
curl -sk -D - -o /dev/null \
  "$KEYCLOAK_BASE/realms/master/protocol/openid-connect/auth?client_id=account&redirect_uri=https://attacker.com&response_type=code" 2>&1

# Check for token endpoint CORS misconfig
curl -sk -D - -o /dev/null \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  "$KEYCLOAK_BASE/realms/master/protocol/openid-connect/token" 2>&1
```

### 6. Default Credentials & Misconfigurations

```bash
# Default admin console
curl -sk -D - -o /dev/null "$KEYCLOAK_BASE/auth/admin/master/console/"
curl -sk -D - -o /dev/null "$KEYCLOAK_BASE/admin/master/console/"

# Check CORS misconfiguration
curl -sk -D - -o /dev/null -H "Origin: https://evil.com" "$KEYCLOAK_BASE/realms/master/"

# Check if registration is enabled (open signup)
REG_URL=$(curl -sk "$KEYCLOAK_BASE/realms/master/.well-known/openid-configuration" | jq -r '.registration_endpoint')
if [ "$REG_URL" != "null" ]; then
  echo "Registration endpoint available: $REG_URL"
fi

# Check if brute force protection is disabled (try multiple logins)
for i in $(seq 1 10); do
  curl -sk -o /dev/null -w "%{http_code}\n" \
    -X POST "$KEYCLOAK_BASE/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli&username=admin&password=wrong$i&grant_type=password"
done
```

## OPSEC

- **Rate limiting**: Keycloak has built-in brute force protection. Spread requests over time.
- **Account lockout**: User enumeration via forgot password can lock accounts. Use test accounts.
- **Logging**: Keycloak logs all failed auth attempts. Coordinate with the blue team.
- **Version fingerprint**: Error messages differ by version. Use them carefully to avoid alerting.

## Verification Checklist

- [ ] Realms enumerated (master + custom)
- [ ] OpenID configuration accessible
- [ ] Public clients discovered
- [ ] Version identified
- [ ] Known CVEs checked
- [ ] User enumeration possible
- [ ] Registration endpoint (if enabled)
- [ ] CORS misconfiguration

## Output Format

```json
{
  "skill": "keycloak-recon",
  "target": "TARGET",
  "status": "completed",
  "realms": ["master", "test", "admin"],
  "version": "22.0.0",
  "open_endpoints": ["well-known", "jwks", "registration"],
  "cves": ["CVE-2023-0264", "CVE-2024-1234"],
  "user_enum_possible": true,
  "evidence": ["realms.txt", "clients.txt", "version.txt"]
}
```

## References

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [CVE-2022-1248 — Keycloak Information Disclosure](https://nvd.nist.gov/vuln/detail/CVE-2022-1248)
- [CVE-2023-0264 — Keycloak Open Redirect](https://nvd.nist.gov/vuln/detail/CVE-2023-0264)
- [Keycloak Hardening Guide](https://www.keycloak.org/server/hardening)
- [HackTricks: Keycloak](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/keycloak)
