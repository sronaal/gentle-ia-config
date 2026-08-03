---
name: aws-cognito-enum
description: Enumerar Amazon Cognito User Pools, Identity Pools, clientes OAuth, usuarios, grupos y roles asociados
phase: cloud-enum
---

# aws-cognito-enum — Enumeración de Cognito

## Activation Contract

**Trigger**: Se detecta un Cognito User Pool ID, App Client ID, Identity Pool ID, o se encuentra un dominio `auth.<target>.com` que apunta a Cognito Hosted UI.

**Pre-requisitos**:
- AWS CLI configurado con perfil (`--profile <target>`)
- Permisos `cognito-idp:ListUserPools`, `cognito-idp:DescribeUserPool`, `cognito-idp:ListUsers`, `cognito-identity:ListIdentityPools`, `cognito-identity:DescribeIdentityPool`
- Si no hay acceso a la API de AWS, se puede hacer OSINT del Hosted UI y extraer `UserPoolId` desde el HTML del login (`_user_pool_id`)

## Hard Rules

1. NO modificar nada en los pools (no crear/borrar usuarios, no cambiar configs)
2. NO intentar autenticarse contra el User Pool salvo que el Decision Gate lo autorice
3. NO exfiltrar datos de usuarios fuera del entorno de analysis
4. OPSEC: usar `--no-cli-pager`, `--output json`, jitter de 1s entre llamadas API

## Decision Gates

Preguntar al usuario ANTES de:
- Listar usuarios de un pool (es una enumeración intrusiva que queda en CloudTrail)
- Intentar registrarse en un pool que permita self-signup
- Probar OAuth flows contra el Hosted UI con credenciales por defecto

## Execution Steps

### Paso 1: Listar User Pools
```bash
aws cognito-idp list-user-pools --max-results 60 --profile <target> --region <region>
```
Guardar `Id` y `Name` de cada pool.

### Paso 2: Describir cada User Pool
```bash
aws cognito-idp describe-user-pool --user-pool-id <pool-id> --profile <target>
```
Extraer: `Arn`, `LambdaConfig` (triggers), `Policies` (password policy), `SchemaAttributes` (atributos requeridos), `AutoVerifiedAttributes`, `MfaConfiguration`, `AccountRecoverySetting`, `Domain` (Hosted UI domain).

### Paso 3: Listar App Clients
```bash
aws cognito-idp list-user-pool-clients --user-pool-id <pool-id> --profile <target>
aws cognito-idp describe-user-pool-client --user-pool-id <pool-id> --client-id <client-id> --profile <target>
```
Detectar: `ExplicitAuthFlows`, `AllowedOAuthFlows` (`code`, `implicit`, `client_credentials`), `AllowedOAuthScopes`, `CallbackURLs`, `LogoutURLs`, `SupportedIdentityProviders`.

Señales de riesgo:
- OAuth flow `implicit` (token en URL fragment — leakage)
- `client_credentials` sin secret (puede generar tokens sin user context)
- `CallbackURLs` con `http://localhost` o `https://evil.com`

### Paso 4: Listar Identity Pools
```bash
aws cognito-identity list-identity-pools --max-results 60 --profile <target>
aws cognito-identity describe-identity-pool --identity-pool-id <pool-id> --profile <target>
```
Detectar: `AllowUnauthenticatedIdentities` (flag crítico), `CognitoIdentityProviders` (vinculación con User Pools), `SamlProviderARNs`, `OpenIdConnectProviderARNs`.

### Paso 5: Enumerar usuarios (solo si el Decision Gate lo autoriza)
```bash
aws cognito-idp list-users --user-pool-id <pool-id> --profile <target>
```
Extraer: `Username`, `UserStatus`, `Enabled`, `UserCreateDate`, `UserLastModifiedDate`, `Attributes` (email, phone, custom:).

### Paso 6: Enumerar grupos
```bash
aws cognito-idp list-groups --user-pool-id <pool-id> --profile <target>
aws cognito-idp list-users-in-group --user-pool-id <pool-id> --group-name <group> --profile <target>
```
Mapear grupos → usuarios para identificar roles privilegiados (`admin`, `manager`).

### Paso 7: Identificar recursos asociados
- Buscar triggers de Lambda (`LambdaConfig`) para identificar funciones asociadas (pre-signup, post-authentication, etc.)
- Identificar regiones mediante el `UserPoolId` (formato: `<region>_<hash>`)

## Output Contract

```json
{
  "phase": "cloud-enum",
  "skill": "aws-cognito-enum",
  "target": "<pool-id|domain>",
  "user_pools": [
    {
      "id": "us-east-1_abc123",
      "name": "prod-users",
      "domain": "auth.target.com",
      "mfa": "ON",
      "password_policy": {"min_length": 8, "require_uppercase": true},
      "lambda_triggers": ["PreSignUp", "PostAuthentication"],
      "clients": [
        {
          "client_id": "abc123...",
          "name": "web-app",
          "o_auth_flows": ["code"],
          "callback_urls": ["https://app.target.com/callback"],
          "risk": "low"
        }
      ]
    }
  ],
  "identity_pools": [
    {
      "id": "us-east-1:xxxx-xxxx",
      "name": "prod-identity",
      "allow_unauthenticated": true,
      "risk": "critical"
    }
  ],
  "users": [
    {"username": "admin@target.com", "status": "CONFIRMED", "groups": ["Admins"]}
  ],
  "findings": [
    {
      "title": "Identity Pool permite acceso no autenticado",
      "severity": "critical",
      "category": "cognito-misconfig",
      "evidence": "AllowUnauthenticatedIdentities=true en <identity-pool-id>",
      "next_steps": ["Intentar obtener credenciales temporales sin auth", "Escalar roles vía Cognito"]
    }
  ],
  "next_phase": "cloud-exploit",
  "recommended_skills": ["aws-cognito-exploit"]
}
```
