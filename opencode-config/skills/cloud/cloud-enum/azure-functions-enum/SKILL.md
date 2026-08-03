---
name: azure-functions-enum
description: Enumerar Azure Function Apps, funciones, triggers, app settings con secrets, function keys, slots de deployment y managed identities
phase: cloud-enum
---

# azure-functions-enum — Enumeración de Azure Functions

## Activation Contract

**Trigger**: Se detectó una Function App en la suscripción (via resource graph, `az functionapp list`, o por URLs con `/api/*` que responden con `You do not have permission to view this directory or page`).

**Pre-requisitos**:
- Azure CLI autenticado (`az login`)
- Permisos `Reader` sobre la Function App o al menos a nivel de resource group
- `az rest` para llamadas directas a API de Azure Resource Manager

## Hard Rules

1. NO invocar funciones (eso es explotación)
2. NO modificar app settings ni connection strings
3. NO leer `APPINSIGHTS_INSTRUMENTATIONKEY` ni connection strings de base de datos — documentar solo que existen
4. OPSEC: `--output json`, `--query` para filtrar, no hacer llamadas consecutivas rápidas (< 1s)

## Decision Gates

Preguntar al usuario ANTES de:
- Listar `function keys` (pueden permitir invocar funciones sin autenticación)
- Listar `app settings` de la Function App (contienen secrets como `AzureWebJobsStorage`, `SQL_CONNECTION`, `API_KEY`)
- Leer el contenido de una Function Key individual
- Acceder a slots de deployment (staging puede tener configs diferentes)

## Execution Steps

### Paso 1: Listar Function Apps
```bash
az functionapp list --resource-group <rg> --output json | jq '[.[] | {name: .name, rg: .resourceGroup, location: .location, kind: .kind, state: .state, defaultHostName: .defaultHostName}]'
```
Extraer: `name`, `defaultHostName` (URL base, ej: `https://func-prod.azurewebsites.net`), `kind` (`functionapp`, `functionapp,linux`), `state`, `siteConfig` (si es accesible).

### Paso 2: Describir configuración de la Function App
```bash
az functionapp show --name <func-name> --resource-group <rg>
```
Extraer información clave:
- `identity` → `type` (SystemAssigned, UserAssigned), `principalId`, `tenantId`
- `siteConfig` → `linuxFxVersion` (runtime), `alwaysOn`, `http20Enabled`, `minTlsVersion`, `ftpsState`
- `hostNameSslStates` → certificados SSL
- `outboundIpAddresses`, `possibleOutboundIpAddresses` — rangos IP de salida
- `vnetRouteAllEnabled` — si la function está integrada con VNet

### Paso 3: Enumerar app settings (contienen secrets)
```bash
az functionapp config appsettings list --name <func-name> --resource-group <rg>
```
Extraer settings de alto riesgo:
- `AzureWebJobsStorage` — connection string del Storage Account
- `AzureWebJobsDashboard` — monitoring
- `FUNCTIONS_EXTENSION_VERSION` — versión del runtime (~4, ~3)
- `APPINSIGHTS_INSTRUMENTATIONKEY` — Application Insights key
- Cualquier setting con nombre que contenga: `CONNECTION`, `PASSWORD`, `KEY`, `SECRET`, `TOKEN`, `ENDPOINT`

NO leer el valor de connection strings — solo documentar su existencia y el tipo de recurso al que apuntan (SQL, Storage, ServiceBus, etc.).

### Paso 4: Enumerar funciones y triggers
```bash
# Listar funciones dentro de la Function App
az functionapp function list --name <func-name> --resource-group <rg>
az functionapp function show --name <func-name> --function-name <fn-name> --resource-group <rg>
```
Extraer:
- `name` (función individual, ej: `http-trigger`, `process-order`)
- `config` → `bindings[]` → `type`, `direction`, `authLevel`, `methods` (GET/POST), `route` (URL path)
- `language` (JavaScript, C#, Python, Java)
- `disabled` (si la función está deshabilitada)

Identificar triggers expuestos:
- `httpTrigger` con `authLevel: anonymous` — cualquier persona puede invocar la función
- `httpTrigger` con `authLevel: function` — requiere function key
- `timerTrigger`, `queueTrigger`, `blobTrigger`, `eventGridTrigger`, `serviceBusTrigger`

### Paso 5: Enumerar Function Keys
```bash
az functionapp function keys list --name <func-name> --function-name <fn-name> --resource-group <rg>
az functionapp keys list --name <func-name> --resource-group <rg>  # Host keys (maestra)
```
Las keys permiten invocar funciones HTTP sin autenticación de Azure AD. La `_master` key da acceso a todas las funciones, incluyendo las administrativas.

### Paso 6: Enumerar deployment slots
```bash
az functionapp deployment slot list --name <func-name> --resource-group <rg>
az functionapp config appsettings list --name <func-name> --slot <slot-name> --resource-group <rg>
```
Los slots de staging pueden tener:
- Configuraciones diferentes (menos restrictivas)
- Versiones anteriores del código con vulnerabilidades conocidas
- Connection strings a bases de datos de staging (posiblemente iguales a prod)

### Paso 7: Enumerar cors y networking
```bash
az functionapp cors show --name <func-name> --resource-group <rg>
az functionapp show --name <func-name> --rg <rg> --query siteConfig
```
- CORS configurado (si permite `*` o dominios externos)
- `ipSecurityRestrictions` — restricciones de IP
- `vnetRouteAllEnabled` — integración VNet

## Output Contract

```json
{
  "phase": "cloud-enum",
  "skill": "azure-functions-enum",
  "target": "<function-app-name>",
  "function_app": {
    "name": "func-prod-orders",
    "hostname": "func-prod-orders.azurewebsites.net",
    "runtime": "node|18",
    "identity": "SystemAssigned (principalId: xxxx)",
    "outbound_ips": ["20.10.10.0/24"]
  },
  "functions": [
    {
      "name": "http-create-order",
      "type": "httpTrigger",
      "auth_level": "anonymous",
      "methods": ["POST"],
      "route": "api/orders",
      "risk": "critical"
    },
    {
      "name": "process-payment",
      "type": "queueTrigger",
      "queue": "payments-pending"
    }
  ],
  "app_settings_sensitive": [
    "AzureWebJobsStorage (StorageAccount)",
    "SQL_CONNECTION (Azure SQL)",
    "STRIPE_API_KEY (Stripe)"
  ],
  "function_keys": {
    "http-create-order": {
      "default": "abc123...",
      "risk": "anonymous_access"
    },
    "host_master": "xxxx... (no leer valor)"
  },
  "findings": [
    {
      "title": "HTTP Function sin autenticación (anonymous)",
      "severity": "critical",
      "category": "function-anonymous-trigger",
      "evidence": "La función http-create-order tiene authLevel=anonymous y puede ser invocada sin credenciales",
      "remediation": "Cambiar authLevel a 'function' o Azure AD, validar inputs en la función",
      "next_steps": ["Probar invocar la función con curl", "Analizar si la función expone datos sensibles"]
    },
    {
      "title": "App Settings contienen secrets de Stripe",
      "severity": "high",
      "category": "function-secrets-exposure",
      "evidence": "STRIPE_API_KEY presente en app settings de func-prod-orders",
      "remediation": "Migrar secrets a Azure Key Vault con referencia @Microsoft.KeyVault()",
      "next_steps": ["Probar acceso a Key Vault via Managed Identity"]
    }
  ],
  "next_phase": "cloud-exploit",
  "recommended_skills": ["azure-functions-exploit", "azure-keyvault"]
}
```
