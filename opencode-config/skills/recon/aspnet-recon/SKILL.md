---
name: aspnet-recon
description: Reconocimiento de aplicaciones ASP.NET — versión, ViewState, tracing, Swagger y configuración expuesta
phase: recon
---

# aspnet-recon — Reconocimiento de ASP.NET

## Contrato de Activación

Activás esta skill CUANDO:
- Detectás headers `X-AspNet-Version`, `X-AspNetMvc-Version` o `X-Powered-By: ASP.NET`
- Encontrás campos ocultos `__VIEWSTATE` o `__EVENTVALIDATION` en formularios HTML
- La URL responde con `/trace.axd` o `/elmah.axd`
- Detectás cookies `ASP.NET_SessionId` o `.ASPXAUTH`

No la activés para sitios PHP, Python o Ruby.

## Reglas Firmes

1. **ViewState es solo lectura**: no intentés modificar __VIEWSTATE. Eso es de exploit
2. **trace.axd requiere confirmación**: acceder a trace.axd expone requests completos de otros usuarios
3. **No descargar web.config sin preguntar**: puede contener connection strings en texto plano
4. **Distinguir Framework vs Core**: .NET Framework usa headers ASP.NET clásicos, .NET Core usa `X-Powered-By: ASP.NET` más sutil

## Compuertas de Decisión

- "Se detectó ASP.NET. ¿Procedo a verificar trace.axd expuesto? (expone requests de otros usuarios)"
- "¿Querés que enumere Swagger UI (/swagger, /swagger/ui) y documentación de API?"
- "Se encontró __VIEWSTATE. ¿Analizo su tamaño y contenido? (puede indicar deserialización insegura)"
- "¿Intento acceder a web.config? (puede exponer machineKey y connection strings)"

## Pasos de Ejecución

### Fase 1 — Fingerprinting pasivo

```bash
# 1. Headers ASP.NET
curl -sI "https://target.com/" | grep -iE "x-aspnet|x-powered-by|x-requestid"

# 2. Cookies
curl -sI "https://target.com/" | grep -iE "ASP.NET_SessionId|.ASPXAUTH|__RequestVerificationToken"

# 3. Detectar ViewState en HTML
curl -s "https://target.com/" | grep -iE "__VIEWSTATE|__EVENTVALIDATION|__VIEWSTATEGENERATOR"
```

### Fase 2 — Enumeración de superficie

```bash
# 4. Tracing expuesto
curl -sI "https://target.com/trace.axd"
curl -sI "https://target.com/elmah.axd"

# 5. Swagger UI (NET Core)
curl -sI "https://target.com/swagger"
curl -sI "https://target.com/swagger/v1/swagger.json"
curl -sI "https://target.com/api-docs"

# 6. Archivos de configuración
curl -sI "https://target.com/web.config"
curl -sI "https://target.com/Web.config"
curl -sI "https://target.com/appsettings.json"

# 7. Rutas MVC comunes
curl -sI "https://target.com/areas"
curl -sI "https://target.com/api/values"
curl -sI "https://target.com/odata"
```

### Fase 3 — Detección de versión y framework

```bash
# 8. Versión via header exacto
curl -sI "https://target.com/" | grep "X-AspNet-Version"

# 9. .NET Core vs Framework
# .NET Framework: X-AspNet-Version, X-AspNetMvc-Version
# .NET Core: X-Powered-By: ASP.NET, server: Kestrel
curl -sI "https://target.com/" | grep -iE "server|kestrel|iis"

# 10. Directory listing
curl -sI "https://target.com/bin/"
curl -sI "https://target.com/Content/"
```

### Fase 4 — Análisis de ViewState

```bash
# 11. Extraer ViewState (tamaño como indicador)
VIEWSTATE=$(curl -s "https://target.com/" | grep -oP '__VIEWSTATE\|value="([^"]+)"' | head -1)
echo "ViewState length: ${#VIEWSTATE}"

# 12. Detectar machineKey leak
curl -s "https://target.com/web.config" | grep -iE "machineKey|decryptionKey|validationKey"
```

## Contrato de Salida

```json
{
  "skill": "aspnet-recon",
  "target": "ejemplo.com",
  "aspnet_detected": true,
  "framework": ".NET Framework 4.8",
  "version": "4.8.4488.0",
  "cpes": ["cpe:/a:microsoft:asp.net:4.8"],
  "runtime": "IIS 10.0",
  "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
  "traces": [
    {"path": "/trace.axd", "accessible": false},
    {"path": "/elmah.axd", "accessible": false}
  ],
  "swagger": {"accessible": false},
  "viewstate_detected": true,
  "viewstate_length": 5420,
  "findings": [
    {
      "title": "ViewState presente sin MAC",
      "severity": "medio",
      "evidence": "__VIEWSTATE field detected, length 5420, no __VIEWSTATEMAC presente",
      "cwe": "CWE-502"
    }
  ]
}
```
