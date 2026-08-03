---
name: weblogic-recon
description: Reconocimiento de servidores Oracle WebLogic — consolas, versionado, vulnerabilidades conocidas y JNDI
phase: recon
---

# weblogic-recon — Reconocimiento de Oracle WebLogic

## Contrato de Activación

Activás esta skill CUANDO:
- Encontrás `/console/login/LoginForm.jsp` con branding de Oracle WebLogic
- Detectás cookies `JSESSIONID` en contexto WebLogic (con patrón ~id hash)
- Las URLs contienen `/wls-wsat/`, `/_async/` o `/bea_wls_deployment_internal/`
- El header `Server` contiene `WebLogic` o `WebLogic Server`
- Puerto 7001, 7002, 8001 comunes de WebLogic están abiertos

No la activés para JBoss, WebSphere, Tomcat o GlassFish.

## Reglas Firmes

1. **NO ejecutar payloads de deserialización**: detectar versión para matching con CVE es recon. Ejecutar exploits es de la fase exploit
2. **/wls-wsat es sensible**: la presencia de este endpoint indica posible CVE-2017-10271 pero no intentés explotarlo
3. **Consola de administración requiere aprobación**: preguntar antes de probar credenciales por defecto
4. **Evidencia obligatoria**: capturar headers de respuesta de login page y páginas de error

## Compuertas de Decisión

- "Se detectó WebLogic. ¿Verifico consolas accesibles (/console, /wls-wsat)?"
- "¿Procedo con fingerprinting de versión via login page? (permite CVE matching)"
- "¿Querés que verifique si /wls-wsat/CoordinatorPortType está accesible?"
- "¿Intento detectar vulnerabilidades conocidas via headers y version? (CVE-2020-14882, CVE-2017-10271)"

## Pasos de Ejecución

### Fase 1 — Detección y fingerprinting

```bash
# 1. Puerto común WebLogic
curl -sI "https://target.com:7001/console/login/LoginForm.jsp" | head -20

# 2. Headers de servidor
curl -sI "https://target.com:7001/" | grep -iE "server|weblogic|x-powered"

# 3. Login page (fingerprint de versión)
curl -s "https://target.com:7001/console/login/LoginForm.jsp" | \
  grep -iE "weblogic|version|oracle|bea|fusion"
```

### Fase 2 — Enumeración de consolas

```bash
# 4. Consola principal
curl -sI "https://target.com:7001/console/"
curl -sI "https://target.com:7001/console/login/LoginForm.jsp"

# 5. WS-AT (Web Services Atomic Transaction)
curl -sI "https://target.com:7001/wls-wsat/"
curl -sI "https://target.com:7001/wls-wsat/CoordinatorPortType"

# 6. Consola async
curl -sI "https://target.com:7001/_async/"

# 7. Deployment internal
curl -sI "https://target.com:7001/bea_wls_deployment_internal/"
```

### Fase 3 — Versión exacta

```bash
# 8. Version via HTML de login
curl -s "https://target.com:7001/console/login/LoginForm.jsp" | \
  grep -oP 'WebLogic Server Version [0-9.]+' | head -1

# 9. Version via /console/ (página de error)
curl -sI "https://target.com:7001/console/" | grep -iE "weblogic|version"

# 10. Cabeceras de versión en respuestas
curl -s -D - "https://target.com:7001/console/../console.portal" -o /dev/null | \
  grep -iE "weblogic|version"
```

### Fase 4 — Mapeo de vulnerabilidades

```bash
# 11. Endpoints de vulnerabilidades conocidas (SOLO DETECCIÓN)
for path in wls-wsat console bea_wls_deployment_internal _async \
  uddi wsee jms ejb; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com:7001/$path/")
  echo "$code - /$path/"
done

# 12. JNDI tree
curl -sI "https://target.com:7001/jndi/"
```

## Contrato de Salida

```json
{
  "skill": "weblogic-recon",
  "target": "ejemplo.com",
  "weblogic_detected": true,
  "version": "12.2.1.4.0",
  "cpes": ["cpe:/a:oracle:weblogic_server:12.2.1.4.0"],
  "port": 7001,
  "consoles": {
    "console_login": {"code": 200, "accessible": true},
    "wls_wsat": {"code": 200, "accessible": true, "cve_related": "CVE-2017-10271"},
    "async": {"code": 404, "accessible": false}
  },
  "vulnerable_endpoints": [
    {"path": "/wls-wsat/CoordinatorPortType", "code": 200, "cve": "CVE-2017-10271"}
  ],
  "findings": [
    {
      "title": "WebLogic versión 12.2.1.4.0 con /wls-wsat expuesto",
      "severity": "alto",
      "evidence": "GET /wls-wsat/CoordinatorPortType → 200. Versión detectada via login page HTML",
      "cwe": "CWE-1104",
      "known_vulnerabilities": [
        {"cve": "CVE-2020-14882", "type": "Auth bypass → RCE", "cvss": 9.8},
        {"cve": "CVE-2017-10271", "type": "XMLDecoder RCE", "cvss": 7.5},
        {"cve": "CVE-2018-2628", "type": "T3 deserialization", "cvss": 9.8}
      ],
      "next_steps": ["Validar CVE-2020-14882 auth bypass", "Verificar T3 protocol habilitado"]
    }
  ]
}
```
