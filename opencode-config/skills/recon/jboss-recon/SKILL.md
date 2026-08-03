---
name: jboss-recon
description: Reconocimiento de servidores JBoss AS/WildFly — JMX console, admin console, deployments y versión
phase: recon
---

# jboss-recon — Reconocimiento de JBoss/WildFly

## Contrato de Activación

Activás esta skill CUANDO:
- Detectás headers `X-Powered-By: JBoss`, `X-Powered-By: WildFly` o `Server: JBoss`
- Encontrás `/console/`, `/web-console/` o `/jmx-console/` en el sitio
- La página de login tiene branding de JBoss/WildFly (logo rojo, "JBoss Management")
- URLs contienen `/invoker/`, `/jndi/` o `/deploy/`

No la activés para Tomcat, Jetty, WebSphere o WebLogic sin señales de JBoss.

## Reglas Firmes

1. **JMX console es crítica**: acceso a JMX permite ejecutar métodos arbitrarios en el servidor
2. **No deployar nada**: ningún WAR o archivo debe subirse al servidor — eso es de exploit
3. **No invocar MBeans sin permiso**: la invocación de métodos puede modificar estado del servidor
4. **Evidencia obligatoria**: cada consola encontrada debe documentarse con código HTTP

## Compuertas de Decisión

- "Se detectó JBoss AS. ¿Procedo con enumeración de consolas? (JMX, admin, web)"
- "¿Querés que verifique accesibilidad a /jmx-console/ o /console/?"
- "¿Querés que enumere deployments y aplicaciones desplegadas?"
- "Se detectó JMX console accesible. ¿Procedo con enumeración de MBeans?"
- "¿Verifico versión exacta via /console/plugins/ para matching con CVE?"

## Pasos de Ejecución

### Fase 1 — Fingerprinting pasivo

```bash
# 1. Headers JBoss
curl -sI "https://target.com:8080/" | grep -iE "x-powered-by|server|jboss|wildfly"

# 2. Página por defecto
curl -s "https://target.com:8080/" | grep -iE "jboss|wildfly|red hat|welcome"
```

### Fase 2 — Consolas de administración

```bash
# 3. JMX Console (JBoss 4-6)
curl -sI "https://target.com:8080/jmx-console/"
curl -s "https://target.com:8080/jmx-console/" | head -50

# 4. Admin Console (JBoss 5-7)
curl -sI "https://target.com:8080/admin-console/"
curl -sI "https://target.com:8080/console/"

# 5. Web Console (WildFly 8+)
curl -sI "https://target.com:9990/console/"
curl -sI "https://target.com:9990/management/"
curl -sI "https://target.com:8080/web-console/"
```

### Fase 3 — Deployments y aplicaciones

```bash
# 6. Enumerar deployments via status
curl -sI "https://target.com:8080/jmx-console/HtmlAdaptor"
curl -sI "https://target.com:8080/invoker/"

# 7. Aplicaciones deployadas
curl -s "https://target.com:8080/status" 2>/dev/null
for path in jmx-console web-console admin-console invoker status \
  webapps manager docs test; do
  echo "$(curl -s -o /dev/null -w "%{http_code}" "https://target.com:8080/$path") - /$path"
done
```

### Fase 4 — Detección de versión

```bash
# 8. Version via /console/plugins/
curl -sI "https://target.com:8080/console/plugins/" | \
  grep -iE "jboss|wildfly|version"

# 9. Version via /error o pages XML
curl -s "https://target.com:8080/jmx-console/HtmlAdaptor?action=displayMBeans" | \
  head -20

# 10. JNDI tree
curl -sI "https://target.com:8080/jndi/"
```

## Contrato de Salida

```json
{
  "skill": "jboss-recon",
  "target": "ejemplo.com",
  "jboss_detected": true,
  "version": "JBoss AS 7.1.3.Final",
  "cpes": ["cpe:/a:redhat:jboss_application_server:7.1.3"],
  "endpoints": {
    "console": {"port": 8080, "path": "/console/", "code": 200, "accessible": true},
    "jmx_console": {"port": 8080, "path": "/jmx-console/", "code": 200, "accessible": true, "auth_required": false},
    "admin_console": {"port": 9990, "path": "/management/", "code": 401, "accessible": true, "auth_required": true},
    "web_console": {"port": 8080, "path": "/web-console/", "code": 403, "accessible": false}
  },
  "applications": [
    "admin-console.war",
    "jmx-console.war",
    "ROOT.war"
  ],
  "findings": [
    {
      "title": "JMX Console accesible sin autenticación",
      "severity": "crítico",
      "evidence": "GET /jmx-console/ → 200 OK. Permite navegar y ejecutar MBeans sin login",
      "cwe": "CWE-306",
      "mitre": "T1190",
      "next_steps": ["Ejecutar MBeans para RCE via jboss.system:service=MainDeployer"]
    }
  ]
}
```
