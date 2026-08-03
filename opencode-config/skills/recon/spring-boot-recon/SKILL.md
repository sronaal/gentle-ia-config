---
name: spring-boot-recon
description: Reconocimiento de aplicaciones Spring Boot — actuators, versionado, endpoints expuestos y Jolokia
phase: recon
---

# spring-boot-recon — Reconocimiento de Spring Boot

## Contrato de Activación

Activás esta skill CUANDO:
- Detectás respuestas con header `X-Application-Context` o `X-Spring-Boot-Version`
- Encontrás `/actuator/` en robots.txt o en respuestas 404 amigables
- La cookie `SESSION` de Spring Boot aparece en headers de respuesta
- La página de error por defecto de Spring Boot (Whitelabel Error Page) aparece

No la activés para aplicaciones Java EE sin señales de Spring Boot.

## Reglas Firmes

1. **Actuators sensibles**: `/actuator/env`, `/actuator/heapdump`, `/actuator/logfile` requieren aprobación explícita antes de acceder
2. **No descargar heapdump** sin permiso — puede contener credenciales en texto plano
3. **Evidencia obligatoria**: cada actuator encontrado debe documentarse con código de respuesta y body parcial
4. **No ejecutar refresh** de Spring Cloud — eso es competencia de exploit

## Compuertas de Decisión

- "Se detectó Spring Boot. ¿Escanéo actuators comunes? (health, info, mappings, beans)"
- "¿Querés que intente acceder a /actuator/env o /actuator/heapdump? Puede exponer credenciales en texto plano."
- "Se detectó Jolokia en /actuator/jolokia. ¿Procedo con enumeración de beans MBean?"

## Pasos de Ejecución

### Fase 1 — Detección y fingerprinting

```bash
# 1. Headers de Spring Boot
curl -sI "https://target.com/" | grep -iE "x-application-context|x-spring-boot|x-spring"

# 2. Whitelabel Error Page
curl -s "https://target.com/" | grep -iE "Whitelabel Error Page|spring"

# 3. Versión via /error
curl -s "https://target.com/error" | grep -iE "spring|timestamp|status|error|message"

# 4. Cookie de sesión
curl -sI "https://target.com/" | grep -iE "SESSION"
```

### Fase 2 — Enumeración de actuators

```bash
# 5. Actuators comunes (seguros)
for path in health info mappings beans conditions configprops threaddump; do
  echo "=== /actuator/$path ==="
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/actuator/$path"
  echo
done

# 6. Actuators sensibles (preguntar antes)
# /actuator/env — variables de entorno
# /actuator/heapdump — dump de memoria
# /actuator/logfile — logs
# /actuator/loggers — config de logging
# /actuator/jolokia — JMX via HTTP
# /actuator/refresh — forzar recarga de config
```

### Fase 3 — Enumeración de endpoints expuestos

```bash
# 7. Swagger / OpenAPI
curl -sI "https://target.com/swagger-ui.html"
curl -sI "https://target.com/v3/api-docs"
curl -sI "https://target.com/swagger-resources"

# 8. H2 Console (base de datos)
curl -sI "https://target.com/h2-console"

# 9. Spring Boot Admin
curl -sI "https://target.com/spring-boot-admin"
```

### Fase 4 — Versión exacta

```bash
# 10. Buscar versión en /actuator/info
curl -s "https://target.com/actuator/info" | grep -iE "version|build"

# 11. Versión via header
curl -sI "https://target.com/actuator/health" | grep -iE "x-spring-boot"
```

## Contrato de Salida

```json
{
  "skill": "spring-boot-recon",
  "target": "ejemplo.com",
  "spring_boot_detected": true,
  "version": "2.7.5",
  "cpes": ["cpe:/a:vmware:spring_boot:2.7.5"],
  "actuators": {
    "health": {"code": 200, "accessible": true},
    "info": {"code": 200, "accessible": true},
    "env": {"code": 403, "accessible": false, "sensitive": true},
    "heapdump": {"code": 200, "accessible": true, "sensitive": true},
    "jolokia": {"code": 200, "accessible": true, "sensitive": true},
    "mappings": {"code": 200, "accessible": true}
  },
  "other_endpoints": [
    {"path": "/swagger-ui.html", "accessible": true},
    {"path": "/h2-console", "accessible": false}
  ],
  "findings": [
    {
      "title": "Actuator heapdump expuesto",
      "severity": "crítico",
      "evidence": "GET /actuator/heapdump → 200 OK, archivo descargable",
      "cwe": "CWE-200",
      "next_steps": ["Descargar heapdump y extraer credenciales AWS/Azure"]
    }
  ]
}
```
