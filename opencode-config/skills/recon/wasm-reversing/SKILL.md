---
name: wasm-reversing
description: Reversing de módulos WebAssembly — extracción, descompilación, análisis de strings, identificación de secretos hardcodeados y lógica ofuscada en binarios .wasm
phase: recon
---

# WebAssembly Reversing

## Activation Contract

**Trigger**: La aplicación carga módulos `.wasm` para lógica del lado del cliente (juegos, procesamiento de video, crypto, validación, DRM). Se sospecha que contienen secretos, lógica sensible o algoritmos propietarios.

**Input requerido**:
- URL de la página que carga el WASM
- Nombre del archivo .wasm (si se conoce)
- Herramientas: wasm-decompile, wasm2wat, wasm-objdump, Chrome DevTools, wabt

## Hard Rules

1. NO redistribuir binarios .wasm extraídos sin permiso del propietario
2. NO usar secretos encontrados en WASM para acceder a sistemas sin autorización
3. Documentar TODO hallazgo de secreto como finding de severidad alta
4. No modificar binarios .wasm para bypassear lógica client-side (es recontra ilegal sin autorización explícita)
5. No asumir que WASM ofuscado es seguro — siempre descompilar y revisar

## Decision Gates

| Disparador | Pregunta |
|-----------|----------|
| Encontrar API key / token en WASM | "Encontré una API key hardcodeada en el binario WASM. ¿Verificamos contra el endpoint?" |
| Descompilar WASM que contiene lógica de crypto/DRM | "El WASM contiene lógica criptográfica o DRM. ¿Procedemos con el análisis completo?" |
| Extraer algoritmo propietario | "El WASM implementa un algoritmo propietario. ¿Documentamos el hallazgo?" |

## Execution Steps

### Fase 1: Extracción del Binario WASM

```bash
# Desde Chrome DevTools: Network → filtrar por .wasm → guardar archivo
# O desde la línea de comandos:

# Extraer URL del WASM desde el HTML/JS
curl -s https://target.com/app.js | grep -oP '\.wasm["'"'"']?[^"'"'"']*\.wasm' | sort -u

# Descargar el binario
curl -s -o module.wasm https://target.com/module.wasm

# También puede estar en base64 inline en el JS
curl -s https://target.com/app.js | grep -oP 'data:application/wasm;base64,([A-Za-z0-9+/=]+)' | head -1 | cut -d, -f2 | base64 -d > module.wasm

# Verificar que es WASM válido
file module.wasm
# → WebAssembly (wasm) binary module version 0x1 (MVP)
```

### Fase 2: Descompilación y Análisis Estructural

```bash
# wasm2wat: convertir a formato textual WAT (legible)
# wasm2wat es parte de wabt (WebAssembly Binary Toolkit)
wasm2wat module.wasm -o module.wat

# wasm-decompile: descompilar a pseudocódigo C-like (más legible)
wasm-decompile module.wasm -o module.dcmp

# Ver estadísticas del módulo
wasm-objdump -h module.wasm
# → Types, Imports, Functions, Tables, Memories, Globals, Exports

# Listar secciones
wasm-objdump -s module.wasm | head -40
```

### Fase 3: Extracción de Strings

```bash
# Strings del binario WASM (no UTF-8 nativo, pero puede tener datasegments)
wasm-objdump -x module.wasm | grep -i 'data\|string\|secret\|key\|token\|password\|api_key\|endpoint\|http'

# Extraer todos los data segments como strings legibles
wasm2wat module.wasm | grep -oP '"([^"\\]|\\.)*"' | sort -u | head -100

# Buscar específicamente patrones de secretos
wasm2wat module.wasm | grep -iE '(api.?key|secret|token|password|eyJ[A-Za-z0-9_-]+\.)' | head -20
```

### Fase 4: Análisis de Funciones Exportadas e Importadas

```bash
# Listar funciones exportadas (las que llama JS)
wasm-objdump -x module.wasm | grep -A1 "Export"

# Listar funciones importadas (las que WASM llama de JS)
wasm-objdump -x module.wasm | grep -A1 "Import"

# Ver detalle de funciones por tipo
wasm-objdump -x module.wasm | grep "Type\[" | head -20
```

### Fase 5: Análisis de Lógica Ofuscada

```bash
# Si el WASM está ofuscado (nombres de función genéricos como f1, f2, f3...)
# Buscar constantes numéricas sospechosas (offsets, longitudes, keys)
wasm2wat module.wasm | grep -oP 'i32\.const \K\d+' | sort -un | head -30

# Buscar operaciones de comparación de strings (validación de contraseñas, licencias)
wasm2wat module.wasm | grep -E 'i32\.(eq|ne|lt|gt)' | head -20

# Identificar bucles de validación (candidatos a lógica de auth/bypass)
wasm2wat module.wasm | grep -c "block\|loop\|if\|br_table"
```

### Fase 6: Análisis en Chrome DevTools

```javascript
// En la consola de DevTools:
// 1. Inspeccionar instancia de WebAssembly
WebAssembly.Module.exports(wasmModule);

// 2. Llamar funciones exportadas directamente
const instance = await WebAssembly.instantiateStreaming(fetch('/module.wasm'));
const result = instance.exports.validateKey("test-input");
console.log(result);

// 3. Hooking de funciones importadas (trampas)
const originalImport = instance.exports._someFunction;
instance.exports._someFunction = function(...args) {
  console.log("Called with:", args);
  return originalImport.apply(this, args);
};
```

### Fase 7: Documentación de Hallazgos

```bash
# Resumen del análisis
echo "=== WASM Analysis Report ==="
echo "Module: $(basename $module)"
echo "Exports: $(wasm-objdump -x module.wasm | grep -c 'Export')"
echo "Functions: $(wasm-objdump -x module.wasm | grep -c 'Function\[')"
echo "Strings found: $(wasm2wat module.wasm | grep -oP '"[^"]{4,}"' | wc -l)"
echo "--- Potential secrets ---"
wasm2wat module.wasm | grep -oP '"[^"]{8,}"' | grep -iE 'key|token|secret|pass|http' | sort -u
```

## Output Contract

```json
{
  "skill": "wasm-reversing",
  "target": "<wasm-source-url>",
  "module_name": "<module.wasm>",
  "module_size": 12345,
  "exports": ["function1", "function2"],
  "imports": ["env.some_import"],
  "findings": [
    {
      "title": "API key hardcodeada en módulo WASM",
      "severity": "high",
      "category": "hardcoded-secret",
      "type": "api-key|secret|token|logic-bypass|algorithm-disclosure",
      "evidence": "<string-encontrado-o-función>",
      "impact": "Acceso no autorizado a API / Bypass de lógica client-side",
      "verified": true|false,
      "poc": "wasm2wat module.wasm | grep 'api_key'"
    }
  ],
  "summary": "Resumen del análisis de reversing WASM"
}
```

> **Chains recomendadas**: wasm-reversing → hardcoded-credentials → api-bola-deep
