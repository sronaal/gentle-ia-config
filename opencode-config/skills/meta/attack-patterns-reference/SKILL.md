---
name: attack-patterns-reference
description: Catalog of 25 attack patterns, 18 WP abuse, 8 CORS variants
version: 1.0.0
phase: meta
category: methodology
tags: [patterns, attack, catalog, wordpress, cors]
tools: []
difficulty: basic
opsec_level: low
time_estimate: 30s
severity_if_found: info
related_skills:
  - hunt-xss
  - hunt-sqli
  - hunt-idor
  - cors-variants-deep
mitre_attack:
  - T1190
  - T1133
---

## When to Use

Use this skill as a reference catalog when classifying findings, selecting
attack patterns, or building attack trees.

## Prerequisites

- Findings from recon or enumeration phases
- No tools required — reference catalog only

## Procedure

### General Attack Patterns (P-01 to P-25)

```bash
# P-01: Credential Stuffing — POST /login with breach credentials
# P-02: IDOR — Change ID: /api/users/123 → /api/users/124
# P-03: SQL Injection — Add ' to parameters, error/blind
# P-04: XSS Reflected — Inject <script>alert(1)</script> in URL params
# P-05: XSS Stored — Inject payload in forms, profiles, comments
# P-06: SSRF — Supply internal URLs (http://169.254.169.254)
# P-07: XXE — Upload XML with external entity declarations
# P-08: Path Traversal — ../../etc/passwd in file parameters
# P-09: Command Injection — ; whoami or | id in inputs
# P-10: Auth Bypass — Remove/modify auth headers, tokens
# P-11: BFLA — Access admin endpoints as regular user
# P-12: Mass Assignment — Add admin=true to registration request
# P-13: Open Redirect — //evil.com in redirect parameters
# P-14: CSRF — Submit state-changing request without token
# P-15: File Upload — Upload .php, .html, .svg with JS
# P-16: Insecure Deserialization — Modify serialized cookies
# P-17: Race Condition — Concurrent requests for limited resources
# P-18: Info Disclosure — Error messages, stack traces, debug
# P-19: Clickjacking — X-Frame-Options header missing
# P-20: CORS Misconfig — Origin reflection, null origin
# P-21: GraphQL Introspection — { __schema { types { name } } }
# P-22: API Versioning Leak — /api/v1 → /api/v2, /api/internal
# P-23: JWT Weakness — none algorithm, weak secret
# P-24: Subdomain Takeover — CNAME to unclaimed service
# P-25: Supply Chain — Compromised npm/pip packages
```

### WordPress Abuse Patterns (WP-01 to WP-18)

```bash
# WP-01: Username Enum — /wp-json/wp/v2/users, /?author=1
# WP-02: XMLRPC Brute Force — system.multicall wp.getUsersBlogs
# WP-03: Plugin Enum — /wp-content/plugins/PLUGIN/readme.txt
# WP-04: Theme Enum — /wp-content/themes/THEME/style.css
# WP-05: Debug Log — /wp-content/debug.log
# WP-06: Backup Files — /wp-config.php.bak, /database.sql
# WP-07: REST API Leak — /wp-json/wp/v2/posts, /wp-json/wp/v2/pages
# WP-08: XMLRPC DDoS — system.multicall pingback.ping
# WP-09: SQL Injection Search — /?s=' UNION SELECT
# WP-10: File Manager Plugin — /wp-content/plugins/wp-file-manager/
# WP-11: Default Install — /wp-admin/install.php, /readme.html
# WP-12: Hardcoded Creds — Search plugin source for passwords
# WP-13: Role Escalation — Modify role in profile update
# WP-14: Password Reset Poisoning — Manipulate Host header
# WP-15: Subscriber Content Injection — Post as subscriber
# WP-16: Media Library — /wp-content/uploads/ directory listing
# WP-17: Cron Abuse — /wp-cron.php event manipulation
# WP-18: Database Dump — /wp-content/db.php, phpmyadmin
```

### CORS Variants (V1-V8)

```bash
# V1: Origin Reflection — evil.com reflected in ACAO header
# V2: Null Origin — null origin trusted (sandboxed iframe)
# V3: Wildcard + Credentials — * with credentials (browser blocks)
# V4: Subdomain Trust — evil.TARGET.com trusted
# V5: Prefix Matching — evilTARGET.com trusted (string match)
# V6: Regex Bypass — TARGET.com.evil.com trusted
# V7: HTTP Downgrade — HTTP origin accepted on HTTPS site
# V8: PostMessage Origin — window.postMessage arbitrary origin
```

## OPSEC Rules

- Reference catalog only — no active testing
- When using patterns for testing, follow the specific skill's OPSEC rules
- Do not test without authorization
- Document which patterns were tested and results

## Verification

- Cross-reference findings with appropriate pattern ID
- Ensure each finding maps to at least one pattern
- Validate pattern applicability to target technology stack

## Pitfalls

- Not all patterns apply to all targets (WP patterns need WordPress)
- Some patterns require authentication to test
- CORS variants need specific browser environment for full impact
- Pattern catalog is not exhaustive — new patterns emerge constantly

## Output Format

```
[PATTERN] P-02 IDOR found in /api/users/{id}
[PATTERN] WP-01 Username enumeration via /wp-json/wp/v2/users
[PATTERN] V1 CORS origin reflection on TARGET.com
```
