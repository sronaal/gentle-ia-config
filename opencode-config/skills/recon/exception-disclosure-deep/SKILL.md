---
name: exception-disclosure-deep
description: "Trigger: OWASP A10, mishandling exceptions, error disclosure, stack trace, debug info, verbose error. Detect and exploit exception handling weaknesses for information disclosure."
license: Apache-2.0
metadata:
  author: "pentest-orchestrator"
  version: "1.0"
---

## Activation Contract

Load when testing for OWASP A10 (Mishandling of Exceptional Conditions), verbose error messages, stack trace disclosure, debug endpoint exposure, or error-based information leakage.

## Hard Rules

- Never trigger denial-of-service — limit error-inducing inputs to 5 per endpoint.
- Document full stack traces as they often contain internal paths, versions, and secrets.
- Do NOT cause 500 errors on production payment or data-writing flows.

## Decision Gates

| Error Source | Trigger Method | What to Extract |
|-------------|----------------|-----------------|
| Stack traces | Invalid input types, long strings, encoding mismatch | Internal paths, framework versions, DB queries |
| Debug endpoints | /.env, /__debug__, /debug, /status, /actuator | Env vars, config, heap dumps |
| DB errors | SQL injection probes, invalid JSON, SQL syntax errors | Table names, column names, DB version, connection strings |
| Framework errors | Invalid routes, wrong methods, malformed headers | Framework name, version, middleware stack |
| JSON/XML parse | Malformed payloads, duplicate keys, type mismatches | Parser info, schema hints, internal struct names |
| Custom error pages | 404/500 page analysis (path differences) | Framework, language, auth state |
| GraphQL errors | Invalid queries, field typos, depth violations | Schema info, type system, resolver paths |

## Execution Steps

1. **Send invalid input types**: Submit string where number expected, array where string expected → capture full response body
2. **Trigger DB errors**: Input `' OR 1=1 --`, malformed JSON, Unicode exploits in search fields → extract SQL/NoSQL error details
3. **Probe debug endpoints**: GET `/.env`, `/debug`, `/__debug__`, `/actuator`, `/health`, `/status`, `/info`, `/heapdump`, `/threads`, `/stacktrace`
4. **Method mismatch**: Send POST to GET-only endpoints, PUT to read-only → observe 405/500 error details
5. **Malformed headers**: Inject newlines, null bytes, long values in headers → capture parsing errors
6. **GraphQL introspection error**: Query `{ __schema { types { name } } }` on error response → compare error details between valid and invalid
7. **Error page analysis**: Request `/nonexistent-12345`, `/nonexistent-67890` → compare 404 pages for dynamic content
8. **Encrypted/encoded error parsing**: Some apps encode errors in base64/JSON within responses — decode and analyze
9. **Rate limit errors**: Test if error messages reveal internal state (e.g., "too many requests for user_id=123")

## Output Contract

Return findings:
- **type**: stack_trace_disclosure | debug_endpoint_exposed | db_error_disclosure | framework_info_leak | error_page_leak | graphql_error_leak
- **endpoint**: URL + method + trigger payload
- **extracted_info**: Internal paths, versions, table names, env vars, connection strings
- **severity**: Critical (secrets in error) / High (internal paths+versions) / Medium (framework info) / Low (minor leaks)
- **evidence**: Captured error response snippet (first 500 chars)
