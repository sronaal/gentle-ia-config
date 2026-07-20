---
name: security-hardening
description: "Trigger: security review, OWASP, audit dependencies, secret scanning, security headers, CSP, input sanitization. Scan code for OWASP Top 10, dependency vulnerabilities, secrets exposure, and missing security controls before review or deploy."
license: Apache-2.0
metadata:
  author: gentleman-programming
  version: "1.0"
---

## Activation Contract

Load this skill when the user asks for a security review, mentions OWASP, dependency audit, secret scanning, security headers, CSP review, input sanitization, authentication audit, or before merging any PR that touches auth, payments, PII, user input, or deploy configuration.

## Hard Rules

- Never log, display, or commit secrets, tokens, keys, or credentials — even in comments or examples.
- For every identified finding, report: file, line, severity (CRITICAL / HIGH / MEDIUM / LOW), and a concrete remediation.
- Do not suggest rolling your own crypto. Use standard library or well-audited packages.
- Input validation must happen server-side; client-side is defense-in-depth only.
- Authentication and authorization must be enforced on every protected endpoint, not only on the frontend.
- Default-deny: fail closed, not open.

## Decision Gates

| Area | What to check |
|---|---|
| Dependencies | `npm audit`, `pip-audit`, `cargo audit`, `govulncheck`, `trivy fs .` |
| Secrets | Hardcoded keys, tokens, `.env` in repo, credentials in config, `git-secrets`, `trufflehog` |
| Auth | JWT validation, session expiry, password hashing (bcrypt/argon2), MFA, rate limiting on login |
| Input | SQL injection, XSS, command injection, path traversal, SSRF — parameterized queries, DOMPurify, allowlists |
| Headers | `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`, `X-Frame-Options`, `Referrer-Policy` |
| Deploy | Non-root user, no debug endpoints, read-only filesystem where possible, health-check auth |

## Execution Steps

1. Identify the project's language and dependency manager. Run the matching audit command.
2. Scan for hardcoded secrets: grep for `api_key`, `secret`, `password`, `token`, `-----BEGIN` in non-test code. Run `trufflehog` or `git-secrets` if available.
3. Review auth middleware: every protected route checks auth, tokens expire, passwords are not stored in plaintext.
4. Review input handling: all user input is validated, parameterized, or sanitized at the server boundary.
5. Check HTTP response headers on API routes and HTML responses.
6. Review deploy config: Dockerfile runs as non-root, no exposed debug ports, `.env` is in `.gitignore`.
7. Report findings grouped by severity. For CRITICAL and HIGH findings, provide a code-level fix.

## Output Contract

Return a structured security report with sections: Dependency Audit, Secrets Scan, Auth Review, Input Handling, Headers & Config. Each finding includes file:line, severity, description, and remediation. Append "No issues found" per section when clean.

## References

- OWASP Top 10: <https://owasp.org/www-project-top-ten/>
