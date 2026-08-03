---
name: source-leaks
description: Detect exposed source code, git repositories, and environment files
version: 1.0.0
phase: recon
category: disclosure
tags: [source-code, git, env, disclosure]
tools: [curl, git]
difficulty: basic
opsec_level: low
time_estimate: 10s
severity_if_found: critical
related_skills:
  - js-secrets
  - google-dorks
mitre_attack:
  - T1592.002
  - T1552.001
---

## When to Use

Use this skill to check for accidentally exposed .git directories, .env files,
and other source code disclosures. These are critical findings.

## Prerequisites

- curl
- git (optional, for cloning exposed repos)

## Procedure

```bash
# Test .git exposure
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/.git/HEAD"
curl -sk "https://TARGET/.git/HEAD" 2>/dev/null | head -5

# Test .env exposure
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/.env"
curl -sk "https://TARGET/.env" 2>/dev/null | head -20

# Test common sensitive files
for path in ".git/config" ".git/config" ".svn/entries" ".env.local" ".env.production" ".DS_Store" "wp-config.php.bak" "config.php.bak" "web.config" "crossdomain.xml"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$path")
  echo "$code $path"
done
```

## OPSEC Rules

- Do not clone full git repositories without authorization
- Limit requests to known sensitive paths
- Do not download large files
- Record HTTP status codes, not full content for large responses

## Verification

- A 200 response with "ref:" content confirms .git exposure
- Verify .env contains real credentials, not placeholders
- Check if backup files are current (not from years ago)

## Pitfalls

- .git exposure may be partial (missing objects)
- .env files may be empty or contain only comments
- Some servers return 200 for all paths (false positives)
- Backup files may be too large to download safely

## Output Format

```
[CRITICAL] .git/HEAD exposed: ref: refs/heads/main
[CRITICAL] .env exposed: DATABASE_URL=postgresql://...
[INFO] .DS_Store exposed (size: 6KB)
```
