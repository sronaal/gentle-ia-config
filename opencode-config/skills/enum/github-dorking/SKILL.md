---
name: github-dorking
description: GitHub code dorking for hardcoded secrets and sensitive data
version: 1.0.0
phase: enum
category: web
tags: [github, secrets, dorking, osint]
tools: [curl, gh]
difficulty: intermediate
opsec_level: low
time_estimate: 120s
severity_if_found: critical
related_skills:
  - gitlab-enumeration
  - api-discovery
mitre_attack:
  - T1552.001
  - T1593.002
---

## When to Use

Use this skill to search GitHub for hardcoded secrets, API keys, credentials,
and sensitive configuration related to your target organization.

## Prerequisites

- curl
- gh CLI (authenticated, for higher rate limits)
- jq

## Procedure

```bash
# Step 1: Search for password leaks
curl -s -H "Accept: application/vnd.github.v3+json" \
  "https://api.github.com/search/code?q=TARGET+password+extension:env" | jq '.items[] | {path, repository.full_name}'

# Step 2: Search for API keys
curl -s "https://api.github.com/search/code?q=TARGET+api_key+extension:py" | jq '.items[].path'
curl -s "https://api.github.com/search/code?q=TARGET+api_secret+extension:yml" | jq '.items[].path'

# Step 3: Search for AWS credentials
curl -s "https://api.github.com/search/code?q=TARGET+AKIA+extension:cfg" | jq '.items[].path'
curl -s "https://api.github.com/search/code?q=TARGET+aws_secret_access_key" | jq '.items[].path'

# Step 4: Search for private keys
curl -s "https://api.github.com/search/code?q=TARGET+BEGIN+RSA+PRIVATE+KEY" | jq '.items[].path'
curl -s "https://api.github.com/search/code?q=TARGET+BEGIN+OPENSSH+PRIVATE+KEY" | jq '.items[].path'

# Step 5: gh CLI (higher rate limits)
gh search code "TARGET password" --json path,repository -L 10
gh search code "TARGET secret" --json path,repository -L 10
gh search code "TARGET token" --json path,repository -L 10

# Step 6: Search for database connection strings
curl -s "https://api.github.com/search/code?q=TARGET+mongodb+://+extension:py" | jq '.items[].path'
curl -s "https://api.github.com/search/code?q=TARGET+postgres://+extension:env" | jq '.items[].path'

# Step 7: Search for config files
curl -s "https://api.github.com/search/code?q=TARGET+filename:.env" | jq '.items[].path'
curl -s "https://api.github.com/search/code?q=TARGET+filename:config.yml+password" | jq '.items[].path'
```

## OPSEC Rules

- Respect GitHub rate limits (60/hour unauthenticated, 5000 with token)
- Do NOT fork or clone leaked repos unless authorized
- Do NOT access private repos without permission
- Document all found secrets but do NOT expose them in logs
- Report findings to the client immediately

## Verification

- Manually verify each secret is real and active
- Check if leaked repos belong to the target organization
- Validate credentials against target services only if authorized

## Pitfalls

- GitHub search has a 1000-result limit per query
- Code search may be slow for large repositories
- Some secrets are in commit history, not current files
- Rate limiting kicks in after 10 requests/minute unauthenticated

## Output Format

```
[GITHUB]  org/app — .env file contains DB_PASSWORD=***
[GITHUB]  org/api — config.yml contains aws_secret_access_key=***
[GITHUB]  user/repo — SSH private key in deploy/keys/id_rsa
[GITHUB]  org/scripts — MongoDB connection string with credentials
[CRITICAL] Active AWS credentials found in public repo
```
