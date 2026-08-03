---
name: gitlab-enumeration
description: GitLab instance enumeration and version detection
version: 1.0.0
phase: enum
category: web
tags: [gitlab, git, code, api]
tools: [curl]
difficulty: basic
opsec_level: low
time_estimate: 60s
severity_if_found: medium
related_skills:
  - github-dorking
  - api-discovery
mitre_attack:
  - T1592.002
  - T1593
---

## When to Use

Use this skill to enumerate a self-hosted GitLab instance, extract version info,
list public projects, and identify potential attack surface.

## Prerequisites

- curl
- jq (for JSON parsing)

## Procedure

```bash
# Step 1: Version detection
curl -sk https://TARGET/ | grep -i "gitlab" | head -5
curl -sk https://TARGET/api/v4/version

# Step 2: List public projects
curl -sk https://TARGET/api/v4/projects?visibility=public | jq '.[].path_with_namespace'

# Step 3: List all accessible projects
curl -sk -H "PRIVATE-TOKEN: TOKEN" https://TARGET/api/v4/projects | jq '.[].path_with_namespace'

# Step 4: Enumerate users
curl -sk https://TARGET/api/v4/users | jq '.[].username'

# Step 5: Check user details
curl -sk https://TARGET/api/v4/users/1 | jq '{name, username, email, admin, state}'

# Step 6: List groups
curl -sk https://TARGET/api/v4/groups | jq '.[].full_path'

# Step 7: Check for exposed snippets
curl -sk https://TARGET/api/v4/snippets | jq '.[].title'

# Step 8: Enumerate repositories in a project
PROJECT_ID=1
curl -sk https://TARGET/api/v4/projects/$PROJECT_ID/repository/tree | jq '.[].name'

# Step 9: Check for deploy keys and webhooks
curl -sk -H "PRIVATE-TOKEN: TOKEN" https://TARGET/api/v4/projects/$PROJECT_ID/deploy_keys | jq '.[].title'
curl -sk -H "PRIVATE-TOKEN: TOKEN" https://TARGET/api/v4/projects/$PROJECT_ID/hooks | jq '.[].url'
```

## OPSEC Rules

- Do NOT clone all repos (creates massive traffic)
- Limit API calls to 5 per second
- Do NOT attempt to create users or modify projects
- Respect rate limits: check `X-RateLimit-Remaining` header
- Log all API calls for audit trail

## Verification

- Confirm `/api/v4/version` returns valid version
- Verify user listing returns real usernames
- Check if private projects are accessible without token

## Pitfalls

- GitLab CE vs EE have different API capabilities
- Some endpoints require admin access
- Rate limiting is strict on unauthenticated requests
- Version detection may be blocked by CDN/proxy

## Output Format

```
[GL]      GitLab 16.2.1 — /api/v4/version accessible
[GL]      Users: admin, developer1, devops-bot
[GL]      Projects: company/app, company/infra, company/docs
[GL]      Groups: engineering, devops, security
[SECRET]  Deploy key found in project 1 — ssh-rsa AAAA...
```
