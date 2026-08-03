---
name: jira-confluence
description: Jira and Confluence instance enumeration
version: 1.0.0
phase: enum
category: web
tags: [jira, confluence, atlassian, projects]
tools: [curl]
difficulty: basic
opsec_level: low
time_estimate: 60s
severity_if_found: medium
related_skills:
  - gitlab-enumeration
  - api-discovery
mitre_attack:
  - T1592.002
  - T1593
---

## When to Use

Use this skill to enumerate Jira and Confluence instances, extract project info,
identify users, and find exposed sensitive pages or issues.

## Prerequisites

- curl
- jq (for JSON parsing)

## Procedure

```bash
# Step 1: Detect Jira/Confluence version
curl -sk https://TARGET/rest/api/2/serverInfo
curl -sk https://TARGET/wiki/rest/api/content | jq '.results[0].type'

# Step 2: Jira — list projects
curl -sk https://TARGET/rest/api/2/project | jq '.[].key'
curl -sk "https://TARGET/rest/api/2/project?expand=lead" | jq '.[].name'

# Step 3: Jira — enumerate issues
curl -sk "https://TARGET/rest/api/2/search?jql=project=KEY&maxResults=5" | jq '.issues[].fields.summary'

# Step 4: Jira — user enumeration
curl -sk https://TARGET/rest/api/2/user/search?username=a | jq '.[].displayName'
curl -sk "https://TARGET/rest/api/2/user?username=admin" | jq '{displayName, email, active}'

# Step 5: Jira — check for open permissions
curl -sk "https://TARGET/rest/api/2/issue/KEY-1" | jq '.fields.summary'

# Step 6: Confluence — list spaces
curl -sk https://TARGET/wiki/rest/api/space | jq '.results[].name'

# Step 7: Confluence — list pages in space
curl -sk "https://TARGET/wiki/rest/api/content?spaceKey=SPACE&expand=body.storage" | jq '.results[].title'

# Step 8: Confluence — search for sensitive content
curl -sk "https://TARGET/wiki/rest/api/content?title=password" | jq '.results[].title'
curl -sk "https://TARGET/wiki/rest/api/content?title=credentials" | jq '.results[].title'
```

## OPSEC Rules

- Do NOT create or modify issues/pages
- Do NOT attempt to brute-force authentication
- Limit API calls to 5 per second
- Do not extract large volumes of data
- Log all requests for audit trail

## Verification

- Confirm REST API returns valid JSON
- Verify project/space listings are real
- Check if unauthenticated access is possible

## Pitfalls

- Jira Cloud vs Server have different API endpoints
- Some endpoints require authentication even for public projects
- Confluence content API may be deprecated in newer versions
- Rate limiting may block rapid enumeration

## Output Format

```
[JIRA]    Version: 8.20.10 — 12 projects found
[JIRA]    Projects: SEC, DEV, OPS, INFRA
[JIRA]    Users: admin, dev1, devops-bot
[CONF]    Spaces: Engineering, HR, Internal
[CONF]    Page: "Production Passwords" in Engineering space
[MEDIUM]  Sensitive page accessible without authentication
```
