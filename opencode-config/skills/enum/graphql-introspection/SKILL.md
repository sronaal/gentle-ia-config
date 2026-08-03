---
name: graphql-introspection
description: GraphQL introspection and schema enumeration
version: 1.0.0
phase: enum
category: web
tags: [graphql, introspection, api]
tools: [curl, graphqlmap]
difficulty: intermediate
opsec_level: medium
time_estimate: 60s
severity_if_found: medium
related_skills:
  - api-discovery
  - dir-busting
mitre_attack:
  - T1592.002
  - T1046
---

## When to Use

Use this skill when you find a GraphQL endpoint and want to extract the full
schema including hidden types, queries, mutations, and subscriptions.

## Prerequisites

- curl
- jq (for JSON parsing)
- graphqlmap (optional, for automated enumeration)

## Procedure

```bash
# Step 1: Discover GraphQL endpoint
curl -sk https://TARGET/graphql
curl -sk https://TARGET/graphql -H "Content-Type: application/json" -d '{"query":"{ __typename }"}'

# Step 2: Full introspection query
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind description fields { name type { name kind ofType { name } } args { name type { name } } } } }"}' \
  | jq . > graphql_schema.json

# Step 3: List all types
cat graphql_schema.json | jq '.data.__schema.types[] | select(.name | startswith("__") | not) | .name'

# Step 4: Extract queries and mutations
cat graphql_schema.json | jq '.data.__schema.types[] | select(.kind == "OBJECT") | {name: .name, fields: [.fields[].name]}'

# Step 5: Test mutations (if found)
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"Mutation\") { fields { name args { name type { name } } } } }"}' \
  | jq '.data.__type.fields[]'

# Step 6: graphqlmap automated scan
graphqlmap -u https://TARGET/graphql --method POST -v
```

## OPSEC Rules

- Limit introspection queries to 1 per endpoint
- Do not trigger mutations without authorization
- Cache schema locally to avoid repeated requests
- Log all queries for audit trail

## Verification

- Confirm introspection returns a valid schema (not `null`)
- Check if query and mutation types are both present
- Verify discovered fields respond to legitimate queries

## Pitfalls

- Introspection may be disabled in production
- Schema may require authentication headers
- Rate limiting may block rapid queries
- Some schemas use persisted queries (no full introspection)

## Output Format

```
[GRAPHQL] Endpoint: /graphql — introspection enabled
[QUERY]   User, Project, Report, AuditLog
[MUTATION] createUser, deleteProject, updateReport
[HIDDEN]  AuditLog — contains user activity trails
```
