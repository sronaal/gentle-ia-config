---
name: db-mongodb-enum
description: MongoDB database enumeration for open ports, databases, collections, and anonymous access
version: 1.0.0
phase: enum
category: database
tags: [database, mongodb, nosql]
tools: [nmap, mongosh, mongo]
difficulty: basic
opsec_level: medium
time_estimate: 60s
severity_if_found: high
related_skills:
  - db-redis-enum
  - elasticsearch-opensearch
mitre_attack:
  - T1213
  - T1046
---

## When to Use

Use this skill when port 27017 (MongoDB) is open and you want to enumerate
databases, collections, and users. Tests for anonymous access and weak auth.

## Prerequisites

- nmap (for service detection)
- mongosh (MongoDB Shell)
- mongo (legacy client, fallback)

## Procedure

```bash
# Step 1: Service detection
nmap -sV -p 27017 TARGET --script mongodb-info

# Step 2: Anonymous access test
mongosh "mongodb://TARGET:27017" --eval "db.version()" 2>/dev/null
mongosh "mongodb://TARGET:27017/test" --eval "db.getUser('')" 2>/dev/null

# Step 3: List databases
mongosh "mongodb://TARGET:27017" --eval "db.adminCommand('listDatabases')" 2>/dev/null

# Step 4: List collections in each database
mongosh "mongodb://TARGET:27017/admin" --eval "db.getCollectionNames()" 2>/dev/null

# Step 5: Enumerate users
mongosh "mongodb://TARGET:27017/admin" --eval "db.getUsers()" 2>/dev/null

# Step 6: Check admin database
mongosh "mongodb://TARGET:27017/admin" --eval "db.system.users.find().pretty()" 2>/dev/null

# Step 7: Sample documents from interesting collections
mongosh "mongodb://TARGET:27017" --eval "use admin; db.system.users.find().limit(3).pretty()" 2>/dev/null

# Step 8: nmap NSE MongoDB scripts
nmap -sV -p 27017 TARGET --script mongodb-databases,mongodb-users
```

## OPSEC Rules

- Do NOT create, drop, or modify any databases or collections
- Do NOT insert, update, or delete documents
- Limit sampling to 3-5 documents per collection
- Do NOT run aggregation pipelines (resource-intensive)

## Verification

- Confirm MongoDB version and open port
- Verify anonymous access is available
- Check which databases and collections contain user data

## Pitfalls

- MongoDB 3.0+ enables auth by default in production
- Some instances use port 27018 (shard) or 27019 (config)
- mongosh is required for MongoDB 5.0+ (legacy mongo deprecated)
- Admin database may be empty if auth is disabled

## Output Format

```
[MONGO]   Host: TARGET:27017 — version: 6.0.5
[MONGO]   Access: Anonymous — no authentication required
[MONGO]   Databases: admin, config, local, app_data, logs
[MONGO]   Collections: app_data.users, app_data.sessions, admin.system.users
[MONGO]   Users: admin (root), app_service (readWrite)
[SAMPLE]  app_data.users: { email, password_hash, role, created_at }
[CRITICAL] Unauthenticated MongoDB — all databases readable
```
