---
name: db-postgresql-enum
description: PostgreSQL database enumeration for version, schemas, roles, and trust auth
version: 1.0.0
phase: enum
category: database
tags: [database, postgresql, sql]
tools: [nmap, psql, sqlmap]
difficulty: basic
opsec_level: medium
time_estimate: 60s
severity_if_found: high
related_skills:
  - db-mysql-enum
  - ldap-enumeration
mitre_attack:
  - T1213
  - T1046
---

## When to Use

Use this skill when port 5432 (PostgreSQL) is open and you want to enumerate
databases, schemas, roles, and identify trust authentication weaknesses.

## Prerequisites

- nmap (for service detection)
- psql (PostgreSQL client)
- sqlmap (optional, for SQL injection)

## Procedure

```bash
# Step 1: Service detection
nmap -sV -p 5432 TARGET --script pgsql-brute

# Step 2: Anonymous / trust auth login
psql -h TARGET -U postgres -c "SELECT version();" 2>/dev/null
psql -h TARGET -U '' -c "SELECT current_database();" 2>/dev/null
PGPASSWORD=postgres psql -h TARGET -U postgres -c "SELECT 1;" 2>/dev/null

# Step 3: Enumerate databases
psql -h TARGET -U postgres -l 2>/dev/null

# Step 4: Enumerate schemas and tables
psql -h TARGET -U postgres -d postgres -c "\dn" 2>/dev/null
psql -h TARGET -U postgres -d postgres -c "\dt" 2>/dev/null

# Step 5: Enumerate roles and privileges
psql -h TARGET -U postgres -c "\du" 2>/dev/null
psql -h TARGET -U postgres -c "SELECT rolname, rolsuper, rolcreaterole, rolcanlogin FROM pg_roles;" 2>/dev/null

# Step 6: Check pg_hba trust entries
psql -h TARGET -U postgres -c "SHOW password_encryption;" 2>/dev/null
psql -h TARGET -U postgres -c "SELECT * FROM pg_hba_file_rules;" 2>/dev/null
```

## OPSEC Rules

- Do NOT modify any schemas, tables, or roles
- Do NOT create new databases or users
- Limit enumeration to system catalogs (pg_catalog, information_schema)
- Log all queries for audit trail

## Verification

- Confirm PostgreSQL version and running port
- Verify trust/auth bypass succeeded
- Check if superuser role is accessible

## Pitfalls

- PostgreSQL may use TLS (port 5432 with sslmode=require)
- pg_hba may restrict access by IP range
- Some deployments use SCRAM-SHA-256 requiring password
- Default `postgres` user may not exist in all installations

## Output Format

```
[PG]      Host: TARGET:5432 — version: 15.3
[PG]      Login: postgres@ (trust auth)
[PG]      Databases: postgres, template0, template1, app_db
[PG]      Schemas: public, app, audit
[PG]      Roles: postgres (superuser), app_user, read_only
[SECRET]  password_encryption: md5 — legacy, susceptible to cracking
[CRITICAL] Trust authentication — superuser access without password
```
