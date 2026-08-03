---
name: wordpress-mass-recon
description: Mass WordPress reconnaissance with wpscan enumeration
version: 1.0.0
phase: recon
category: fingerprinting
tags: [wordpress, wpscan, cms, enumeration]
tools: [wpscan, curl, httpx]
difficulty: intermediate
opsec_level: low
time_estimate: 5m
severity_if_found: medium
related_skills:
  - cms-fingerprint-deep
  - xmlrpc-deep
mitre_attack:
  - T1592
  - T1595
---

## When to Use

- Target identified as WordPress during initial fingerprinting
- Need comprehensive plugin/theme/user enumeration
- Hunting for outdated components with known CVEs
- Config backup or debug log exposure

## Prerequisites

- wpscan installed (`apt install wpscan` or `gem install wpscan`)
- Network access to target on port 80/443
- API token from wpvulndb.org (optional, for vulnerability data)

## Procedure

### 1. Basic WordPress Detection

```bash
curl -sI "https://TARGET/" | grep -i "x-powered-by\|link.*wp-json\|set-cookie.*wordpress"
curl -s "https://TARGET/xmlrpc.php" | head -20
```

### 2. Full Enumeration Scan

```bash
wpscan --url "https://TARGET" \
  --enumerate ap,at,u,cb,dbe \
  --random-user-agent \
  --disable-tls-checks \
  --format cli-no-color 2>&1 | tee wordpress_recon.txt
```

Enum flags:
- `ap` — All plugins
- `at` — All themes
- `u` — Users
- `cb` — Config backups
- `dbe` — DB exports

### 3. Passive User Enumeration Fallback

```bash
# Author archive enumeration
for i in $(seq 1 20); do
  STATUS=$(curl -sI "https://TARGET/?author=$i" -o /dev/null -w "%{http_code}")
  [ "$STATUS" != "404" ] && echo "User $i exists (HTTP $STATUS)"
done
```

### 4. Plugin/Theme Version Extraction

```bash
curl -s "https://TARGET/" | grep -oP 'ver=[0-9.]+' | sort -u
curl -s "https://TARGET/wp-content/plugins/" | head -50
```

### 5. Config Backup Hunting

```bash
for f in wp-config.php.bak wp-config.php.old wp-config.php~ wp-config.php.save .wp-config.php.swp; do
  CODE=$(curl -sI "https://TARGET/$f" -o /dev/null -w "%{http_code}")
  [ "$CODE" = "200" ] && echo "BACKUP FOUND: $f"
done
```

## OPSEC Rules

- Rate-limit requests to < 10/second to avoid WAF triggers
- Use `--random-user-agent` to rotate UA strings
- Do NOT run active plugins brute-force against production without authorization
- Log all requests for audit trail

## Verification

```bash
# Confirm scan completed
grep -c "Interesting Finding" wordpress_recon.txt
# Check for API rate limiting (429 responses)
grep -c "429" wordpress_recon.txt
```

## Pitfalls

- `--enumerate ap` without API token limits vulnerability data
- Large sites may take 10+ minutes for full plugin enumeration
- Some WAFs block wpscan UA even with random UA rotation
- Config backups may return 200 but with empty body — verify content

## Output Format

```json
{
  "target": "https://TARGET",
  "wordpress_version": "6.x",
  "plugins": [{"name": "plugin-name", "version": "1.0", "vulns": []}],
  "themes": [{"name": "theme-name", "version": "2.0"}],
  "users": [{"id": 1, "name": "admin"}],
  "config_backups": ["wp-config.php.bak"],
  "severity": "medium|high"
}
```
