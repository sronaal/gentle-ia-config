---
name: c2-infrastructure
description: C2 infrastructure deployment — redirector setup, domain rotation, C2 framework selection (Cobalt Strike, Mythic, Sliver, Havoc), infrastructure automation, and OPSEC
version: 1.0.0
phase: post
category: post-exploitation
tags: [c2, infrastructure, redirector, cobalt-strike, mythic, sliver]
tools: [terraform, ansible, docker, python3, nginx, letsencrypt]
difficulty: advanced
opsec_level: high
time_estimate: 4-8h
severity_if_found: critical
mitre_attack:
  - T1090
  - T1572
  - T1583
  - T1584
---

## When to Use

Use this skill when you need to deploy a complete C2 infrastructure for a red team engagement — from framework selection through redirector setup, domain rotation, and OPSEC hardening. Prerequisite for any operation requiring persistent beacon-based access.

Not for one-off reverse shells (use `reverse-shell` skill). Use when you need multi-session management, payload generation, and egress evasion.

## What It Does

Selects the right C2 framework for the engagement, deploys team servers with automated Terraform/Ansible, configures redirector chains (NGINX, Apache, HAProxy, Cloudflare Workers), manages domain and IP rotation, implements Malleable C2 profiles for traffic profiling, randomizes JARM/JA3 fingerprints, and sets up monitoring/failover.

## Methodology

### Phase 1: Framework Selection

| Framework | Language | Pros | Cons |
|-----------|----------|------|------|
| Cobalt Strike | Java (server), C/Beacon | Most mature, EDR bypass ecosystem, community profiles | Expensive ($3,500/yr), heavily signatured |
| Mythic | Python (server), Go/C#/Rust | Open source, multi-agent, extensible, full chain encryption | Steeper learning curve, fewer public profiles |
| Sliver | Go | Free, modern, DNS/HTTP/MTLS, armory plugins | Smaller community, fewer native EDR bypasses |
| Havoc | C++/Go | Modern UI, similar to CS, free | Newer, fewer tested OPSEC profiles |
| BruteRatel | C/C++ | Commercial, excellent EDR evasion | Very expensive, limited availability |
| PoshC2 | PowerShell/.NET | Fast setup, good for internal | PowerShell-heavy, easily detected by AMSI |
| Covenant | C#/.NET | Modern UI, good for internal | Requires .NET, fewer external profiles |

**Decision matrix:**
- **External assessment**: Cobalt Strike or Mythic (best egress profiles)
- **Internal post-exploit**: Sliver or PoshC2 (fast deployment)
- **Budget-conscious**: Sliver + Mythic combination
- **Stealth priority**: BruteRatel (if available) or heavily customized CS

```bash
# Sliver — fastest path to functional C2
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
chmod +x sliver-server_linux && ./sliver-server_linux

# Mythic — Docker-based deployment
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic && sudo make
```

### Phase 2: Team Server Deployment (Terraform + Ansible)

```hcl
# terraform/c2-main.tf (minimal example)
resource "digitalocean_droplet" "teamserver" {
  image  = "ubuntu-22-04-x64"
  name   = "c2-redir-${count.index}"
  region = var.c2_region
  size   = "s-2vcpu-4gb"
  count  = var.teamserver_count

  # Use Ansible for post-provisioning
  provisioner "local-exec" {
    command = "ansible-playbook -i ${self.ipv4_address}, playbooks/harden.yml"
  }
}

resource "cloudflare_record" "c2_domain" {
  zone_id = var.cloudflare_zone_id
  name    = random_pet.domain_name.id
  value   = digitalocean_droplet.teamserver[0].ipv4_address
  type    = "A"
  proxied = true  # CDN wrapping
}
```

```yaml
# ansible/playbooks/harden.yml
- hosts: all
  tasks:
    - name: Install C2 framework (Sliver)
      get_url:
        url: https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
        dest: /usr/local/bin/sliver-server
        mode: '0755'
    - name: Configure firewall (egress only)
      ufw:
        rule: allow
        port: '443'
        proto: tcp
    - name: Install Let's Encrypt cert
      command: certbot --nginx -d {{ c2_domain }} --non-interactive --agree-tos -m admin@{{ c2_domain }}
```

### Phase 3: Redirector Architecture

**Single redirector pattern:**

```
Implant ──TLS──▸ CDN/Worker (front.tld) ──▸ Redirector (redirector.tld)
  ──▸ Team Server (c2-backend.tld, firewalled egress only)
```

**NGINX redirector with domain-fronted fallback:**

```nginx
server {
    listen 443 ssl http2;
    server_name redirector.tld;
    ssl_certificate /etc/letsencrypt/live/redirector.tld/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/redirector.tld/privkey.pem;

    # C2 beacon path — forward to teamserver
    location /analytics/collect {
        proxy_pass https://c2-backend.tld:443;
        proxy_set_header Host c2-backend.tld;
        proxy_ssl_name c2-backend.tld;
        proxy_ssl_server_name on;

        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;

        # Keepalive for long-lived beacons
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    # Decoy content for everyone else
    location / {
        root /var/www/decoy;
        index index.html;
    }
}
```

**HAProxy for multi-backend:**

```haproxy
frontend c2_front
    bind *:443 ssl crt /etc/ssl/private/c2.pem alpn h2,http/1.1
    acl cs_beacon path_beg /analytics/collect
    acl sliver_beacon path_beg /api/v2/
    use_backend cs_servers if cs_beacon
    use_backend sliver_servers if sliver_beacon
    default_backend decoy_servers

backend cs_servers
    server cs1 ip-1:443 check ssl verify none
    server cs2 ip-2:443 check ssl verify none backup
```

### Phase 4: Domain & IP Rotation

**Domain categorization avoidance:**
- Avoid `.xyz`, `.top`, `.club` — these TLDs are statistically red-flagged
- Use `.com`, `.io`, `.co`, `.app` for C2 — blend with real business domains
- Submit domain to Google Safe Browsing before use: no history = not blocked
- Use Parked domain → after 30-60 days of benign content → swap to C2

**IP rotation strategies:**

| Strategy | OPSEC | Complexity | Cost |
|----------|-------|------------|------|
| Rotating VPS (new box) | High | Medium | High |
| CDN wrapping | Medium | Low | Medium |
| Serverless (Lambda/CF) | Medium | High | Low |
| P2P C2 (Sliver) | High | High | Free |

```bash
# Automate domain rotation with DigitalOcean API + Cloudflare
doctl compute droplet create c2-node --region fra1 --size s-2vcpu-4gb \
  --image ubuntu-22-04-x64 --wait
```

### Phase 5: C2 Profile Hardening

**Malleable C2 for Cobalt Strike (mod for other frameworks):**

- Set `sleeptime` with jitter (60000 + 40% jitter)
- URI paths that mimic real apps: `/assets/js/chunk-vendors.8a6d3c12.js`
- User-Agent: real Chrome/Firefox/Edge UA strings only
- HTTP headers should match what real browsers send (Accept, Accept-Language, Accept-Encoding, Sec-Fetch-*)
- Enable `http_post` with matching content-type
- Disable `x86` if x64-only beacons are acceptable (smaller footprint)

**JARM/JA3 randomization:**

```bash
# Sliver — custom JA3 via TLS library
profiles new --mtls 443 --ja3 "771,4865-4866-4867,0-23-35-13,254-0,29-23-24" --jarm "29d29d15fd29d00029d29d15fd29d..."
```

## Detection & OPSEC

**Red flags for SOC/SIEM:**
- Implant dials out at regular intervals (± jitter) — NGFW stream analysis detects periodic beacons
- DNS queries for C2 domains resolve to fresh domains (<30d old)
- JARM hash matches known C2 tooling (Cobalt Strike's unique JARM is widely fingerprinted)
- Session duration >30min on a single egress connection (unusual for web browsing)
- SSL/TLS certificate self-signed or issued within the last 24h

**OPSEC checklist:**
- Never SSH directly to teamserver from your real identity — always use jumpbox/VPN/proxy chain
- Team server IP never sends email, never does DNS resolution to other targets
- Separate VPS for redirector, team server, and payload staging
- Use different cloud providers for each layer (DO → AWS → Hetzner)
- Enable 2FA on all cloud provider accounts associated with C2 infra
- Domain registration with privacy WHOIS and anonymous payment
- Take teamserver snapshots before major payload changes
- Log all C2 activity with timestamps for after-action review
- Failover: provision 2+ team servers, DNS rotation on detection
- Kill switch: pre-configure domain takedown for all active C2 domains

## References

- Cobalt Strike Malleable C2 profile reference: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile_language.md
- Mythic documentation: https://docs.mythic-c2.net/
- Sliver Wiki: https://github.com/BishopFox/sliver/wiki
- Havoc C2: https://github.com/HavocFramework/Havoc
- Red Team Infrastructure Wiki: https://ired.team/offensive-security/red-team-infrastructure
- Redirector patterns (Ryan Hanson): https://blog.nviso.eu/2019/12/17/cobalt-strike-and-domain-fronting/
