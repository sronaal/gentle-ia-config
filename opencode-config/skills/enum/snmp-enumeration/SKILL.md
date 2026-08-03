---
name: snmp-enumeration
description: SNMP community string and MIB enumeration
version: 1.0.0
phase: enum
category: network
tags: [snmp, network, mib, monitoring]
tools: [snmpwalk, onesixtyone]
difficulty: basic
opsec_level: medium
time_estimate: 60s
severity_if_found: medium
related_skills:
  - smb-enumeration
  - ldap-enumeration
mitre_attack:
  - T1018
  - T1049
---

## When to Use

Use this skill when UDP port 161 is open and you want to enumerate system info,
network configuration, and running processes via SNMP.

## Prerequisites

- snmpwalk (net-snmp)
- onesixtyone (community string brute-force)

## Procedure

```bash
# Step 1: Test default community strings
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt TARGET

# Step 2: Walk system info with public community
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.1.1.0    # sysDescr
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.1.3.0    # sysUpTime
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.1.5.0    # sysName

# Step 3: Enumerate network interfaces
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.2.2       # ifTable
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.4.20      # ipAddrTable

# Step 4: Enumerate running processes
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2    # hrSWRun

# Step 5: Enumerate installed software
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.6.3    # hrSWInstalled

# Step 6: Enumerate users (if available)
snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25 # atConsoleUsers

# Step 7: Check SNMPv3 users
snmpwalk -v3 -l authPriv -u USER -a SHA -A PASS -x AES -X PASS TARGET 1.3.6.1.4.1.77.1.2.25

# Step 8: Full walk (all OIDs — verbose)
snmpwalk -v2c -c public TARGET 1.3.6.1 -O n 2>/dev/null | tee snmp_walk.txt
```

## OPSEC Rules

- Do NOT set or modify SNMP values (snmpset)
- Do NOT trap or flood the SNMP service
- Limit walk to specific OIDs when possible
- Do not brute-force community strings excessively
- Log all requests for audit trail

## Verification

- Confirm community string works (walk returns data)
- Verify sysDescr returns valid system info
- Check if SNMPv3 is also enabled

## Pitfalls

- Community string `public` is most common but not universal
- Some devices restrict SNMP to specific source IPs
- SNMPv3 requires auth/priv credentials
- UDP is unreliable — responses may be lost

## Output Format

```
[SNMP]    Community: public — version: v2c
[SNMP]    sysDescr: Linux server 5.15.0 #1 SMP
[SNMP]    sysName: webserver-prod
[NET]     eth0: 10.0.1.15/24, eth1: 192.168.1.100/24
[PROC]    nginx, postgresql, redis-server
[USER]    root, postgres, redis
```
