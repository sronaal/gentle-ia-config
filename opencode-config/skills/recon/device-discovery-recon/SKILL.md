---
name: device-discovery-recon
description: "Trigger: IoT recon, device discovery, router scan, camera find, embedded device. Discover and fingerprint IoT, embedded, and network devices on target ranges."
license: Apache-2.0
metadata:
  author: "pentest-orchestrator"
  version: "1.0"
---

## Activation Contract

Load when the user wants to discover IoT devices, routers, IP cameras, printers, NAS, smart home devices, or embedded systems on a target network or IP range.

## Hard Rules

- Use passive discovery (SSDP, mDNS) before active probing.
- Do NOT perform factory resets or firmware modification.
- Default credential testing requires explicit approval (`pentest approve credential`).
- Rate-limit discovery to 5 packets/sec on production networks.

## Decision Gates

| Device Type | Discovery Method | Fingerprint |
|-------------|-----------------|-------------|
| Router/AP | UPnP SSDP scan, admin panel check | `M-SEARCH * HTTP/1.1`, `/cgi-bin/`, `/login.htm` |
| IP Camera | RTSP probe, ONVIF discovery | `rtsp://`, port 554, `/onvif/device_service` |
| Printer | JetDirect, SNMP, LPD | Port 9100, 161, 515; SNMP OID walk |
| NAS | SMB, AFP, HTTP admin | Port 445, 548, 5000/5001 (Synology), 8080 (QNAP) |
| Smart Home | mDNS, MQTT, CoAP | Port 5353, 1883, 5683; `_hap._tcp` (HomeKit) |
| Industrial | Modbus, BACnet, Profinet | Port 502, 47808, 34962 |
| VoIP/SIP | SIP OPTIONS scan | Port 5060, 5061; `SIP/2.0` |
| Medical | HL7, DICOM | Port 2575, 11112, 104 |

## Execution Steps

1. **SSDP/UPnP discovery**: Send `M-SEARCH * HTTP/1.1` multicast to `239.255.255.250:1900` → collect device descriptors (USN, LOCATION, SERVER)
2. **mDNS scan**: Probe `_http._tcp.local`, `_airplay._tcp.local`, `_hap._tcp.local`, `_ipp._tcp.local` → resolve ServiceInstance names
3. **Port scan targeted**: Scan top 50 IoT ports across ranges (23, 80, 443, 554, 1883, 502, 161, 9100, 5683, 1900, 5353, 49152-49156)
4. **HTTP banner grab**: GET `/` on discovered HTTP services → parse Server header, title, WWW-Authenticate realm
5. **RTSP detection**: Send `OPTIONS rtsp://<ip>:554` → parse Supported/Public headers
6. **SNMP enumeration**: Walk `.1.3.6.1.2.1.1` (system), `.1.3.6.1.2.1.25` (host resources) with `public`/`private` communities
7. **Default credential test**: For identified devices, test known default creds from `assets/default-creds.json`
8. **CVE mapping**: Map vendor + model + firmware against known CVEs (2026 active: router, camera, NAS vulns)
9. **MQTT probe**: Connect to port 1883 → subscribe to `#` → capture topics and messages

## Output Contract

Return device inventory:
- **ip**, **port**, **protocol**: Connection info
- **vendor**, **model**, **firmware**: Fingerprint details
- **services**: HTTP, RTSP, SNMP, MQTT, etc.
- **default_creds**: Tested and found (or "not tested")
- **cve_matches**: Known vulnerabilities for device
- **risk_score**: 1-10 based on exposure + known vulns
