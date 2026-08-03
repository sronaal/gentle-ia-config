---
name: linux-security-bypass
description: "Trigger: Linux security bypass, SELinux bypass, AppArmor bypass, LSM bypass, kernel security. Bypass Linux security modules — SELinux, AppArmor, seccomp, and capabilities restrictions."
license: Apache-2.0
metadata:
  author: "pentest-orchestrator"
  version: "2.0"
---

## Activation Contract

Load when needing to bypass Linux security mechanisms: SELinux enforcing mode, AppArmor profiles, seccomp filters, or restricted capabilities after initial compromise.

## Hard Rules

- Bypassing LSMs may trigger audit logs — use OPSEC silent mode for production.
- SELinux/AppArmor bypass requires existing code execution on the host.
- Do NOT disable SELinux globally (setenforce 0) — use process-level bypass instead.

## Decision Gates

| LSM | Bypass Technique | Success Rate |
|-----|------------------|-------------|
| SELinux | Use unconfined domains, exec into `init_t` | High with existing root |
| SELinux | selinuxfs manipulation, `runcon` with permissive domain | Medium |
| AppArmor | Use `aa-exec` to switch profile, unconfined binaries | High |
| AppArmor | Remove profile: `aa-remove-unknown` | Requires CAP_MAC_ADMIN |
| seccomp | Use `seccomp-tools`, switch to `SECCOMP_MODE_ALLOW` | Requires sys_admin |
| seccomp | Use golang with raw syscalls (bypass libseccomp wrappers) | Medium |
| Capabilities | Abuse CAP_SYS_ADMIN, CAP_NET_RAW, CAP_DAC_OVERRIDE | High |
| Namespaces | `unshare -r` to new user namespace with full capabilities | High |

## Execution Steps

1. **LSM detection**: Check `/sys/kernel/security/lsm`, `getenforce`, `aa-status`, `cat /proc/self/attr/current`
2. **SELinux bypass**: `runcon -t init_t /bin/bash` → if allowed, escape confined domain
3. **AppArmor bypass**: `sudo aa-exec -p unconfined /bin/bash` → escape profile
4. **seccomp bypass**: Check `/proc/self/status | grep Seccomp` → if 2 (filtered), use raw syscalls or `seccomp-tools` to dump and identify allowed calls
5. **Capability abuse**: Check `/proc/self/status | grep CapEff` → decode → abuse capabilities like CAP_DAC_OVERRIDE for file access
6. **User namespace escape**: `unshare -Ur` → if supported, run with full capabilities in new namespace
7. **Memfd_create + exec**: Write payload to `memfd_create` then exec from it (avoids file-based policy enforcement)
8. **LSM audit log check**: `ausearch -m AVC,USER_AVC`, `grep DENIED /var/log/audit/audit.log`

## Output Contract

Return:
- **type**: selinux_bypass | apparmor_bypass | seccomp_bypass | capability_abuse | namespace_escape
- **current_lsm**: SELinux / AppArmor / seccomp / capabilities
- **state**: Enforcing / Permissive / Complain / Kill
- **bypass_achieved**: Whether LSM restriction was escaped
- **severity**: Critical (full escape) / High (restricted escape)
