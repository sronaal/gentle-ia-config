---
name: cms-detection
description: Detect the CMS platform and version used by a target website
version: 1.0.0
phase: enum
category: cms
tags: [cms, detection, wordpress, drupal, joomla]
tools: [whatweb, cmseek]
difficulty: basic
opsec_level: low
time_estimate: 15s
severity_if_found: info
related_skills:
  - wordpress-scan
  - tech-detection
mitre_attack:
  - T1592.002
---

## When to Use

Use this skill to identify the CMS platform (WordPress, Drupal, Joomla, etc.)
and its version. CMS-specific vulnerabilities depend on knowing the platform.

## Prerequisites

- whatweb
- cmseek (optional, for deeper CMS checks)

## Procedure

```bash
# Quick CMS detection
whatweb TARGET -v

# Deep CMS scan
cmseek -u TARGET

# Check common CMS paths
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/wp-login.php"  # WordPress
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/CHANGELOG.txt"  # Drupal
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/administrator/"  # Joomla
```

## OPSEC Rules

- Single request per check — do not repeat
- CMS detection is passive and low-risk
- Do not probe for vulnerabilities without authorization

## Verification

- Cross-check detection with known CMS fingerprints
- Verify version against official releases
- Check if CMS is behind a WAF that may hide the platform

## Pitfalls

- Security plugins may hide CMS fingerprints
- Some sites use custom themes that obscure CMS identity
- CMS detection accuracy varies between tools

## Output Format

```
[CMS] WordPress 6.4.1 detected
[PLUGIN] WooCommerce 8.3.1
[THEME] Astra 3.3.2
```
