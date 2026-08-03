---
name: recon-playbook
description: 4-phase recon pipeline with scoring and escalation
version: 1.0.0
phase: meta
category: methodology
tags: [recon, pipeline, methodology, scoring]
tools: [subfinder, httpx, curl, nmap]
difficulty: advanced
opsec_level: medium
time_estimate: 15m
severity_if_found: info
related_skills:
  - subdomain-discovery
  - tech-detection
  - cors-variants-deep
mitre_attack:
  - T1595
  - T1595.001
---

## When to Use

Use this skill to orchestrate a complete reconnaissance pipeline across 4 phases
with automatic scoring and escalation. Targets scoring >= 6 escalate to Phase 3.

## Prerequisites

- subfinder, httpx, curl, nmap installed
- Target domain or CIDR scope defined

## Procedure

### Phase 0: Target Generation (5-10 min)

```bash
curl -s "https://crt.sh/?q=%25.TARGET.com&output=json" | jq -r '.[].name_value' | sort -u > crt_raw.txt
subfinder -d TARGET.com -silent -o subfinder_raw.txt
cat crt_raw.txt subfinder_raw.txt | sort -u | grep -v '\*' > targets_phase0.txt
```

### Phase 1: Quick Filter (2-3s per target)

```bash
cat targets_phase0.txt | httpx -silent -title -tech-detect -status-code -follow-redirects > phase1_results.txt
cat targets_phase0.txt | httpx -silent -path "/wp-login.php" -status-code -match-string "WordPress" > wp_detected.txt
cat phase1_results.txt | grep -E '\[2[0-9]{2}\]' > alive_targets.txt
```

### Phase 2: Deep Check (30s per target)

```bash
# CORS check
cat alive_targets.txt | xargs -I{} curl -s -o /dev/null -w "%{http_code} {}\n" -H "Origin: https://evil.com" {} > cors_results.txt

# User enumeration, XMLRPC, leaks
for t in $(cat alive_targets.txt); do
  curl -s -o /dev/null -w "%{http_code}\n" "$t/wp-json/wp/v2/users" >> users.txt
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "$t/xmlrpc.php" -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' >> xmlrpc.txt
  curl -s -o /dev/null -w "%{http_code}\n" "$t/.env" >> leaks.txt
done
```

### Phase 3: Deep Invade (5-10 min per target, score >= 6 only)

```bash
# SSRF, error logs, plugins, ports, JS secrets
for t in $(cat high_score_targets.txt); do
  curl -s -o /dev/null -w "%{http_code}\n" "$t/api/proxy?url=http://169.254.169.254" >> ssrf.txt
  curl -s -o /dev/null -w "%{http_code}\n" "$t/wp-content/debug.log" >> errorlog.txt
  curl -s "$t" | grep -oP 'wp-content/plugins/[^/]+' | sort -u > plugins_$t.txt
  nmap -sV -T4 --top-ports 100 "$t" -oN ports_$t.txt
  curl -s "$t" | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//' | xargs -I{} curl -s "$t/{}" | grep -oiE '(api[_-]?key|secret|token)["\x27:=]+[^\s"'\'']{8,}' >> js_secrets_$t.txt
done
```

### Scoring

```bash
while read -r target; do
  score=0
  grep -q "$target" alive_targets.txt && ((score++))
  grep -q "$target" cors_results.txt && ((score+=2))
  grep -q "200.*$target" users.txt && ((score++))
  grep -q "200.*$target" xmlrpc.txt && ((score++))
  grep -q "200.*$target" leaks.txt && ((score+=2))
  [ -s "plugins_$target.txt" ] && ((score++))
  [ -s "js_secrets_$target.txt" ] && ((score+=2))
  echo "$target $score" >> scoring_results.txt
  [ "$score" -ge 6 ] && echo "$target" >> high_score_targets.txt
done < alive_targets.txt
```

## OPSEC Rules

- Phase 0-1: Passive sources first, minimize active probing
- Phase 2: Rate limit to 1/second per target
- Phase 3: Never exceed 5 requests/second
- Do not attempt authentication or credential stuffing
- Log all requests for audit trail

## Verification

- Check output file existence and line counts per phase
- Spot-check 3-5 targets manually for scoring accuracy
- Verify no out-of-scope targets in results

## Pitfalls

- crt.sh returns wildcards — always deduplicate
- httpx misses non-standard ports — supplement with nmap
- WordPress detection may false-positive on WP-like themes
- Large target lists (>500) slow Phase 2/3 — batch them

## Output Format

```
[PHASE0] targets_phase0.txt — 47 unique subdomains
[PHASE1] alive_targets.txt — 23 alive hosts
[PHASE2] cors_results.txt — 5 CORS misconfigs
[PHASE3] high_score_targets.txt — 4 targets escalated
[SCORING] scoring_results.txt — target scores
```
