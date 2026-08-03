---
name: hash-cracking
description: Password hash cracking operations — hashcat and John the Ripper workflow, rule-based attacks, mask attacks, wordlist optimization, and distributed cracking
version: 1.0.0
phase: post
category: post-exploitation
tags: [hash-cracking, hashcat, john, password, cracking]
tools: [hashcat, john, python3]
difficulty: intermediate
opsec_level: medium
time_estimate: varies
severity_if_found: critical
mitre_attack:
  - T1110.002
  - T1003
---

## When to Use

Use this skill after credential dumping (NTDS.dit, SAM, LSASS, /etc/shadow, database dumps) when you have extracted raw password hashes and need plaintext credentials. Also use for WPA handshake cracking, document/archive password cracking, and benchmarking GPU cracking performance.

**Do NOT** use for online brute-force — this is strictly offline cracking against already-obtained hashes.

## What It Does

Identifies hash types, selects optimal attack modes, and executes password cracking campaigns using hashcat (GPU-accelerated) and John the Ripper (CPU fallback). Covers rule-based wordlist attacks, mask attacks for known patterns, combinator and hybrid attacks, Markov-chain probabilistic attacks, and distributed cracking orchestration.

## Methodology

### Phase 1: Hash Identification & Extraction

Identify hash type — never guess:

```bash
# Hashcat built-in identification
hashcat --identify hashes.txt

# John's hash identifier
john hashes.txt

# Manual distinction — critical for correct mode selection:
# NT (1000)   : 32 hex chars, all uppercase — 9e8c8a0b1c3d4e5f6a7b8c9d0e1f2a3b
# NTLM (1000) : 32 hex chars, mixed case — same format as NT but auth differs
# NetNTLMv2 (5600) : has $NETNTLMv2$ prefix — ADMINISTRATOR::host:...
# bcrypt (3200) : starts with $2a$/$2b$/$2y$ — $2a$10$N9q...
# SHA-512 (1800) : starts with $6$ — $6$salt$hash
# md5crypt (500) : starts with $1$ — $1$salt$hash
```

Use `cut -d: -f4` on NTDS.dit dumps to extract just the hashes. Remove LM hashes (all-zero or `aad3b435b51404eeaad3b435b51404ee` — these indicate no LM hash, wasting compute).

### Phase 2: Attack Mode Selection

| Mode | Flag | Use Case | Speed |
|------|------|----------|-------|
| Straight | `-a 0` | Wordlist + rules | Fastest |
| Combinator | `-a 1` | word1+word2 concatenation | Fast |
| Mask | `-a 3` | Known patterns (Summer2024!) | Medium |
| Hybrid word+mask | `-a 6` | word + suffix bruteforce | Medium |
| Hybrid mask+word | `-a 7` | prefix bruteforce + word | Medium |
| Association | `-a 9` | Related-word substitution | Slow |

**Rule-based (always pair with -a 0):**

```bash
# Best64 — 64 highest-value mutation rules
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# OneRuleToRuleThemAll (48k rules) — community gold standard
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r OneRuleToRuleThemAll.rule

# Generate your own rules from cracked passwords
# (Prince processor or rule extraction from potfile)
```

**Mask attacks for known policies:**

```bash
# Summer2024! pattern — uppercase+lower+year+special
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?d?d?d?d?s

# CompanyYear! — CompanyName2024!
hashcat -m 1000 -a 6 hashes.txt company-wordlist.txt ?d?d?d?d?s

# Policy-derived masks: if min 8 + uppercase + digit + special
# Start with ?u?l?l?l?l?l?d?s then expand length
```

### Phase 3: Wordlist Optimization

```bash
# CeWL — spider target domain for custom wordlist
cewl -d 2 -m 5 -w target-words.txt https://target.com

# Combine and deduplicate
cat rockyou.txt target-words.txt | sort -u > combined.txt

# Prune by length (skip <8 for modern NTLM)
awk 'length >= 8' combined.txt > pruned.txt

# Statistically prune — keep most frequent patterns
# (hashcat --stdout + sort | uniq -c | sort -rn)

# Combinator attack — two-word concatenation
hashcat -m 1000 -a 1 hashes.txt wordlist.txt wordlist.txt
```

### Phase 4: Session Management

```bash
# Start session with restore point
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule \
  --session crack1 --restore-file-path session.restore

# Restore session (if hashcat crashes or is stopped)
hashcat --restore --session crack1

# Show cracked hashes
hashcat -m 1000 --show hashes.txt

# Show cracked with plaintext
hashcat -m 1000 --show hashes.txt --username --outfile-format=1,2,3
```

Always use `--backend-devices` to target specific GPUs. Profile with `--benchmark -m 1000` before starting.

### Phase 5: Distributed Cracking (hashtopolis)

```bash
# Deploy hashtopolis server
docker run -d -p 80:80 --name hashtopolis s3inlc/hashtopolis

# Agents connect to server, receive chunks, return results
# Server handles work distribution, deduplication, potfile management
```

Hashtopolis splits the keyspace into chunks, distributes to GPU agents, merges results. Useful for large NTDS dumps (10k+ hashes) or time-sensitive ops.

### Phase 6: WPA/WPA2 Cracking

```bash
# Convert hccapx (old) or pcap to hashcat format
hccapx2john capture.hccapx > wpa.hash
# or directly with hashcat
hashcat -m 22000 hashes.txt wordlist.txt
# hcxpcapngtool from hcxtools for PMKID/EAPOL
hcxpcapngtool -o hash.hc22000 capture.pcap
```

WPA2 handshake requires the 4-way handshake or PMKID. WPA3 (SAE) uses different format — verify hashcat mode.

## Detection & OPSEC

**GPU thermal/power**: Hashcat pushes GPUs to 100% for hours. Monitor temps (<85°C for most cards). On shared infrastructure, users may notice fan noise or performance degradation.

**Potfile hygiene**: Hashcat's `hashcat.potfile` stores all cracked passwords in plaintext. Either delete after use or point `--potfile-path` to a temp location:

```bash
hashcat -m 1000 hashes.txt wordlist.txt --potfile-path /tmp/crack.pot
```

**Memory**: John the Ripper keeps hashes in memory. On assessment VMs, use encrypted swap if the system may be imaged.

**Network detection**: Hashtopolis agents communicate with the server. If the server is remote, tunnel over SSH or use a redirector. Unencrypted hashtopolis traffic reveals cracked passwords on the wire.

**Resource limits**:
- Crack only what's needed for the assessment scope
- Delete cracked hash files and potfiles when done
- On multi-tenant VMs, GPU cracking may violate shared resource policies

**Timing attacks**: Don't run cracking on battery-powered laptops at DEF CON — thermal output alone will dox you.

## References

- Hashcat wiki: https://hashcat.net/wiki/
- OneRuleToRuleThemAll: https://github.com/NotSoSecure/password_cracking_rules
- Hashtopolis: https://github.com/s3inlc/hashtopolis
- hcxtools (WPA capture): https://github.com/ZerBea/hcxtools
- CrackStation password dictionary: https://crackstation.net/
- Pipal (password stats): https://github.com/digininja/pipal
- Kerberoast hashcat modes: 13100 (TGS-REP), 19600 (Kerberos 5 TGS-REP etype 23)
