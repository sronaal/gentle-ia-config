---
name: cross-wave-delta
description: Compare recon waves and track findings over time
version: 1.0.0
phase: meta
category: methodology
tags: [delta, comparison, tracking, waves]
tools: [diff, jq]
difficulty: intermediate
opsec_level: low
time_estimate: 1m
severity_if_found: info
related_skills:
  - recon-playbook
  - finding-consolidation
mitre_attack: []
---

## When to Use

Use this skill to compare reconnaissance results across multiple waves and
categorize changes as NEW, REGRESSION, PERSISTENT, or CHANGE.

## Prerequisites

- Previous wave results stored (JSON or text)
- Current wave results from recon-playbook
- jq installed

## Procedure

### Step 1: Normalize Wave Data

```bash
jq -n \
  --arg id "002" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argfile targets <(cat targets_phase0.txt | jq -R . | jq -s .) \
  --argfile alive <(cat alive_targets.txt | jq -R . | jq -s .) \
  '{wave_id:$id, timestamp:$ts, targets:$targets, alive:$alive}' > waves/wave_002.json
```

### Step 2: Compare Two Waves

```bash
PREV=$(jq -r '.targets[]' waves/wave_001.json | sort)
CURR=$(jq -r '.targets[]' waves/wave_002.json | sort)

# NEW: in current but not previous
comm -13 <(echo "$PREV") <(echo "$CURR") > delta_new.txt

# REMOVED: in previous but not current
comm -23 <(echo "$PREV") <(echo "$CURR") > delta_removed.txt

# PERSISTENT: in both
comm -12 <(echo "$PREV") <(echo "$CURR") > delta_persistent.txt

# Status changes
PREV_ALIVE=$(jq -r '.alive[]' waves/wave_001.json)
CURR_ALIVE=$(jq -r '.alive[]' waves/wave_002.json)
for t in $(cat delta_persistent.txt); do
  P="dead"; C="dead"
  echo "$PREV_ALIVE" | grep -q "^${t}$" && P="alive"
  echo "$CURR_ALIVE" | grep -q "^${t}$" && C="alive"
  [ "$P" != "$C" ] && echo "$t: $P → $C" >> delta_changes.txt
done
```

### Step 3: Score Comparison

```bash
for t in $(cat delta_persistent.txt); do
  PS=$(jq -r ".scores[]|select(startswith(\"$t\"))" waves/wave_001.json|awk '{print $2}')
  CS=$(jq -r ".scores[]|select(startswith(\"$t\"))" waves/wave_002.json|awk '{print $2}')
  [ "$CS" -gt "$PS" ] 2>/dev/null && echo "$t: $PS → $CS" >> delta_scores.txt
done
```

### Step 4: Generate Report

```bash
cat > delta_report.md << EOF
# Delta Report: Wave 001 → Wave 002
- NEW: $(wc -l < delta_new.txt)
- REMOVED: $(wc -l < delta_removed.txt)
- PERSISTENT: $(wc -l < delta_persistent.txt)
- Status changes: $(wc -l < delta_changes.txt 2>/dev/null || echo 0)
- Score increases: $(grep -c . delta_scores.txt 2>/dev/null || echo 0)
EOF
```

## OPSEC Rules

- No active scanning — analysis only
- Compare stored results, do not re-scan
- Previous wave data must be from authorized testing
- Do not compare waves from different engagements

## Verification

- Confirm both wave files exist and are valid JSON
- Validate target counts: NEW + REMOVED + PERSISTENT = total
- Review delta report for completeness

## Pitfalls

- Waves must use same target format (FQDN vs IP)
- Timezone differences affect timestamp comparisons
- Large time gaps may invalidate comparisons
- Score methodology must be consistent across waves

## Output Format

```
[DELTA] Wave 001 → Wave 002
[NEW] 12 new targets discovered
[REMOVED] 3 targets disappeared
[PERSISTENT] 34 targets still present
[CHANGES] 5 targets changed alive status
[REPORT] delta_report.md generated
```
