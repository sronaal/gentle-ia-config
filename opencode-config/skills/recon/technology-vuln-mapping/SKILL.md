---
name: technology-vuln-mapping
description: Map detected technologies and versions to known CVEs and vulnerabilities — NVD, Exploit-DB, Nuclei, and OSV integration
version: 1.0.0
phase: recon
category: fingerprinting
tags: [cve, vulnerability, mapping, nvd, nuclei, searchsploit]
tools: [curl, searchsploit, nuclei, whatweb, python3]
difficulty: intermediate
opsec_level: low
time_estimate: 60s
severity_if_found: high
related_skills:
  - technology-cve-matching
  - cms-detection
mitre_attack:
  - T1592
---

## When to Use

Use this skill after `tech-detection` or `cms-fingerprint-deep` have identified
live technologies and version strings. It maps every discovered technology to its
known CVEs via four independent data sources: **NVD** (CVSS-scored CVE catalog),
**OSV.dev** (ecosystem-specific vulns for npm, PyPI, Go, Maven, etc.),
**Exploit-DB** (searchsploit), and **Nuclei** (automated CVE template scanning).

The output is a prioritized vulnerability map grouped by severity, with exploit
availability markers — designed to feed directly into `hunt-*` exploitation
skills. This replaces blind CVE spraying with targeted, version-verified attacks.

Also detects **end-of-life (EOL)** software versions that receive no further
security patches, which are high-value targets despite lacking a specific CVE.

## Prerequisites

- `whatweb` — technology and version fingerprinting
- `nuclei` (ProjectDiscovery) with downloaded templates from `nuclei-templates` repo
- `searchsploit` — local Exploit-DB copy (`apt install exploitdb || git clone https://gitlab.com/exploit-database/exploitdb`)
- `curl` and `jq` — API queries and JSON processing
- `python3` with `requests` — OSV batch queries and result aggregation
- NVD API key (optional but recommended: `https://nvd.nist.gov/developers/request-an-api-key`)
  — without it, rate limit is ~5 requests per 30 seconds
- `git` — for PoC exploit repository check

### Verify Tooling

```bash
for cmd in whatweb nuclei searchsploit curl jq python3 git; do
    command -v "$cmd" >/dev/null 2>&1 || echo "[MISSING] $cmd"
done
echo "[OK] All required tools present"
```

## Procedure

### 1. Technology Fingerprint Collection

Collect every technology + version pair from the target. Sources: whatweb,
response headers, HTML meta tags, body version patterns, and JavaScript bundle
analysis.

```bash
TARGET="https://target.com"
DOMAIN=$(echo "$TARGET" | sed 's|https\?://||; s|/.*||')
OUTDIR="vuln-map-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

echo '=== Step 1: Technology Fingerprint Collection ==='

# 1a. whatweb with JSON output
whatweb "$TARGET" -v --log-json="$OUTDIR/whatweb.json" 2>/dev/null

# 1b. Response header extraction
curl -skIL "$TARGET" 2>/dev/null > "$OUTDIR/headers.txt"
grep -iE '^(server|x-powered-by|x-generator|x-drupal-cache|x-varnish|x-aspnet-version|x-nginx-version|x-version):' "$OUTDIR/headers.txt" \
    > "$OUTDIR/header_tech.txt" 2>/dev/null

# 1c. HTML body version patterns
curl -sk "$TARGET" 2>/dev/null \
    | grep -oP '(?<=ver=)[0-9]+\.[0-9]+(\.[0-9]+)?' \
    | sort -u > "$OUTDIR/body_versions_ver_param.txt" 2>/dev/null

curl -sk "$TARGET" 2>/dev/null \
    | grep -oP '(?<=version["\'\'']?\s*[:=]\s*["\'\''])[0-9]+\.[0-9]+(\.[0-9]+)?' \
    | sort -u > "$OUTDIR/body_versions_json_ld.txt" 2>/dev/null

# 1d. Common path version probes (CHANGELOG, README, meta files)
for path in CHANGELOG.md CHANGELOG.txt changelog README.md package.json composer.json; do
    ver=$(curl -sk "$TARGET/$path" 2>/dev/null \
        | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' \
        | head -1)
    [ -n "$ver" ] && echo "$path => $ver" >> "$OUTDIR/file_versions.txt"
done

# 1e. Aggregate: build a clean tech+version inventory
echo "=== Technology Inventory ==="
python3 -c "
import json, re

inventory = []

# Parse whatweb output
try:
    with open('$OUTDIR/whatweb.json') as f:
        ww = json.load(f)
    for plugin in ww.get('plugins', []):
        name = plugin.get('name', '')
        version = plugin.get('version', '')
        certainty = plugin.get('certainty', 100)
        if version:
            inventory.append({'tech': name, 'version': version, 'source': 'whatweb', 'certainty': certainty})
except: pass

# Parse header tech
try:
    with open('$OUTDIR/header_tech.txt') as f:
        for line in f:
            if ':' in line:
                key, val = line.split(':', 1)
                inventory.append({'tech': key.strip().lower(), 'version': val.strip(), 'source': 'header', 'certainty': 90})
except: pass

if inventory:
    print(json.dumps(inventory, indent=2))
else:
    print('[WARN] No technologies detected')
print(f'\\nTotal tech+version pairs collected: {len(inventory)}')
" 2>&1
```

### 2. NVD API CVE Lookup

Query the NVD API 2.0 for each tech+version pair. Returns CVE IDs, CVSS v3.1
scores, descriptions, and published dates. API key speeds up the rate limit
from 5 req/30s to ~50 req/30s.

```bash
echo '=== Step 2: NVD CVE Lookup ==='

NVD_API_KEY="${NVD_API_KEY:-}"  # Set this for higher rate limits
NVD_BASE="https://services.nvd.nist.gov/rest/json/cves/2.0"
API_PARAM=""
[ -n "$NVD_API_KEY" ] && API_PARAM="&apiKey=$NVD_API_KEY"

nvd_search() {
    local product="$1"
    local version="$2"
    local query="${product}+${version}"
    local outfile="$OUTDIR/nvd_${product}_${version}.json"

    # URL-encode the keyword search
    curl -sk "${NVD_BASE}?keywordSearch=${query}&resultsPerPage=20${API_PARAM}" \
        2>/dev/null \
        | jq -r '
            .vulnerabilities[]? // [] |
            {
                id: .cve.id,
                published: .cve.published,
                sourceIdentifier: .cve.sourceIdentifier,
                cvss: (.cve.metrics.cvssMetricV31[0].cvssData.baseScore // null),
                severity: (.cve.metrics.cvssMetricV31[0].cvssData.baseSeverity // null),
                vector: (.cve.metrics.cvssMetricV31[0].cvssData.vectorString // null),
                epss: null,
                description: (.cve.descriptions[] | select(.lang == "en") .value // ""),
                exploitAvailable: false
            }' 2>/dev/null > "$outfile"

    local count
    count=$(jq -s 'length' "$outfile" 2>/dev/null || echo 0)
    echo "[NVD] $product $version → $count CVEs"
}

# Read inventory from Python output and call nvd_search for each
# (Manual expansion example — in real use pipe from step 1e)
nvd_search "nginx" "1.18.0"
nvd_search "apache-httpd" "2.4.49"
nvd_search "wordpress" "5.8.2"
nvd_search "php" "7.4.30"
nvd_search "drupal" "7.89"

sleep 6  # Rate limit guard for non-API-key usage
```

### 3. OSV.dev Batch Query

Query Google's OSV.dev API for ecosystem-specific vulnerabilities. Covers npm,
PyPI, Go, Maven, NuGet, RubyGems, crates.io, and more. Returns CVE IDs with
affected version ranges.

```bash
echo '=== Step 3: OSV.dev Ecosystem Vulnerability Query ==='

cat > "$OUTDIR/osv_query.py" << 'PYEOF'
import json, requests, sys, os

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE = "https://api.osv.dev/v1/query"

# Map detected tech to OSV ecosystems
ECOSYSTEM_MAP = {
    "node": "npm", "nodejs": "npm", "npm": "npm",
    "python": "PyPI", "pip": "PyPI",
    "go": "Go", "golang": "Go",
    "java": "Maven", "maven": "Maven", "tomcat": "Maven",
    "dotnet": "NuGet", "asp.net": "NuGet", "nuget": "NuGet",
    "ruby": "RubyGems", "gem": "RubyGems",
    "rust": "crates.io", "cargo": "crates.io",
    "php": "Packagist", "composer": "Packagist", "wordpress": "Packagist",
    "drupal": "Packagist", "joomla": "Packagist",
}

# Build batch query from detected technologies
inventory = []
try:
    with open(f"{sys.argv[1]}/whatweb.json") if len(sys.argv) > 1 else "/dev/null" as f:
        pass  # parsed inline below for simplicity
except: pass

# Manual inventory input — populate from whatweb/cms-detection output
detected = {
    # Format: "tech_name": {"ecosystem": "npm", "version": "4.17.21"}
}

queries = []
for tech, info in detected.items():
    eco = ECOSYSTEM_MAP.get(info.get("ecosystem", tech.lower()), None)
    if not eco:
        continue
    queries.append({
        "package": {"name": tech, "ecosystem": eco},
        "version": info["version"]
    })

if not queries:
    # Fallback: query via commit hash / package URL from detected libs
    print("[OSV] No ecosystem-mapped technologies found — skipping batch query")
    sys.exit(0)

# Batch query (up to 1000 at once)
resp = requests.post(OSV_BATCH, json={"queries": queries}, timeout=30)
if resp.status_code == 200:
    results = resp.json().get("results", [])
    for idx, result in enumerate(results):
        q = queries[idx]
        vulns = result.get("vulns", [])
        if vulns:
            out = []
            for v in vulns:
                out.append({
                    "id": v.get("id"),
                    "aliases": v.get("aliases", []),
                    "summary": v.get("summary", ""),
                    "modified": v.get("modified", "")
                })
            print(f"[OSV] {q['package']['name']} ({q['version']}): {len(out)} vulns")
            for v in out:
                print(f"       {v['id']} — {v['summary'][:100]}")
        else:
            print(f"[OSV] {q['package']['name']} ({q['version']}): 0 vulns")
else:
    print(f"[OSV] Batch query failed: HTTP {resp.status_code}")
PYEOF

python3 "$OUTDIR/osv_query.py" "$OUTDIR"
```

### 4. searchsploit Version Matching

Match each detected version against the local Exploit-DB database. This is
entirely offline — zero network detection risk.

```bash
echo '=== Step 4: searchsploit Exploit Lookup ==='

# Build a clean version list from step 1
whatweb "$TARGET" -v 2>/dev/null \
    | grep -oP '\[[0-9]+\.[0-9]+(\.[0-9]+)?\]' \
    | tr -d '[]' \
    | sort -u > "$OUTDIR/versions.txt"

# Also extract product names for targeted search
whatweb "$TARGET" -v 2>/dev/null \
    | grep -oP '^[A-Za-z][A-Za-z0-9_-]+' \
    | sort -u > "$OUTDIR/products.txt"

echo "=== searchsploit: Version-Based ==="
while IFS= read -r version; do
    [ -z "$version" ] && continue
    # Major.minor search (broader)
    major_minor=$(echo "$version" | cut -d. -f1,2)
    result=$(searchsploit "$major_minor" 2>/dev/null | grep -v "^$" | grep -v "Exploits:" | tail -n +4)
    if [ -n "$result" ]; then
        count=$(echo "$result" | grep -c "^")
        echo "[SSPLOIT] Version $major_minor.x → $count results"
        echo "$result" | head -10
        echo "---"
    fi
done < "$OUTDIR/versions.txt"

echo "=== searchsploit: Product-Specific ==="
while IFS= read -r product; do
    [ -z "$product" ] && continue
    result=$(searchsploit "$product" 2>/dev/null | grep -v "^$" | grep -v "Exploits:" | tail -n+4 | head -5)
    if [ -n "$result" ]; then
        echo "[SSPLOIT] Product: $product"
        echo "$result"
        echo "---"
    fi
done < "$OUTDIR/products.txt"
```

### 5. Nuclei CVE Template Scan

Run Nuclei with CVE and exposure templates against the target. This is the
automated verification layer — it actively probes for each CVE condition.

```bash
echo '=== Step 5: Nuclei CVE Scan ==='

# 5a. Full CVE template scan (broad)
nuclei -u "$TARGET" \
    -t ~/nuclei-templates/cves/ \
    -rl 30 -c 3 \
    -severity critical,high,medium \
    -silent \
    -o "$OUTDIR/nuclei_cves.txt" 2>/dev/null

# 5b. Technology-tagged subset (focused, faster)
for tech in nginx apache iis tomcat wordpress drupal joomla php python nodejs java express \
            flask django rails jenkins gitlab postgres mysql redis; do
    nuclei -u "$TARGET" \
        -t ~/nuclei-templates/cves/ \
        -t ~/nuclei-templates/exposures/ \
        -tags "$tech" \
        -rl 30 -c 3 \
        -silent \
        -o "$OUTDIR/nuclei_${tech}.txt" 2>/dev/null &
done
wait

# 5c. Aggregate Nuclei results
echo "=== Nuclei CVE Results ==="
for f in "$OUTDIR"/nuclei_*.txt; do
    [ -f "$f" ] && [ -s "$f" ] && echo "[NUCLEI] $(basename "$f"): $(wc -l < "$f") findings" && head -5 "$f" && echo "---"
done
```

### 6. Exploit Availability Check

For each CVE found, check if a public exploit exists — either in Exploit-DB,
GitHub PoC repos, or Metasploit modules.

```bash
echo '=== Step 6: Exploit Availability Check ==='

# Collect all unique CVE IDs from steps 2-5
grep -rohP 'CVE-\d{4}-\d{4,}' "$OUTDIR/" 2>/dev/null \
    | sort -u > "$OUTDIR/all_cves.txt"

echo "=== Checking ${total_cves:-0} unique CVEs for public exploits ==="

while IFS= read -r cve; do
    [ -z "$cve" ] && continue
    cve_upper=$(echo "$cve" | tr '[:lower:]' '[:upper:]')

    # 6a. searchsploit check
    ss_count=$(searchsploit --cve "$cve_upper" 2>/dev/null | grep -c "exploits\|shellcodes")
    ss_path=$(searchsploit --cve "$cve_upper" 2>/dev/null | grep -oP '/exploits/[^ ]+' | head -1)

    # 6b. GitHub PoC search (via API — unauthenticated, rate-limited)
    gh_count=0
    gh_resp=$(curl -sk "https://api.github.com/search/repositories?q=${cve_upper}+poc&per_page=3" 2>/dev/null)
    if [ -n "$gh_resp" ]; then
        gh_count=$(echo "$gh_resp" | jq '.total_count // 0' 2>/dev/null)
        gh_top=$(echo "$gh_resp" | jq -r '.items[:3][] | "  GH: \(.html_url) ⭐\(.stargazers_count)"' 2>/dev/null)
    fi

    # 6c. Metasploit module check
    msf_count=0
    if command -v msfconsole &>/dev/null; then
        msf_count=$(msfconsole -q -x "search ${cve_upper}; exit" 2>/dev/null | grep -c "exploit/\|auxiliary/")
    fi

    exploit_info=""
    [ "$ss_count" -gt 0 ] && exploit_info+=" Exploit-DB:${ss_count}"
    [ "$gh_count" -gt 0 ] && exploit_info+=" GitHub:${gh_count}"
    [ "$msf_count" -gt 0 ] && exploit_info+=" MSF:${msf_count}"

    if [ -n "$exploit_info" ]; then
        echo "[EXPLOIT] ${cve_upper} →${exploit_info}"
        [ -n "$ss_path" ] && echo "  EDB: ${ss_path}"
        [ -n "$gh_top" ] && echo "${gh_top}"
    fi

done < "$OUTDIR/all_cves.txt"
```

### 7. EOL / End-of-Life Detection

Identify software versions past their vendor-supported end-of-life — these have
no security patches and are high-value even without a specific CVE match.

```bash
echo '=== Step 7: EOL Software Detection ==='

eol_check() {
    local product="$1"
    local version="$2"
    local major_minor
    major_minor=$(echo "$version" | cut -d. -f1-2)
    local major
    major=$(echo "$version" | cut -d. -f1)

    case "$product" in
        php|phpmyadmin)
            # PHP EOL timeline: https://www.php.net/eol.php
            for eol_ver in 5.6 7.0 7.1 7.2 7.3 7.4 8.0; do
                [ "$major_minor" = "$eol_ver" ] && echo "[EOL] PHP ${version} — no security patches (EOL: 2023-11-26 for 8.0)"
            done
            ;;
        drupal)
            [ "$major" = "7" ] && echo "[EOL] Drupal 7 — end of life 2025-01-05 (extended support ended)"
            [ "$major" = "8" ] && echo "[EOL] Drupal 8 — end of life 2021-11-17"
            ;;
        wordpress)
            echo "[CHECK] WordPress ${version} — check https://wordpress.org/download/releases/ for EOL advisory"
            ;;
        nginx|openresty)
            [ "$major_minor" = "1.18" ] && echo "[CHECK] nginx ${major_minor} — verify mainline vs stable support status"
            ;;
        tomcat)
            [ "$major" -le 8 ] && echo "[EOL] Tomcat ${version} — Tomcat 8.x EOL: 2018-09-30, 9.x EOL: 2024-10-01"
            ;;
        node|nodejs)
            [ "$major" -le 16 ] && echo "[EOL] Node.js ${version} — v${major} reached EOL"
            ;;
        python)
            [ "$major_minor" = "2.7" ] && echo "[EOL] Python 2.7 — end of life 2020-01-01"
            [ "$major_minor" = "3.6" ] && echo "[EOL] Python 3.6 — end of life 2021-12-23"
            [ "$major_minor" = "3.7" ] && echo "[EOL] Python 3.7 — end of life 2023-06-27"
            ;;
        mariadb|mysql)
            [ "$major" -le 5 ] && echo "[EOL] MySQL/MariaDB ${version} — MySQL 5.x EOL"
            ;;
        *)
            echo "[INFO] No EOL data for ${product} ${version} — check vendor site"
            ;;
    esac
}

# Run EOL check on each detected product+version
whatweb "$TARGET" -v 2>/dev/null \
    | grep -oP '([A-Za-z][A-Za-z0-9_-]*)\s*\[?[0-9]+\.[0-9]+(\.[0-9]+)?\]?' \
    | while IFS= read -r line; do
        product=$(echo "$line" | grep -oP '^[A-Za-z][A-Za-z0-9_-]*' | tr '[:upper:]' '[:lower:]')
        version=$(echo "$line" | grep -oP '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
        [ -n "$product" ] && [ -n "$version" ] && eol_check "$product" "$version"
    done
```

### 8. Vulnerability Aggregation and Severity Sorting

Merge all findings into a single prioritized report: critical/high CVEs with
public exploits first, followed by high-severity without exploits, then
medium/low.

```bash
echo '=== Step 8: Vulnerability Aggregation ==='

python3 << 'PYEOF'
import json, glob, os, re

OUTDIR = "{}".format(os.environ.get('OUTDIR', os.path.expanduser('.')))
findings = []

# Collect Nuclei findings
for f in glob.glob(f"{OUTDIR}/nuclei_*.txt"):
    name = os.path.basename(f)
    with open(f) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            findings.append({
                "source": "nuclei",
                "tag": name.replace("nuclei_", "").replace(".txt", ""),
                "raw": line,
                "severity": "unknown"
            })

# Collect NVD results
for f in glob.glob(f"{OUTDIR}/nvd_*.json"):
    with open(f) as fh:
        try:
            data = json.load(fh)
            if isinstance(data, list):
                findings.extend(data)
            elif isinstance(data, dict):
                findings.append(data)
        except: pass

# Collect searchsploit results (parsed from text output)
ss_file = f"{OUTDIR}/searchsploit_results.txt"
if os.path.exists(ss_file):
    with open(ss_file) as fh:
        pass  # Text parsing depends on output format

# Prioritize by CVSS score
critical = [f for f in findings if isinstance(f, dict) and f.get('cvss') and f['cvss'] >= 9.0]
high = [f for f in findings if isinstance(f, dict) and f.get('cvss') and 7.0 <= f['cvss'] < 9.0]
medium = [f for f in findings if isinstance(f, dict) and f.get('cvss') and 4.0 <= f['cvss'] < 7.0]
low = [f for f in findings if isinstance(f, dict) and f.get('cvss') and f['cvss'] < 4.0]
unknown = [f for f in findings if isinstance(f, dict) and not f.get('cvss')]
nuclei_hits = [f for f in findings if f.get('source') == 'nuclei']

print("=== VULNERABILITY MAP (Prioritized) ===")
print(f"\n[CRITICAL] CVSS 9.0-10.0: {len(critical)} findings")
for f in critical[:10]:
    print(f"  {f.get('id','N/A')} | CVSS: {f.get('cvss','N/A')} | {f.get('description','')[:120]}")

print(f"\n[HIGH] CVSS 7.0-8.9: {len(high)} findings")
for f in high[:10]:
    print(f"  {f.get('id','N/A')} | CVSS: {f.get('cvss','N/A')} | {f.get('description','')[:120]}")

print(f"\n[MEDIUM] CVSS 4.0-6.9: {len(medium)} findings")
for f in medium[:5]:
    print(f"  {f.get('id','N/A')} | CVSS: {f.get('cvss','N/A')}")

print(f"\n[LOW] CVSS 0.0-3.9: {len(low)} findings")
print(f"\n[UNKNOWN CVSS]: {len(unknown)} findings")
print(f"\n[NUCLEI CONFIRMED]: {len(nuclei_hits)} findings")
PYEOF

echo ''
echo "=== Full results directory: $OUTDIR ==="
ls -la "$OUTDIR"
```

### 9. Pipeline into Exploitation

The output directory `vuln-map-<timestamp>/` contains structured data for
exploitation targeting:

| File | Purpose |
|------|---------|
| `all_cves.txt` | Unique CVE IDs for targeted exploitation |
| `nuclei_*.txt` | Nuclei-verified vulnerabilities per technology |
| `nvd_*.json` | NVD CVSS-scored CVE details |
| `osv_query.py` + output | OSV.dev ecosystem vulns |
| `headers.txt` | Raw response headers for manual review |
| `whatweb.json` | Full technology inventory |

**Pipeline into hunt skills:**
- Pass `all_cves.txt` to `hunt-cve` for targeted CVE exploitation
- High-severity CVEs with public exploits (from step 6) → immediate escalation
- EOL software → treat as unpatched; use generic version-based techniques
- Nuclei-verified CVEs → highest confidence; bypass verification step

```bash
# Example: feed into hunt skill
# hunt-cve --cves "$OUTDIR/all_cves.txt" --target "$TARGET"
# hunt-pub-sploit --priority "$OUTDIR/priority_targets.txt"
```

## OPSEC Rules

- **whatweb** emits 1 request — low noise. Add `--user-agent` to blend with
  normal traffic.
- **searchsploit** is entirely local (offline). Zero detection risk.
- **NVD API** calls go to `services.nvd.nist.gov` — NIST logs requests. Do not
  proxy through the target's network; run from your jump host.
- **OSV.dev API** calls go to `api.osv.dev` — Google logs requests. Low risk
  but tracked.
- **Nuclei CVE templates** send multiple probe payloads per vulnerability.
  Use `-rl 15` (rate-limit) and `-c 2` (concurrency) for covert ops. Each
  template is a detection event.
- **GitHub API** search for PoC repos — unauthenticated requests are
  rate-limited to 10/min. The search itself reveals intent, but correlates to
  your IP, not the target.
- **EOL checks** require no external network — all data is local.
- All vulnerability-lookup traffic originates from your scan host, not the
  target.
- For **stealth operations**: skip Nuclei entirely; use NVD + searchsploit
  only (passive).
- If using a **proxy chain** (`--proxy`), all outbound API calls must also
  route through it to avoid attribution leaks.

## Verification

- Confirm each CVE applies to the actual running version — version bumper may
  differ from runtime
- Cross-reference NVD with vendor advisory: NVD sometimes lists CVEs as
  affecting versions that have already been patched in backported distro builds
- For CMS plugins/themes (WordPress, Drupal, Joomla), verify the specific
  component is active — version in `readme.txt` does not mean it is loaded
- Check that the vulnerable endpoint is reachable (behind a reverse proxy? WAF?)
- Nuclei false positives are common — manually verify `curl` + custom payload
  before declaring a CVE confirmed
- For EOL software: confirm the exact version, then check the vendor changelog
  for any post-EOL security patches (rare but possible for paid-support tiers)
- Cross-source validation: a CVE found in NVD + Exploit-DB + Nuclei has
  highest confidence

## Pitfalls

- **Version bumper mismatch**: `Server: Apache/2.4.6` may be Red Hat's
  backported build with all patches applied — the version string is frozen at
  the original release while security fixes are backported. Check `yum info
  httpd` or `dpkg -l apache2` on the server.
- **CDN/WAF masking**: whatweb may report Cloudflare, Akamai, or AWS WAF
  instead of the origin server. Use origin IP discovery first.
- **NVD rate limits**: 5 requests per 30 seconds without an API key. Batch
  queries with jq or use the `/cve/:cveId` endpoint for individual lookups
  instead.
- **Nuclei template quality**: Community-contributed templates may have false
  positives, broken regex, or incorrect version matching. Always verify.
- **OSV.dev coverage**: Only covers open-source ecosystems. Proprietary
  software (Oracle, SAP, IBM) won't appear there — use NVD for those.
- **Exploit-DB staleness**: searchsploit is only as current as your last
  `searchsploit -u`. Schedule weekly updates.
- **GitHub PoC quality**: A repo with `CVE-202X-XXXX` in the name may be
  PoC-quality or just a scanner. Review before using.
- **EOL detection gaps**: EOL by major version may flag software that still
  receives paid/custom support (e.g., RHEL, Ubuntu LTS, Drupal 7 with
  third-party support).
- **Version overmatching**: A version string like `5.8.2` may match both a
  WordPress core CVE and a plugin CVE for the same version number — verify
  the vulnerable component path.
- **OSV batch size**: Max 1000 queries per batch request. For large inventories
  (monorepos), split into multiple batch calls.

## Output Format

```json
{
  "metadata": {
    "target": "https://target.com",
    "domain": "target.com",
    "scan_date": "2026-07-13T14:30:00Z",
    "tools_used": ["whatweb", "nuclei", "searchsploit", "nvd_api", "osv_api"],
    "total_cves_found": 14
  },
  "technologies": [
    {
      "name": "nginx",
      "version": "1.18.0",
      "source": "whatweb",
      "certainty": 100,
      "eol_status": "active",
      "cves": [
        {
          "id": "CVE-2021-23017",
          "cvss_v31": 6.5,
          "severity": "MEDIUM",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
          "epss": 0.0024,
          "description": "DNS resolution denial of service in nginx resolver",
          "exploit_available": false,
          "nuclei_confirmed": false,
          "sources": ["nvd"],
          "published": "2021-07-22"
        },
        {
          "id": "CVE-2021-3618",
          "cvss_v31": 5.9,
          "severity": "MEDIUM",
          "description": "ALPACA TLS attack affecting nginx",
          "exploit_available": false,
          "nuclei_confirmed": true,
          "sources": ["nvd", "nuclei"]
        }
      ]
    },
    {
      "name": "WordPress",
      "version": "5.8.2",
      "source": "whatweb",
      "certainty": 100,
      "eol_status": "active",
      "cves": [
        {
          "id": "CVE-2022-21661",
          "cvss_v31": 7.5,
          "severity": "HIGH",
          "description": "SQL injection via WP_Query",
          "exploit_available": true,
          "exploit_sources": {
            "searchsploit": true,
            "github_poc": true,
            "metasploit": false
          },
          "nuclei_confirmed": true,
          "sources": ["nvd", "nuclei", "searchsploit", "osv"],
          "published": "2022-01-06"
        }
      ]
    },
    {
      "name": "PHP",
      "version": "7.4.30",
      "source": "header",
      "certainty": 90,
      "eol_status": "eol",
      "eol_note": "PHP 7.4 reached end-of-life 2022-11-28",
      "cves": [
        {
          "id": "CVE-2022-31626",
          "cvss_v31": 7.5,
          "severity": "HIGH",
          "description": "Pool corruption in PHP's FPM",
          "exploit_available": false,
          "nuclei_confirmed": false,
          "sources": ["nvd"]
        }
      ]
    }
  ],
  "priority_targets": [
    {
      "cve_id": "CVE-2022-21661",
      "technology": "WordPress 5.8.2",
      "cvss": 7.5,
      "severity": "HIGH",
      "has_public_exploit": true,
      "confidence": "confirmed",
      "recommended_skill": "hunt-sqli",
      "risk_score": 8.2
    }
  ],
  "eol_findings": [
    {
      "product": "PHP",
      "version": "7.4.3",
      "status": "eol",
      "advisory": "PHP 7.4 reached end-of-life 2022-11-28 - upgrade to 8.x"
    }
  ],
  "summary": {
    "total_technologies": 3,
    "critical_cves": 0,
    "high_cves": 2,
    "medium_cves": 2,
    "low_cves": 0,
    "with_public_exploit": 1,
    "nuclei_verified": 2,
    "eol_products": 1,
    "estimated_exploitability_score": 7.4
  }
}
```

The JSON output is designed to be consumed by downstream exploitation skills:
- `hunt-sqli` — consumes `priority_targets` with CVE-mapped injection points
- `hunt-rce` — consumes CVEs tagged with public exploits in nginx, Apache, PHP
- `hunt-auth-bypass` — consumes authentication-related CVEs
- `hunt-pub-sploit` — directly takes the `priority_targets` array
