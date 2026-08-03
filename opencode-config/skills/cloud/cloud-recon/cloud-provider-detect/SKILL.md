---
name: cloud-provider-detect
description: Detect cloud provider (AWS, Azure, GCP) from target IP, DNS, or HTTP headers
version: 1.0.0
phase: cloud
category: discovery
tags: [cloud, aws, azure, gcp, provider-detect]
tools: [dig, curl, whois]
difficulty: basic
opsec_level: passive
time_estimate: 30s
severity_if_found: info
related_skills:
  - cloud-metadata
mitre_attack:
  - T1590.002
  - T1596.001
---

## When to Use

Use this skill during the cloud phase to identify which cloud provider hosts the
target infrastructure. Provider detection guides subsequent cloud-specific
enumeration (S3, Blob, Lambda, etc.).

## Prerequisites

- dig (dnsutils/bind-utils)
- curl
- whois

## Procedure

```bash
# Step 1: Check DNS for cloud indicators
dig +short <target> | head -5

# Step 2: Reverse DNS for cloud hostname patterns
dig +short -x <ip-address>

# Step 3: WHOIS for ASN and cloud provider
whois <ip-address> | grep -iE "aws|amazon|azure|microsoft|gcp|google" | head -10

# Step 4: Check HTTP response headers
curl -sI https://<target> | grep -iE "x-amz|x-azure|x-gcs|server|via|x-powered-by"

# Step 5: Check known cloud IP ranges
for range in "54.239.0.0" "13.64.0.0" "35.184.0.0"; do
  if echo "<ip-address>" | grep -q "$range"; then
    echo "Match: $range"
  fi
done
```

## OPSEC Rules

- Passive queries only — no direct access to target services
- WHOIS queries are logged by registrars but are standard recon
- DNS queries resolve through public resolvers (no direct target DNS)
- Rate limit DNS queries to 2/second to avoid resolver throttling

## Verification

- Cross-check provider across multiple sources (DNS + WHOIS + headers)
- Verify ASN ownership on bgp.he.net
- Confirm with cloud-specific endpoint probes

## Pitfalls

- CDNs (Cloudflare, Akamai) may mask the origin provider
- Targets behind a load balancer may show different providers per region
- WHOIS data can be stale or redacted
- Some targets use multi-cloud deployments

## Output Format

```
Provider: aws
Evidence:
  ASN:      AS16509 (Amazon.com, Inc.)
  DNS:      ec2-54-239-0-0.compute-1.amazonaws.com
  Header:   Server: CloudFront
Confidence: high
```
