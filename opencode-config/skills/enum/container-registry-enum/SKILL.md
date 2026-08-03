---
name: container-registry-enum
description: Container registry enumeration for image discovery, anonymous pull, and vulnerability scanning
version: 1.0.0
phase: enum
category: container
tags: [container, docker, registry, kubernetes]
tools: [curl, crane, skopeo, docker]
difficulty: intermediate
opsec_level: medium
time_estimate: 60s
severity_if_found: high
related_skills:
  - docker-api
  - kubernetes-api
mitre_attack:
  - T1610
  - T1613
---

## When to Use

Use this skill when you discover a container registry (Docker Registry v2,
ECR, GCR, ACR, Harbor, or self-hosted) and want to enumerate repositories,
tags, and check for anonymous pull access.

## Prerequisites

- curl (for Registry API probing)
- crane (google/go-containerregistry)
- skopeo (for image inspection)
- docker (optional, for pulling images)

## Procedure

```bash
# Step 1: Check Registry v2 API
curl -sk https://TARGET/v2/
curl -sk https://TARGET/v2/_catalog

# Step 2: List repositories
curl -sk https://TARGET/v2/_catalog?n=100 | jq '.repositories[]'

# Step 3: List tags for each repository
for repo in $(curl -sk https://TARGET/v2/_catalog | jq -r '.repositories[]'); do
  echo "=== $repo ==="
  curl -sk "https://TARGET/v2/$repo/tags/list" | jq '.tags[]'
done

# Step 4: Pull image manifest (anonymous)
crane manifest TARGET/repo:tag --insecure 2>/dev/null
crane config TARGET/repo:tag --insecure 2>/dev/null | jq '.config'

# Step 5: Inspect image layers
crane manifest TARGET/repo:tag --insecure 2>/dev/null | jq '.layers[].digest'

# Step 6: Check for vulnerabilities (local)
skopeo inspect --tls-verify=false docker://TARGET/repo:tag | jq '.Labels'
docker pull TARGET/repo:tag 2>/dev/null && docker scout quickview TARGET/repo:tag

# Step 7: Check registry auth configuration
curl -sk https://TARGET/v2/ -v 2>&1 | grep -i "www-authenticate\|docker-distribution"
```

## OPSEC Rules

- Do NOT push images to discovered registries
- Do NOT delete tags or repositories
- Limit image pulls to 1-2 samples for analysis
- Do NOT exploit registry vulnerabilities (only enumerate)
- Log all API calls for audit trail

## Verification

- Confirm registry v2 API responds with available endpoints
- Verify repository listing returns real images
- Check if anonymous pull is possible (no auth header needed)

## Pitfalls

- Some registries require Bearer token auth via WWW-Authenticate
- ECR/GCR/ACR use cloud IAM — may require specific roles
- /v2/_catalog may be disabled in private registries
- crane may need --insecure for self-signed TLS certs

## Output Format

```
[REGISTRY] Host: TARGET:5000 — Docker Registry v2
[REGISTRY] Repos: app-backend, frontend-nginx, worker, redis-sidecar
[TAGS]    app-backend: latest, v1.2.3, v1.2.2, v1.1.0
[PULL]    Anonymous pull: ENABLED — images downloadable
[LAYER]   app-backend:latest — 12 layers, ~450MB
[ALERT]   base image: node:18-alpine — 3 critical CVEs (CVE-2024-XXXX)
[CRITICAL] Unauthenticated registry — all images and tags exposed
```
