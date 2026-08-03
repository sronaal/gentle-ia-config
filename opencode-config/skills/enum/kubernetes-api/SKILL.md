---
name: kubernetes-api
description: Kubernetes API server enumeration and exposure check
version: 1.0.0
phase: enum
category: infrastructure
tags: [kubernetes, k8s, api, containers]
tools: [curl, kubectl]
difficulty: intermediate
opsec_level: high
time_estimate: 60s
severity_if_found: critical
related_skills:
  - docker-api
  - cloud-storage
mitre_attack:
  - T1610
  - T1613
---

## When to Use

Use this skill when you suspect a Kubernetes API server is exposed externally
or accessible from the network without proper authentication.

## Prerequisites

- curl
- kubectl (optional, for authenticated access)

## Procedure

```bash
# Step 1: Check if K8s API is listening
curl -sk https://TARGET:6443/healthz
curl -sk https://TARGET:6443/version

# Step 2: List API resources (unauthenticated)
curl -sk https://TARGET:6443/api/v1
curl -sk https://TARGET:6443/apis

# Step 3: Enumerate namespaces
curl -sk https://TARGET:6443/api/v1/namespaces | jq '.items[].metadata.name'

# Step 4: List pods in each namespace
curl -sk https://TARGET:6443/api/v1/namespaces/default/pods | jq '.items[].metadata.name'
curl -sk https://TARGET:6443/api/v1/namespaces/kube-system/pods | jq '.items[].metadata.name'

# Step 5: Check for secrets
curl -sk https://TARGET:6443/api/v1/namespaces/default/secrets | jq '.items[].metadata.name'

# Step 6: List services and endpoints
curl -sk https://TARGET:6443/api/v1/namespaces/default/services | jq '.items[].metadata.name'
curl -sk https://TARGET:6443/api/v1/namespaces/default/endpoints | jq '.items[].metadata.name'

# Step 7: kubectl (if token available)
kubectl --server=https://TARGET:6443 --token=TOKEN get pods --all-namespaces
kubectl --server=https://TARGET:6443 --token=TOKEN get secrets --all-namespaces
```

## OPSEC Rules

- Do NOT brute-force tokens or certificates
- Limit API calls to 10 per second
- Do not modify or delete any resources
- Log all requests but never expose secrets in logs
- Stop immediately if RBAC blocks access

## Verification

- Confirm `/healthz` returns `ok`
- Verify namespace listing returns real data
- Check if secrets endpoint is accessible without auth

## Pitfalls

- TLS cert may be self-signed — use `-k`
- Some endpoints require RBAC authorization
- kubelet API (10250) is separate from API server (6443)
- Production clusters should have auth disabled externally

## Output Format

```
[K8S]     API Server: 6443 — version: v1.27.3
[K8S]     Namespaces: default, kube-system, monitoring
[K8S]     Pods: nginx-7f8b6, postgres-5c4d2, redis-3a1b7
[SECRET]  default/secrets: db-credentials, api-key
[CRITICAL] Unauthenticated access to K8s API confirmed
```
