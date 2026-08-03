---
name: k8s-rbac-deep
description: Deep Kubernetes RBAC audit for ClusterRoles, RoleBindings, ServiceAccounts, and overly permissive access
version: 1.0.0
phase: enum
category: container
tags: [kubernetes, k8s, rbac, auth]
tools: [kubectl, kube-hunter, kubeaudit]
difficulty: intermediate
opsec_level: medium
time_estimate: 120s
severity_if_found: critical
related_skills:
  - kubernetes-api
  - container-registry-enum
mitre_attack:
  - T1610
  - T1613
  - T1526
---

## When to Use

Use this skill when you have Kubernetes API access (via kubeconfig, service
account token, or API proxy) and want to audit RBAC configurations for
overly permissive roles, risky bindings, and excessive ServiceAccount
privileges.

## Prerequisites

- kubectl (with cluster access or token)
- kube-hunter (optional, for automated K8s security scanning)
- kubeaudit (optional, for RBAC-specific audit)

## Procedure

```bash
# Step 1: Check current permissions
kubectl auth can-i --list
kubectl auth can-i create pods --all-namespaces
kubectl auth can-i get secrets --all-namespaces

# Step 2: List namespaces and pods
kubectl get namespaces
kubectl get pods --all-namespaces -o wide

# Step 3: Enumerate ClusterRoles
kubectl get clusterroles -o wide | head -30
kubectl get clusterrolebinding -o wide | head -30

# Step 4: Check for dangerous RBAC rules
for role in $(kubectl get clusterroles -o name); do
  echo "=== $role ==="
  kubectl get "$role" -o yaml | grep -A5 -E "verbs:|resources:" | grep -E "create|update|patch|delete|\*|impersonate|escalate"
done

# Step 5: List RoleBindings in each namespace
for ns in $(kubectl get namespaces -o name | cut -d/ -f2); do
  echo "=== $ns ==="
  kubectl get rolebindings -n "$ns" -o wide
done

# Step 6: Enumerate ServiceAccounts
kubectl get serviceaccounts --all-namespaces
kubectl get serviceaccounts --all-namespaces -o yaml | grep -E "secrets:|name:" | head -40

# Step 7: Check for secrets access
for ns in $(kubectl get namespaces -o name | cut -d/ -f2); do
  kubectl get secrets -n "$ns" 2>/dev/null
done

# Step 8: kube-hunter automated scan
kube-hunter --remote TARGET 2>/dev/null || true
kubeaudit rbac --all-namespaces 2>/dev/null || true
```

## OPSEC Rules

- Do NOT create or modify any RBAC resources
- Do NOT create pods, secrets, or any other resources
- Do NOT attempt privilege escalation (report it)
- Limit API calls to avoid rate limiting or detection
- Log all RBAC findings for audit trail

## Verification

- Confirm current user's permissions via `auth can-i --list`
- Verify ClusterRoles with wildcard or dangerous verbs
- Check if secrets are accessible in any namespace

## Pitfalls

- Large clusters may have hundreds of roles — filter by relevance
- kube-hunter scanning may trigger alerts on production clusters
- K8s 1.24+ no longer auto-creates secrets for ServiceAccounts
- Anonymous API access may be restricted by webhook auth

## Output Format

```
[K8S]     API Server: TARGET:6443 — version: v1.28.2
[K8S]     Namespaces: default, kube-system, monitoring, production
[AUTH]    Current access: cluster-admin (full admin)
[RBAC]    cluster-admin — FULL ACCESS (bound to user: admin)
[RBAC]    view — READ-ONLY (bound to monitoring ServiceAccount)
[RISK]    production/default — can create pods, exec into containers
[RISK]    kube-system/controller — can get secrets (token, db-cred)
[CRITICAL] cluster-admin role bound to service account — full cluster compromise
```
