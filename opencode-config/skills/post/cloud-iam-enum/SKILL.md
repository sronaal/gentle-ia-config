---
name: cloud-iam-enum
description: Enumerate cloud IAM permissions and identify excessive access
version: 1.0.0
phase: post
category: post-exploitation
tags: [cloud, aws, gcp, azure, iam, enumeration]
tools: [aws, gcloud, az]
difficulty: intermediate
opsec_level: medium
time_estimate: 5m
severity_if_found: high
related_skills:
  - credential-harvest
  - lateral-movement
mitre_attack:
  - T1078.004
  - T1580
---

## When to Use

Use this skill after gaining access to cloud credentials (CLI keys, service
accounts, instance profiles) to enumerate IAM permissions and identify
excessive privileges or abuse paths.

## Prerequisites

- Cloud CLI tools installed (aws, gcloud, az)
- Valid credentials configured (access keys, service account, managed identity)
- Network access to cloud API endpoints

## Procedure

```bash
# ── AWS ──────────────────────────────────────────────
# Check current identity
aws sts get-caller-identity

# Enumerate attached policies
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity | jq -r '.Arn' | cut -d/ -f2)
aws iam list-attached-role-policies --role-name ROLE_NAME

# List all roles and check for cross-account access
aws iam list-roles --query 'Roles[*].[Arn,AssumeRolePolicyDocument]' --output table

# Check for overly permissive policies
aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn]' --output table

# Enumerate S3 buckets (data exposure)
aws s3 ls

# Check for publicly accessible resources
aws s3api get-bucket-acl --bucket BUCKET_NAME

# ── GCP ──────────────────────────────────────────────
gcloud auth list
gcloud projects get-iam-policy PROJECT_ID --format=json
gcloud iam service-accounts list --project=PROJECT_ID
gcloud compute instances list

# ── AZURE ────────────────────────────────────────────
az account show
az role assignment list --scope /subscriptions/SUB_ID --output table
az account list --output table
az keyvault list --output table
```

## OPSEC Rules

- Do not modify IAM policies or create new principals
- Do not exfiltrate secrets from metadata or key vaults
- Document excessive permissions but do not exploit them during assessment
- Limit API calls to enumeration only
- Check rate limits before batch operations

## Verification

- Confirm identity and permission boundaries
- Map all discoverable roles and policies
- Identify privilege escalation paths (e.g., iam:PassRole)
- Document cross-account or cross-tenant access

## Pitfalls

- CloudTrail / Audit Logs will record all API calls
- Some APIs require elevated permissions not present in current role
- Service account keys may be rotated during assessment
- Azure RBAC evaluations can be complex with nested scopes
- GCP org policies may restrict enumeration

## Output Format

```
[IAM] Excessive permissions found
  Cloud: AWS
  Identity: arn:aws:iam::123456789012:role/web-app-role
  Permissions: s3:*, iam:*, sts:AssumeRole
  Risk: Cross-account takeover possible
  Severity: HIGH

[IAM] Service account with user-managed key
  Cloud: GCP
  SA: compromised@project.iam.gserviceaccount.com
  Key age: 180 days (never rotated)
  Severity: HIGH
```
