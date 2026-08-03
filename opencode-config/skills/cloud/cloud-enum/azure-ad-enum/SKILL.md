---
name: azure-ad-enum
description: Enumerate Azure AD users, groups, service principals, and applications
version: 1.0.0
phase: cloud
category: enumeration
tags: [azure, azure-ad, entra-id, cloud]
tools: [az-cli, curl]
difficulty: advanced
opsec_level: active
time_estimate: 180s
severity_if_found: medium
related_skills:
  - cloud-provider-detect
  - azure-keyvault
mitre_attack:
  - T1087.004
  - T1524
---

## When to Use

Use this skill when Azure AD credentials are available to enumerate tenant
configuration, users, groups, service principals, and OAuth applications for
privilege escalation paths.

## Prerequisites

- az-cli authenticated to the target tenant
- Read permissions (Directory.Read.All, User.Read.All, or equivalent)

## Procedure

```bash
# Step 1: Get tenant information
az account show
az ad tenant list
az rest --method GET --uri "https://graph.microsoft.com/v1.0/tenantDetails"

# Step 2: Enumerate users
az ad user list --output table
az ad user list --query "[?userPrincipalName.contains(@,'admin')]" 
az ad user list --query "[?accountEnabled==true]"

# Step 3: Enumerate groups
az ad group list --output table
az ad group list --query "[?securityEnabled==true]"
az ad group list --query "[?mailEnabled==true]"

# Step 4: Enumerate service principals
az ad sp list --output table
az ad sp list --query "[?appRoleAssignmentRequired==false]"
az ad sp list --query "[?tags.contains(@,'WindowsAzureActiveDirectoryIntegratedApp')]"

# Step 5: Enumerate OAuth applications
az ad app list --output table
az ad app list --query "[?publicClient==null || publicClient==true]"
az ad app list --query "[?requiredResourceAccess[?resourceAppId!=null]]"

# Step 6: Check for privileged roles
az rest --method GET --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"

# Step 7: Check conditional access policies
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
```

## OPSEC Rules

- All Graph API calls are logged in Azure AD Audit Logs
- Use read-only enumeration — do not modify users, groups, or applications
- Avoid enumerating large tenants sequentially (rate limited)
- Respect 30 requests/minute throttling on Graph API

## Verification

- Confirm user objects resolve in the tenant
- Verify service principal permissions via manifest review
- Cross-reference Azure RBAC with Azure AD roles

## Pitfalls

- Guest users have limited query results
- Some properties require P1/P2 licenses to enumerate
- Dynamic groups do not show explicit membership
- Graph API pagination may require `$top` and `$skip` parameters

## Output Format

```
Tenant:     target.onmicrosoft.com (tenant-id: 550e8400-e29b-41d4-a716-446655440000)
Users:      247 total, 12 admins, 3 service accounts
Groups:     34 total, 8 security groups, 4 mail-enabled
SPNs:       156 service principals
Apps:       47 OAuth applications, 6 with publicClient=true
Privileged: Global Administrator — 3 users, 2 groups
Risk:       Global Admin group has 2 inactive members (6+ months)
```
