---
name: aws-lambda-enum
description: Enumerate AWS Lambda functions, versions, and event sources
version: 1.0.0
phase: cloud
category: enumeration
tags: [aws, lambda, serverless, cloud]
tools: [aws-cli]
difficulty: advanced
opsec_level: active
time_estimate: 180s
severity_if_found: medium
related_skills:
  - cloud-provider-detect
  - aws-iam-privesc
mitre_attack:
  - T1525
  - T1613
---

## When to Use

Use this skill when AWS credentials are available (from token theft, instance
role, or compromise) to enumerate Lambda functions for privilege escalation
paths and sensitive data in environment variables.

## Prerequisites

- aws-cli configured with target account credentials
- Read-only IAM permissions (lambda:ListFunctions, lambda:GetFunction, lambda:ListEventSourceMappings)

## Procedure

```bash
# Step 1: List all Lambda functions (all regions)
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  aws lambda list-functions --region "$region" --output json 2>/dev/null
done

# Step 2: Get function details (code, config, tags)
aws lambda get-function --function-name <function-name> --region <region>
aws lambda get-function-configuration --function-name <function-name> --region <region>

# Step 3: List event source mappings (triggers)
aws lambda list-event-source-mappings --function-name <function-name> --region <region>

# Step 4: Check function policies for cross-account access
aws lambda get-policy --function-name <function-name> --region <region> 2>/dev/null | jq .

# Step 5: Download and inspect function code
aws lambda get-function --function-name <function-name> --region <region> --query 'Code.Location' --output text | xargs curl -s | tar -xz -C /tmp/lambda-code/

# Step 6: List Lambda layers
aws lambda list-layer-versions --layer-name <layer-name> --region <region>
aws lambda get-layer-version --layer-name <layer-name> --version-number <ver> --region <region>
```

## OPSEC Rules

- List operations (ListFunctions) are logged in CloudTrail
- GetFunction downloads the deployment package — expect detection
- Minimize regions scanned to those relevant to the target
- Do not invoke functions (that triggers execution logs)

## Verification

- Cross-reference function names with CloudFormation stacks
- Check environment variables for hardcoded secrets
- Inspect IAM role attached to each function

## Pitfalls

- Functions in a VPC may not be accessible from outside the VPC
- Lambda@Edge functions are in us-east-1 regardless of origin region
- Reserved concurrency limits may indicate critical functions
- Some functions use container images (response is different from ZIP)

## Output Format

```
Function:  process-payments (us-east-1)
Runtime:   nodejs18.x
Role:      arn:aws:iam::123456789012:role/payment-processor
Env Vars:  STRIPE_KEY=sk_live_***partial***, DB_URL=jdbc:postgresql://...
Triggers:  SQS (payment-queue), API Gateway (POST /payments)
Layers:    lambda-layer-secrets (v3)
Code:      Downloaded — contains vendor-secrets.js
Severity:  MEDIUM — environment variable with partial secret exposure
```
