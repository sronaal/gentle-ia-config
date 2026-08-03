---
name: serverless-recon
description: Discover serverless functions across cloud providers
version: 1.0.0
phase: recon
category: discovery
tags: [serverless, lambda, functions, cloud]
tools: [curl, dig, nuclei]
difficulty: medium
opsec_level: passive
time_estimate: 120s
severity_if_found: info
related_skills:
  - cloud-provider-detect
  - aws-lambda-enum
  - subdomain-discovery
mitre_attack:
  - T1595.001
  - T1590.002
---

## When to Use

Use this skill during the recon phase to discover serverless function endpoints across AWS Lambda (function URLs, API Gateway), Azure Functions, and GCP Cloud Functions. Serverless functions often expose undocumented APIs, debug endpoints, and staging environments.

## Prerequisites

- Target domain or subdomain list
- curl and dig installed
- nuclei (optional, for function URL detection templates)
- Basic understanding of cloud provider function URL patterns

## Procedure

1. Discover AWS Lambda Function URLs:
   ```bash
   # AWS Lambda function URL format: https://<random-id>.lambda-url.<region>.on.aws/
   for region in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-central-1; do
     dig +short "lambda-url.$region.on.aws" | head -1
   done
   
   # Check for API Gateway endpoints
   curl -sk "https://{target}/api/" | grep -i "lambda\|function\|arn:aws" | head -10
   
   # Scan subdomains for serverless patterns
   for sub in api-func func lambda fn serverless exec handler; do
     curl -sk -o /dev/null -w "%{http_code} %{url_effective}\n" "https://$sub.{target}/"
   done
   
   # Test for exposed Lambda function URLs by ID pattern
   curl -sk -o /dev/null -w "%{http_code}\n" "https://{target}/prod/function"
   curl -sk -o /dev/null -w "%{http_code}\n" "https://{target}/default/function"
   ```

2. Discover Azure Functions endpoints:
   ```bash
   # Azure Function format: https://<app>.azurewebsites.net/api/<func>
   curl -sk "https://{target}.azurewebsites.net/api/" 2>&1 | grep -i "function\|api"
   
   # Probe for Azure Functions admin endpoint
   curl -sk "https://{target}.azurewebsites.net/admin/functions" 2>&1 | grep -i "function\|keys"
   
   # Scan for common Azure Functions subdomains
   for sub in api-func func-app fn-app serverless function-app; do
     curl -sk "https://$sub.azurewebsites.net/" | grep -i "azure\|function\|api"
   done
   
   # Check for function key exposure in HTML/JS source
   curl -sk "https://{target}/" | grep -iE "x-functions-key|code=|_master"
   ```

3. Discover GCP Cloud Functions:
   ```bash
   # GCP Cloud Function format: https://<region>-<project>.cloudfunctions.net/<name>
   for region in us-central1 us-east1 europe-west1; do
     curl -sk "https://$region-{project}.cloudfunctions.net/" | grep -i "function\|cloud"
   done
   
   # Try common function names
   for func in hello api webhook process handler auth login callback; do
     curl -sk "https://us-central1-{project}.cloudfunctions.net/$func" | grep -i "function\|response\|hello"
   done
   
   # Check for gen2 Cloud Functions (Cloud Run-based)
   curl -sk "https://{func}-{hash}-$region.a.run.app" | grep -i "cloud\|function"
   ```

4. Scan with nuclei for serverless exposure:
   ```bash
   # Use nuclei serverless templates
   nuclei -target "https://{target}" -tags serverless,lambda,cloud-function -silent
   ```

5. Identify API Gateway-backed endpoints:
   ```bash
   # Common serverless API patterns
   curl -sk "https://{target}/v1/" | grep -i "lambda\|stage\|prod\|staging"
   curl -sk "https://{target}/api/v1/functions" 2>&1
   
   # Check for CloudFront + Lambda@Edge origins
   dig +short {target} | while read ip; do
     nslookup $ip | grep -i "cloudfront\|lambda"
   done 2>/dev/null
   ```

6. Detect function metadata exposure:
   ```bash
   # Check for /debug endpoints
   for path in /debug /info /health /_debug /status /__/info; do
     curl -sk "https://{target}$path" | grep -iE "runtime|region|function|memory|timeout"
   done
   ```

## OPSEC Rules

- Passive DNS and HTTP queries only — no direct cloud provider API calls
- Do not invoke serverless functions beyond the initial HTTP probe
- Rate-limit subdomain scans to 5 requests/second per provider region
- Document every serverless endpoint discovered with HTTP response codes
- Do not extract or decrypt environment variables from function responses
- Avoid sending payloads that would trigger function execution (billing risk)

## Verification

- Verify serverless endpoints by matching response patterns to known cloud provider signatures
- Cross-check Azure Functions by the x-azure-ref response header
- Validate AWS Lambda by the x-amzn-requestid response header
- Confirm GCP Cloud Functions by the x-cloud-trace-context header
- Check if exposed endpoints return 200 (public) vs. 403 (authorization required)

## Pitfalls

- Cloud provider function URLs are NOT discoverable via DNS brute force — random IDs prevent enumeration
- AWS Lambda function URLs require IAM auth by default — most return 403 without proper credentials
- Azure Functions scale on demand — the first request is slower (cold start) but function is public
- GCP Cloud Functions URLs contain project IDs which can be found via other recon techniques
- Serverless functions behind API Gateway or CloudFront may mask the underlying architecture
- Many serverless endpoints return 404/403 without meaningful error messages (security by obscurity)
- Cold starts affect response timing — slow first response may indicate a serverless backend

## Output Format

```
[SERVERLESS] Exposed Azure Function
  Endpoint: https://{target}.azurewebsites.net/api/users
  Method: GET
  Response: 200 OK — JSON array with user data
  Provider: Azure Functions
  Severity: INFO
  Evidence: x-azure-ref header present, /api/ path pattern, JSON response
```
