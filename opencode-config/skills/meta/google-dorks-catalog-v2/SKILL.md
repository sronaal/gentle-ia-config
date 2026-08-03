---
name: google-dorks-catalog-v2
description: "Trigger: dorks, Google dorks, OSINT dork, search operators. 160+ dork patterns organized by service type — cloud, IoT, APIs, CI/CD, LLM, databases."
license: Apache-2.0
metadata:
  author: "pentest-orchestrator"
  version: "2.0"
---

## Activation Contract

Load when the user needs Google dork queries for OSINT, wants to find exposed panels, sensitive files, cloud storage leaks, IoT device panels, or CI/CD pipeline exposure.

## Hard Rules

- Dorks are informational — do NOT execute against targets without scope clearance.
- Reference `assets/dorks.json` for the full catalog. This file is the source of truth.
- Test dork queries manually first — they may trigger Google's bot detection at scale.

## Decision Gates

| Category | Sub-types | Number of Dorks |
|----------|-----------|-----------------|
| Cloud storage | S3, GCS, Azure Blob, Firebase | 25 |
| LLM/AI | OpenAI, Ollama, HuggingFace, LM Studio | 20 |
| API Gateways | Kong, Apigee, AWS API GW, Traefik | 15 |
| IoT/Embedded | Routers, cameras, NAS, printers, SCADA | 20 |
| Databases | MongoDB, Elastic, Redis, MySQL, PG, CouchDB | 15 |
| CI/CD | GitHub Actions, GitLab CI, Jenkins, CircleCI | 10 |
| Kubernetes | kubeconfig, dashboard, etcd, manifests | 15 |
| Code Secrets | Tokens, passwords, API keys in repos | 20 |
| Serverless | Lambda, Cloud Functions, debug endpoints | 10 |
| Shadow IT | Notion, Trello, Asana, internal tools | 10 |
| **Total** | | **160+** |

## Execution Steps

1. **Select category**: Match target type to category in Decision Gates
2. **Load dorks**: Read `assets/dorks.json` → filter by category → select relevant dorks
3. **Customize**: Replace `example.com` with target domain in site: operators
4. **Execute**: Submit dork to Google search → collect results
5. **Validate**: Verify each result is truly exposed (not cached or irrelevant)
6. **Document**: Record URL, sensitivity, and potential impact

## Output Contract

Return results per tested dork:
- **dork**: The exact query used
- **category**: Which category it belongs to
- **results_count**: Approximate results from Google
- **valid_hits**: Verified exposed URLs with description
- **severity**: Critical / High / Medium / Info
- **impact**: What could be done with this exposure

## References

- `assets/dorks.json` — Full dork catalog with 160+ patterns
