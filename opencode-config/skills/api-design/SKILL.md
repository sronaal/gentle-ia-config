---
name: api-design
description: "Trigger: OpenAPI, REST API, GraphQL, endpoint design, API contract, schema design. Design consistent APIs: endpoints, schemas, errors, versioning, and contract-first documentation."
license: Apache-2.0
metadata:
  author: gentleman-programming
  version: "1.0"
---

## Activation Contract

Load this skill when designing new API endpoints, reviewing API contracts, writing OpenAPI/Swagger specs, defining GraphQL schemas, setting up API versioning, or standardizing error responses across a service.

## Hard Rules

- Every endpoint must return consistent error shapes. Use RFC 9457 (Problem Details) or a team-level error contract — never ad-hoc per route.
- Use plural nouns for collection resources (`/users`, not `/user`). Nest under the parent resource (`/users/:id/orders`).
- HTTP methods must match semantics: GET is read-only, POST creates, PUT replaces, PATCH partial update, DELETE removes.
- Version the API through the URL prefix (`/v1/`) or the `Accept` header — never through a query parameter.
- OpenAPI schemas must use `$ref` for shared components; do not inline the same model in multiple endpoints.
- Responses must include `Cache-Control`, `ETag`, or `Last-Modified` on GET endpoints unless the data is dynamic per-request.

## Decision Gates

| Decision | Recommendation |
|---|---|
| Protocol | REST for CRUD-heavy APIs; GraphQL for aggregated/flexible queries from multiple clients |
| Naming | Resources are nouns, not verbs (`/orders`, not `/getOrders`). Actions are sub-resources or custom verbs (`/orders/:id/cancel`) |
| Pagination | Cursor-based for lists that grow unbounded; offset+limit for stable, bounded collections |
| Error format | RFC 9457 Problem Details: `type`, `title`, `status`, `detail`, `instance` |
| Auth method | Bearer JWT for service-to-service; OAuth 2.0 for third-party; API keys for public SDKs |
| Idempotency | POST to creation endpoints must support `Idempotency-Key` header when the client may retry |

## Execution Steps

1. Identify all resources and their relationships. Map endpoints to operations.
2. Define the error contract first — every endpoint inherits it.
3. Write the OpenAPI/GraphQL schema: models, request bodies, response shapes, query parameters.
4. Validate the schema: run `redocly lint` or `spectral lint` on OpenAPI files.
5. Add pagination, filtering, sorting, and field selection where collections are returned.
6. Review naming against the resource map — no endpoints with verbs as resource names.
7. Generate server stubs or type definitions from the schema contract.

## Output Contract

Return: endpoint map (resource → methods → paths), OpenAPI snippet or full schema, error contract with examples, and any lint warnings. For changes to existing APIs, include a diff showing what moved, was renamed, or was removed.

## References

- RFC 9457 Problem Details: <https://www.rfc-editor.org/rfc/rfc9457>
