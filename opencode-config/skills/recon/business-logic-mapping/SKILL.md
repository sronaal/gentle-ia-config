---
name: business-logic-mapping
description: Map business logic workflows — user journey enumeration, state machine discovery, role/permission matrix mapping, and critical function identification
version: 1.0.0
phase: recon
category: reconnaissance
tags: [business-logic, workflow, mapping, enumeration]
tools: [burp, python3, httpx, katana]
difficulty: advanced
opsec_level: medium
time_estimate: 90m
severity_if_found: medium
mitre_attack:
  - T1040
  - T1082
---

## When to Use

- Authenticated access to an application with multi-step workflows
- Different user roles exist (user, manager, admin, superadmin)
- Financial operations in scope (pricing, discounts, checkout, refunds)
- Privilege escalation or business logic bypass is a stated objective
- Multi-tenant authorization or complex state transitions (draft→review→published)
- Any engagement where "the logic is the vulnerability" — behavioral flaws over technical bugs

## What It Does

Maps the full business logic attack surface of a web application. This is not a technical vulnerability scan — it's a behavioral and architectural recon of how the application's business rules can be subverted:

- **User journey mapping** — traces complete flows from registration→payment→fulfillment, identifying each step, branching point, and skip possibility
- **Role hierarchy enumeration** — identifies all user roles, their permission matrices, and privilege escalation paths between them
- **Workflow state machine discovery** — maps every state transition (draft→review→published) and tests for unauthorized transitions
- **Multi-step form identification** — discovers wizards and multi-page forms where step-skip or replay may bypass validation
- **Critical function endpoint discovery** — locates privileged functions (user impersonation, refunds, role changes, data export)
- **Privilege boundary mapping** — documents which API endpoints differentiate admin vs user vs anonymous access
- **Financial flow analysis** — enumerates pricing endpoints, discount application, checkout logic, and payment gateway interactions
- **Vertical/horizontal privilege boundary identification** — maps which resources are scoped to users vs accessible cross-tenant

## Methodology

### Step 1: Pre-Mapping Recon
```bash
# Crawl with authenticated sessions to capture full state space
katana -u $TARGET -H "Cookie: $SESSION" -d 5 -jc -o urls.txt
httpx -l urls.txt -mc 200,201,202 -status-code -content-length -tech-detect -o live.txt
# Categorize endpoints by path depth
cat urls.txt | awk -F/ '{print $NF}' | sort | uniq -c | sort -rn > endpoint_types.txt
```

### Step 2: User Journey Mapping

For every complete user journey, document each step as a state transition and test boundary conditions:

```
Journey: Checkout
  Cart → POST /api/cart/add → Cart-Updated
  Cart-Updated → GET /checkout → Checkout-Form
  Checkout-Form → POST /checkout/submit → Order-Created
  Order-Created → POST /payment/charge → Payment-Pending
  Payment-Pending → GET /payment/confirm/{id} → Confirmed (Terminal)
```

**Key tests per journey**: Can steps be skipped? (checkout without cart items). Can steps be replayed? (double charge on payment callback resubmit). Are state transitions enforced server-side or only in the UI? What happens at step 4 without completing step 3? (inconsistent state, logic gap). Are there side effects on replay? (duplicate orders, double charges).

### Step 3: Role Hierarchy & Permission Matrix
```bash
# Crawl as each role, diff the accessible URL sets to find divergence
katana -u $TARGET -H "Cookie: $USER_COOKIE" -d 3 -o user_urls.txt
katana -u $TARGET -H "Cookie: $ADMIN_COOKIE" -d 3 -o admin_urls.txt
diff <(sort user_urls.txt) <(sort admin_urls.txt) | grep '^>'
```
**High-value role endpoints**: `/api/users`, `/api/roles`, `/api/admin/*`, `/impersonate`, `/sudo`, `/switch-user`, `/export`, `/bulk`, `/config`, `/feature-flags`. Any endpoint accessible to admin but not user is a privilege boundary.

### Step 4: Workflow State Machine Testing

For each stateful resource, document valid transitions and test edge cases:
```
Document: draft → under_review → approved → published
                     ↓
                 rejected → draft
```
**Test unauthorized transitions**: `draft→published` (skip review), `draft→approved` (skip both), `rejected→published` (bypass correction). Try each transition with another user's resource ID (horizontal privilege). If the server accepts an impossible state transition, you have a state machine bypass — report as high severity.

**State parameter fuzzing**: When you see status/state in requests, try `PUT /api/documents/{id}` with `{ status: "published" }` directly, or `{ status: "approved", reviewedBy: "self" }`.

### Step 5: Privilege Boundary Mapping
```python
import requests
ENDPOINTS = [
    {'path': '/api/profile', 'method': 'GET'},
    {'path': '/api/admin/users', 'method': 'GET'},
    {'path': '/api/export/users.csv', 'method': 'GET'},
    {'path': '/api/impersonate/2', 'method': 'POST'},
    {'path': '/api/orders/1/cancel', 'method': 'POST'},
    {'path': '/api/config', 'method': 'GET'},
]
def test(base, cookies, role):
    for ep in ENDPOINTS:
        r = getattr(requests, ep['method'].lower())(f"{base}{ep['path']}", cookies=cookies, timeout=5)
        print(f"[{role}] {ep['method']} {ep['path']} → {r.status_code} ({len(r.text)}b)")
```
Divergence points (admin gets 200, user gets 403/404) are the authorization boundary. Also test with no auth to establish the anonymous baseline.

### Step 6: Financial Flow Analysis
```bash
grep -iE '(price|cost|discount|coupon|promo|checkout|payment|refund|subscription|billing|invoice|tax)' urls.txt
```
**Attack patterns to test**:
- **Price manipulation**: Change `amount: 9999` to `amount: 1` in checkout/charge requests
- **Quantity overflow**: Set `quantity: -1` or `quantity: 999999` — tests for integer handling flaws
- **Currency arbitrage**: Change `currency: USD` to `currency: IRR` (weakest rate) — test for exchange rate manipulation
- **Coupon stacking**: Apply multiple promo codes where the backend should enforce one per order
- **Payment callback replay**: Replay the webhook notification after refund to trigger double credit
- **Rounding abuse**: Set `quantity: 3` with 33.33% discount — test for $0.01 rounding accumulation
- **Race condition**: Send two checkout requests with the same cart ID simultaneously

### Step 7: Multi-Tenant & Horizontal Privilege Mapping
```bash
grep -oP '(org|account|company|team|workspace|tenant)_?id[=:][a-zA-Z0-9]+' urls.txt | sort -u
# Sequential ID enumeration across tenant boundary
for id in $(seq 1 100); do
  status=$(curl -s -o /dev/null -w "%{http_code}" -H "Cookie: $SESSION" "https://TARGET.COM/api/orders/$id")
  echo "Order $id: HTTP $status"
done
```

### Step 8: Gap Analysis

Document each logic gap with reproduction steps:

| Gap Type | Example | Impact |
|----------|---------|--------|
| Missing precondition | GET /checkout with empty cart → 200 | Logic bypass |
| Horizontal IDOR | PUT /api/documents/5/approve when doc 5 belongs to another user | Data access |
| Replay | POST /api/payment/confirm resubmission → double charge | Financial loss |
| Role confusion | Change X-Role: admin header → admin access | Privilege escalation |
| State skip | PATCH /api/document/5 { status: "published" } from draft | Bypass review |

## Detection & OPSEC

**Triggers**: Sequential endpoint access in non-normal patterns, accessing step N+1 without step N, cookie swapping across sessions, parallel sessions from same IP with different user roles, sequential ID enumeration (1000 requests in 5 minutes), repeated parameter tampering on price/discount fields, "impossible" state transitions in logs.

**Countermeasures**: Use separate browser profiles per role. Add human delays (1-5s) between workflow steps. Never jump directly to step 3 — traverse steps 1-2 first with realistic timing. Spread ID enumeration to ~50/hr. Blend logic tests with normal browsing traffic. Use multiple accounts for exploration vs exploitation — never test exploitation with your exploration account.

**Evidence**: Flowchart diagrams per journey. HAR API call sequences. Role permission matrix (admin vs user vs anonymous). State transition tables with tested transitions. Financial flow diagram (pricing→discount→checkout→payment→refund). Gap analysis with curl reproduction steps. Split-tunnel request/response pairs showing the exploit.

## References

- [OWASP Business Logic Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README)
- [OWASP Business Logic Flaws](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)
- [PortSwigger Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
- [Business Logic Attack Payloads](https://github.com/payloadbox/business-logic-attack-payloads)
- [MITRE T1040 — Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [MITRE T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)
