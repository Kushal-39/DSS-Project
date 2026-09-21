# Zero-Trust Request Execution Flow

This document details the step-by-step lifecycle of an execution request through the system.

## Lifecycle Steps

1. **Authentication (Person 1)**
   - Client sends credentials (`/login`) to the Identity Provider.
   - IdP validates credentials and returns a signed RS256 JWT containing `sub`, `roles`, and `device_id`.

2. **Ingress Filtering & Token Verification (Person 2)**
   - Client calls `POST /api/v1/payment` on the API Gateway with `Authorization: Bearer <token>`.
   - API Gateway fetches public keys from IdP (`/jwks.json`) to verify the JWT signature.
   - If invalid or expired, Gateway returns `401 Unauthorized`.

3. **Secure Forwarding via mTLS (Person 2 -> Person 4/5)**
   - API Gateway establishes an mTLS handshake with the targeted microservice using internal x509 certificates.
   - Gateway passes the JWT and appends the W3C trace header (`traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`).

4. **Policy Enforcement Check (Person 4/5 -> Person 3)**
   - Microservice intercepts the request and extracts JWT claims + request body details.
   - Microservice issues a synchronous `POST` request to the Policy Engine (`http://policy-engine:8181/v1/data/authz/allow`) with the payload wrapped in an `"input"` object per `docs/policymaker.md` (`subject` nested as an object with `user_id` and `roles`, plus `action`, `resource`, and `context` including `mTLS_verified`).
   - Policy Engine evaluates Attribute-Based Access Control (ABAC) rules and returns `{"result": {"allow": true}}` or `{"result": {"allow": false}}`.
   - If `result.allow` is anything other than `true`, Microservice immediately aborts and returns `403 Forbidden`.

5. **Inter-Service Execution (Person 4 -> Person 5)**
   - If Microservice A needs to invoke Microservice B (e.g., Account Service triggering Payment Service):
     - Establishes a secondary mTLS handshake.
     - Propagates the original `traceparent` and Bearer JWT token.
     - Microservice B re-evaluates policy with Person 3 before processing.

6. **Audit & Telemetry Export (Person 1, 2, 3, 4, 5 -> Person 6)**
   - Every component emits structured JSON logs and OpenTelemetry spans.
   - Access decisions (PERMIT/DENY) are logged asynchronously to Person 6's central logging pipeline for real-time threat monitoring.

