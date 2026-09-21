#### Member Responsibilities

* **Person 1: Identity & Token Authority (IdP)**
* **Responsibilities:** Deploy the Identity Provider (Keycloak, Dex, or a lightweight Go/Python OAuth2 server). Generate RSA keypairs for signing RS256 JWTs. Issue tokens containing user roles, device IDs, and context claims.


* **Deliverable:** A running auth service exposing standard OpenID Connect endpoints (`/.well-known/openid-configuration`, `/token`, `/jwks.json`).




* **Person 2: API Gateway & Perimeter Ingress**
* **Responsibilities:** Build or configure the gateway entry point (e.g., Go reverse proxy, Kong, or Spring Cloud Gateway). Intercept incoming public traffic, validate incoming JWT signatures using Person 1's JWKS endpoint, enforce global rate-limiting, and attach context headers.


* **Deliverable:** Reverse proxy routing requests to internal services over mutual TLS.




* **Person 3: Policy Engine & ABAC Evaluator**
* **Responsibilities:** Implement fine-grained Attribute-Based Access Control (ABAC) using Open Policy Agent (OPA) or a custom policy server. Write policy rules that evaluate user roles, action types, requested resource context, and threat levels.


* **Deliverable:** A centralized REST/gRPC policy endpoint that receives context JSON and returns a simple `{"allow": true/false}` decision.




* **Person 4: Microservice A (Account Service)**
* **Responsibilities:** Build a lightweight backend service (e.g., Python FastAPI or Go) handling account management. Enforce mandatory mTLS on incoming connections. Intercept incoming calls, forward context to Person 3's Policy Engine before executing business logic, and propagate tracing headers.


* **Deliverable:** Account microservice with integrated policy check middleware and mTLS server certificates.




* **Person 5: Microservice B (Payment & Transaction Service)**
* **Responsibilities:** Build the downstream financial transaction service. Validate client certificates on every incoming connection from Microservice A or the API Gateway. Re-verify policy decisions via Person 3's engine for high-risk transaction actions.


* **Deliverable:** Payment microservice with strict mTLS enforcement and internal gRPC/HTTP API endpoints.




* **Person 6: Observability, Distributed Tracing & Centralized Logging**
* **Responsibilities:** Deploy centralized log ingestion (ELK/Loki) and distributed tracing (Jaeger/Zipkin via OpenTelemetry). Build a central audit logging consumer that ingests security decision logs from the API Gateway, Microservices, and Policy Engine.


* **Deliverable:** Telemetry receiver and audit dashboard tracking blocked requests, unauthorized access attempts, and trace flows across all components.

---

#### Component Integration Interfaces

To avoid integration bottlenecks during development, everyone must strictly adhere to three global interfaces from Day 1:

1. **Auth Contract:** Standard `Authorization: Bearer <JWT>` HTTP header.


2. **Transport Contract:** Internal service-to-service communication uses TLS 1.3 with mutual certificate verification (mTLS) using a shared local self-signed Certificate Authority (CA).


3. **Policy Request Contract:** Every microservice queries the Policy Engine via `POST http://policy-engine:8181/v1/data/authz/allow` with this standard payload structure (canonical format defined in `docs/policymaker.md` — copy it exactly):


```json
{
  "input": {
    "subject": {
      "user_id": "uuid-string-from-jwt",
      "roles": ["customer"]
    },
    "action": "TRANSFER",
    "resource": "account_987",
    "context": {
      "amount": 50.00,
      "ip_address": "192.168.1.50",
      "mTLS_verified": true
    }
  }
}
```

> **WARNING: The Policy Engine strictly enforces a nested payload wrapped in an `input` object. Sending a flat payload will trigger an immediate default-deny (403 Forbidden) and drop the request. There are no exceptions.**

