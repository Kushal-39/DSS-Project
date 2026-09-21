# Policy Engine — OPA / ABAC (Person 3)

The centralized Zero-Trust decision point. Microservices (Persons 4 & 5)
synchronously ask this engine whether an action is allowed **before**
executing any sensitive operation.

This service has **no Dockerfile of its own**: it runs the official, pinned
`openpolicyagent/opa` image, and the policy-as-code in `policies/` is
volume-mounted read-only into the container by the root `docker-compose.yml`.

## Contract (do not guess — copy this)

**Endpoint:** `POST http://policy-engine:8181/v1/data/authz/allow`

**Request** — the payload MUST be wrapped in an `"input"` object. A flat
dictionary evaluates to `false` (OPA logs an `api_usage_warning` you will
waste an hour on if you don't read the logs).

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

**Response** — exactly the shape from `docs/policymaker.md`:

```json
{"result": {"allow": true}}
```

If `result.allow` is anything other than `true`, immediately return
`403 Forbidden` to the client. If the engine is unreachable, **fail closed**
(treat as denied). Use a short client timeout — this is a synchronous call
in the request path.

## Current policy rules (`policies/authz.rego`)

| Rule | Effect |
| --- | --- |
| `default allow := {"allow": false}` | **Default Deny** — malformed/missing/suspicious input is always denied |
| admin override | any action, if `input.subject.roles` contains `"admin"` |
| `TRANSFER` | allowed only if `roles` contains `"customer"`, `0 < amount <= 50000`, and `context.mTLS_verified == true` |

> **Input shape note:** `docs/division.md` shows a *flat* payload
> (`"roles"` at the top level). The implemented contract shape is the
> *nested* one from `docs/policymaker.md` (`input.subject.roles`). A flat
> payload is denied by default. Send the nested shape.

## Testing & verification checklist (self-service)

### 1. Run the unit tests (no Docker needed)

```bash
# with a local opa binary (https://www.openpolicyagent.org/docs/cli):
opa test -v policy-engine/policies        # expect: PASS: 17/17
opa check --strict policy-engine/policies # expect: no output
opa fmt --list policy-engine/policies     # expect: no output
```

### 2. Bring the stack up

```bash
cd <repo root>
docker compose up --build -d
docker compose ps        # expect: policy-engine  Up (healthy)
docker compose logs policy-engine   # policies loaded, no errors
```

The healthcheck runs a **real policy evaluation**
(`opa eval --fail -d /policies 'data.authz.allow == {"allow": false}'`),
so the container reports unhealthy if the policies are missing, fail to
compile, or the default-deny decision document stops resolving.

### 3. Exercise the decision endpoint (from inside the compose network)

```bash
# ALLOW: the exact contract payload (customer, 50.00, mTLS verified)
docker compose exec idp wget -qO- --header='Content-Type: application/json' \
  --post-data='{"input":{"subject":{"user_id":"uuid-string-from-jwt","roles":["customer"]},"action":"TRANSFER","resource":"account_987","context":{"amount":50.00,"ip_address":"192.168.1.50","mTLS_verified":true}}}' \
  http://policy-engine:8181/v1/data/authz/allow
# → {"result":{"allow":true}}

# DENY: amount over the 50,000 fraud threshold
#   …same command, "amount":60000        → {"result":{"allow":false}}
# DENY: mTLS not verified                ("mTLS_verified":false) → false
# DENY: flat division.md shape           (roles at top level)   → false
# DENY: payload not wrapped in "input"   → false + api_usage_warning in logs
# 400:  malformed JSON body              → OPA invalid_parameter error
```

Or from any machine, via a one-off container on the compose network:

```bash
docker run --rm --network <project>_default curlimages/curl:latest -s \
  -X POST http://policy-engine:8181/v1/data/authz/allow \
  -H 'Content-Type: application/json' \
  -d '{"input":{"subject":{"user_id":"u","roles":["customer"]},"action":"TRANSFER","resource":"account_987","context":{"amount":50,"ip_address":"192.168.1.50","mTLS_verified":true}}}'
```

### 4. Rules for integrating services (Persons 4 & 5)

1. Wrap the payload in `{"input": ...}` — always.
2. Parse the response as JSON; allow **only** when `result.allow == true`.
3. Return `403 Forbidden` otherwise; fail closed if the engine is down.
4. Set a short HTTP timeout (e.g. 2s) — the check sits in the request path.
5. `POST /v1/data/authz/allow` is the only endpoint you need; do not
   scrape `/v1/data`, `/v1/policies`, or the health API.

## Security posture

- Internal Docker network only — **no host ports are published**.
- Official image runs as non-root `1000:1000`; policies are mounted `:ro`.
- Pinned version (`1.20.2`) — no floating tags.

### Hardening roadmap (deferred; do not implement in the baseline PR)

- `--set decision_logs.console=true` — structured PERMIT/DENY audit events
  for Person 6's pipeline (`docs/flow.md` §6).
- `--authentication=token` + a `system.authz` Rego policy — stop the engine
  itself being an open endpoint.
- TLS/mTLS listener (`--tls-cert-file`, `--tls-ca-cert-file`) once the
  shared self-signed CA from the Transport Contract exists.
