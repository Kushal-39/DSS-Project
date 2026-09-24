# Account Service — Microservice A (Person 4)

The Account Service manages user accounts and balances in the Zero-Trust Distributed System. It enforces fine-grained Attribute-Based Access Control (ABAC) with Person 3's Policy Engine before executing atomic balance deductions, validates JWTs from Person 1 (IdP), supports mTLS, and emits structured security audit events for Person 6 (Telemetry).

---

## 1. Responsibilities & Database Ownership

- **Microservice A Owner:** Person 4 ([`docs/division.md`](../docs/division.md))
- **Database Ownership:** Exclusively owns the `accounts` table ([`docs/database.md`](../docs/database.md) §2). No other microservice reads or writes this table directly.

### Database Schema ([`migrations/001_init.up.sql`](./migrations/001_init.up.sql))

```sql
CREATE TABLE accounts (
    user_id UUID PRIMARY KEY,
    balance DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    status VARCHAR(20) DEFAULT 'ACTIVE'
);
```

---

## 2. API Contract ([`docs/contacts.md`](../docs/contacts.md))

### `POST /api/v1/accounts/deduct`

Deducts funds from a user's account balance.

- **Headers:**
  - `Authorization: Bearer <RS256-JWT>`
  - `traceparent: 00-<trace_id>-<span_id>-01` (optional, synthesized if omitted)
- **Request Body:**
  ```json
  {
    "user_id": "22222222-2222-4222-8222-222222222222",
    "amount": 50.00
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "status": "success",
    "user_id": "22222222-2222-4222-8222-222222222222",
    "deducted_amount": 50.00,
    "remaining_balance": 950.00
  }
  ```
- **Mandatory Flow & Rejection Logic:**
  1. Validates JWT signature against IdP JWKS (`/.well-known/jwks.json`).
  2. Queries database: verifies user exists, is `ACTIVE`, and `balance >= amount`.
  3. Queries Policy Engine (`POST http://policy-engine:8181/v1/data/authz/allow`) with the strict nested `"input"` format.
  4. If `result.allow == true`, executes atomic deduction (`UPDATE accounts SET balance = balance - $1 WHERE user_id = $2 AND balance >= $1 RETURNING balance`) and returns `200 OK`.
  5. If balance is too low, user inactive, or Policy Engine returns anything other than `true`, immediately returns `403 Forbidden` and leaves the database untouched.

### Additional Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/accounts/{user_id}` | Returns account balance and status (requires token of owner or admin) |
| `GET` | `/healthz` | Process liveness probe (`{"status": "ok"}`) |
| `GET` | `/readyz` | Readiness probe verifying DB connection & Policy Engine reachability |

---

## 3. Integration Contracts

### Policy Engine Request Format ([`docs/policymaker.md`](../docs/policymaker.md))

```json
{
  "input": {
    "subject": {
      "user_id": "22222222-2222-4222-8222-222222222222",
      "roles": ["customer"]
    },
    "action": "TRANSFER",
    "resource": "account_22222222-2222-4222-8222-222222222222",
    "context": {
      "amount": 50.00,
      "ip_address": "127.0.0.1",
      "mTLS_verified": true
    }
  }
}
```

### Structured Telemetry & Audit Logs (Person 6)

Emits single-line JSON logs on `stdout` matching [`telemetry/docs/integration.md`](../telemetry/docs/integration.md):

```json
{"time": "2026-09-22T06:30:00Z", "service": "account-service", "msg": "access_decision", "decision": "permit", "action": "TRANSFER", "resource": "account_...", "user_id": "...", "traceparent": "00-..."}
```

---

## 4. Running & Development

### Using Docker Compose

```bash
docker compose up --build account-service
```

### Running Locally

```bash
cd account-service
pip install -r requirements.txt
python -m uvicorn src.main:app --host 0.0.0.0 --port 8082
```

### Running Unit & Integration Tests

```bash
python -m unittest discover -s tests
```
