# Microservice API & Database Contracts

Read this carefully. If your code does not match these exact specifications, your PR will be rejected. We are not guessing field names or debugging your JSON parsing errors.

## Person 4: Account Service
**Your Job:** Manage user balances and verify account status. 

### Database Schema
You own the `accounts` table. Put this exact SQL in your `migrations/001_init.up.sql` file. Do not add random columns.
```sql
CREATE TABLE accounts (
    user_id UUID PRIMARY KEY,
    balance DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    status VARCHAR(20) DEFAULT 'ACTIVE'
);

```

### API Contract

You must expose a `POST /api/v1/accounts/deduct` endpoint.

**Incoming Request Format:**

```json
{
    "user_id": "uuid-string",
    "amount": 50.00
}

```

**Mandatory Logic:**

1. Extract and validate the JWT passed from the API Gateway.
2. Query your database to check if the user has enough balance.
3. Call the Policy Engine (Person 3) via HTTP to verify if this specific user is authorized to move this amount of money.
4. If the Policy Engine returns `true`, update your database and return `200 OK`.
5. If the balance is too low or the Policy Engine returns `false`, return `403 Forbidden` and do not touch the database.

---

## Person 5: Payment Service

**Your Job:** Process the transfer request and maintain an immutable ledger of transactions.

### Database Schema

You own the `transactions` table. Put this exact SQL in your `migrations/001_init.up.sql` file.

```sql
CREATE TABLE transactions (
    txn_id UUID PRIMARY KEY,
    sender_id UUID NOT NULL,
    receiver_id UUID NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

```

### API Contract

You must expose a `POST /api/v1/payments/transfer` endpoint.

**Incoming Request Format:**

```json
{
    "sender_id": "uuid-string",
    "receiver_id": "uuid-string",
    "amount": 50.00
}

```

**Mandatory Logic:**

1. Validate the JWT and ensure the request came over an mTLS connection.
2. **DO NOT** try to deduct money yourself. You do not have access to the accounts table.
3. You MUST send a synchronous HTTP request to Person 4's `/api/v1/accounts/deduct` endpoint.
4. If Person 4 returns `200 OK`, write the new transaction record to your database.
5. If Person 4 returns an error, immediately abort the process and return `400 Bad Request` to the client.


