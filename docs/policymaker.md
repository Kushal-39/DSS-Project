# Policy Engine Contract (OPA)

If the security policy engine fails, the entire Zero-Trust architecture is useless. Person 3, this is your domain. Person 4 and 5, this is exactly how you must ask for permission before executing any sensitive action. Do not guess the format. Copy and paste it.

## 1. The Core Rule: Default Deny
In a Zero-Trust system, the default answer is always `false`. If a request is malformed, missing attributes, or looks even slightly suspicious, block it. 

## 2. The Input Payload (Person 4 & 5)
When Microservice A or B needs to authorize an action, they make a synchronous `POST` request to the Policy Engine. 

Open Policy Agent (OPA) requires the payload to be wrapped in an `"input"` object. If you send a flat JSON dictionary without this wrapper, it will fail and you will waste hours debugging a non-existent network issue.

**Endpoint:** `POST http://policy-engine:8181/v1/data/authz/allow`

**Exact Request Format:**
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

## 3. The Output Payload (Person 3)

The Policy Engine evaluates the Rego rules against the input. The response must be a strict JSON object containing the evaluation result. Do not return custom string messages like "Approved". Stick to the standard OPA output.

**Exact Response Format:**

```json
{
  "result": {
    "allow": true
  }
}

```

*(Note for Person 4 & 5: Parse your JSON properly. If `result.allow` is anything other than `true`, you immediately return a `403 Forbidden` to the client).*

## 4. The Rego Baseline (Person 3)

Here is the baseline Rego policy you need to write in a file named `authz.rego`. This enforces that only authenticated customers can initiate transfers, and completely blocks anything over a specific threshold to prevent massive fraud on day one.

```rego
package authz

# Default deny everything
default allow = false

# Rule: Allow transfers if the user is a customer and the amount is sane
allow {
    input.action == "TRANSFER"
    "customer" == input.subject.roles[_]
    input.context.amount <= 50000
    input.context.mTLS_verified == true
}

```

