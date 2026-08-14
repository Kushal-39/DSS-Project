# IdP — Identity Provider

Person 1's microservice in the Zero-Trust architecture. Owns the
`credentials` table (Database-per-Service — see `docs/database.md`),
authenticates users, and issues RS256-signed JWTs that the API Gateway
(Person 2) verifies against our JWKS.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/login` | Authenticate (`{"username","password","device_id"?}`) → `{token, token_type, expires_in, user}` |
| `GET` | `/.well-known/jwks.json` | Public RSA key (JWKS) for signature verification |
| `GET` | `/.well-known/openid-configuration` | Minimal discovery document |
| `GET` | `/healthz`, `/readyz` | Liveness / readiness (DB ping) |

## Running

```bash
# 1. Environment (see .env.example — copy into the git-crypt-encrypted .env)
#    DATABASE_URL=postgres://...  (Supabase)
#    IDP_RSA_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n...  (or _PATH)

# 2. Build & run
docker compose up --build          # via the root compose file
# or locally:
go run ./cmd/server migrate && go run ./cmd/server seed && go run ./cmd/server serve

# 3. Smoke test
curl -s http://localhost:8080/.well-known/jwks.json
curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
```

The container entrypoint runs `migrate → seed → serve` automatically
(`docs/database.md` §4). Migrations and the seed script are compiled into
the binary via `go:embed`.

## Bootstrap users (DEV-ONLY)

| username | password | role |
| --- | --- | --- |
| `admin` | `admin123` | `admin` |
| `customer` | `customer123` | `customer` |

These are intentionally known, documented values so every team member can
exercise the flow. They are **not** secrets; real credentials are provisioned
out of band.

## Developer utilities

```bash
go run ./cmd/server genkey          # print a fresh RSA private key for .env
go run ./cmd/server hash <password> # print a bcrypt hash for seed data
```

## Token claims

`sub` (user UUID), `roles` (`["admin"]`/`["customer"]` — the array shape the
Policy Engine contract expects), `device_id`, plus `iss`/`aud`/`exp`/`iat`/`jti`.
See `decisions.md` for the full design rationale.

## Testing & verification checklist (self-service)

### 1. Prerequisites (one-time)

```bash
git-crypt unlock /path/to/zerotrust-key.key   # decrypt the root .env
docker --version && docker compose version    # Docker + Compose v2
go version                                    # 1.23+ for unit tests
```

### 2. Bring the stack up

```bash
cd <repo root>
docker compose up --build -d     # builds ./idp, runs migrate → seed → serve
```

### 3. Confirm the container is healthy

```bash
docker compose ps                # expect: Up (healthy)
docker compose logs idp          # expect migrate → seed → serve lines, no errors
```

If it never becomes healthy or crashes, read the logs — the service fails
fast with a clear message for missing env vars or an unreachable DB.

### 4. Exercise the endpoints

```bash
# liveness / readiness
curl -s -w '\n%{http_code}\n' http://localhost:8080/healthz   # 200 {"status":"ok"}
curl -s -w '\n%{http_code}\n' http://localhost:8080/readyz    # 200 (DB ping)

# public keys for the gateway
curl -s http://localhost:8080/.well-known/jwks.json            # {"keys":[{kty,use,alg,kid,n,e}]}
curl -s http://localhost:8080/.well-known/openid-configuration

# login (see Bootstrap users below)
curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123","device_id":"my-laptop"}'
# → 200 with {"token":"<jwt>","token_type":"Bearer","expires_in":900,"user":{...}}

# negative cases must also work:
curl -s -w '\n%{http_code}\n' -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"wrong"}'   # 401
curl -s -w '\n%{http_code}\n' -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' -d '{"username":"ghost","password":"x"}'      # 401 (same error)
```

### 5. Inspect the token

Decode the JWT payload from step 4 (middle segment, base64url):

```bash
# grab a token
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"customer","password":"customer123"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
# decode payload
python3 -c "import sys,base64,json; p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))" "$TOKEN"
```

Expect `iss`, `sub` (user UUID), `aud: ["zerotrust-api-gateway"]`, `roles`
(array), `device_id`, `exp`, `iat`, `jti`. The `kid` in the header must match
the `kid` served by `/jwks.json`.

### 6. Verify the signature (what the gateway will do)

A compact end-to-end check: fetch the JWKS, log in, and verify the token
against the served public key (needs `cryptography`):

```bash
python3 - <<'EOF'
import base64, json, urllib.request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

jwks = json.load(urllib.request.urlopen("http://localhost:8080/.well-known/jwks.json"))["keys"][0]
body = json.dumps({"username": "admin", "password": "admin123"}).encode()
req = urllib.request.Request("http://localhost:8080/login", data=body, headers={"Content-Type": "application/json"})
token = json.load(urllib.request.urlopen(req))["token"]
header, payload, sig = token.split(".")
def b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
pub = rsa.RSAPublicNumbers(int.from_bytes(b64(jwks["n"]), "big"), 65537).public_key()
pub.verify(b64(sig), f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
print("SIGNATURE OK — claims:", json.loads(b64(payload)))
EOF
```

### 7. Run the Go checks (no Docker needed)

```bash
cd idp
go build ./... && go vet ./... && gofmt -l .   # expect no output from gofmt
go test -race ./...                             # keys, auth, HTTP handler tests
```

### 8. Tear down

```bash
docker compose down    # removes the container and network (keeps the DB untouched)
```

### Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `fatal ... DATABASE_URL is not set` | `.env` not decrypted — run `git-crypt unlock`, or export the var |
| `fatal ... neither IDP_RSA_PRIVATE_KEY nor ... set` | Missing key in `.env` — add one from `go run ./cmd/server genkey` |
| `serve: keys: no PEM block found` | Key in `.env` is truncated/corrupt — regenerate and replace it |
| `dial tcp [....]:5432: network is unreachable` | IPv6-only host; the compose network already sets `enable_ipv6: true` — don't remove it |
| Container `(unhealthy)` | DB unreachable (`/readyz` fails) — check `docker compose logs idp` |

## Tests

```bash
go test ./...        # unit tests (keys, auth, HTTP handlers)
go vet ./...         # static analysis
```
