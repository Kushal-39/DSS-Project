"""Public ingress: authenticate, limit traffic, and proxy over mutual TLS 1.3."""
import asyncio
import json
import os
import ssl
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from common.observability import TraceMiddleware

IDP = os.getenv("GATEWAY_IDP_URL", "http://idp:8080")
ISSUER = os.getenv("JWT_ISSUER", "http://idp:8080")
AUDIENCE = os.getenv("JWT_AUDIENCE", "zerotrust-api-gateway")
RATE = int(os.getenv("GATEWAY_RATE_LIMIT", "120"))
WINDOW = float(os.getenv("GATEWAY_RATE_WINDOW", "60"))
if RATE < 1 or WINDOW <= 0:
    raise ValueError("Gateway rate limit and window must be positive")


def log(msg, **fields):
    print(json.dumps({"time": datetime.now(timezone.utc).isoformat(),
                      "service": "gateway", "msg": msg, **fields}), flush=True)


@asynccontextmanager
async def lifespan(app):
    context = ssl.create_default_context(cafile=os.getenv("GATEWAY_CA_FILE", "/certs/ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(os.getenv("GATEWAY_CERT_FILE", "/certs/gateway.crt"),
                            os.getenv("GATEWAY_KEY_FILE", "/certs/gateway.key"))
    app.state.secure = httpx.AsyncClient(verify=context, timeout=10, follow_redirects=False)
    app.state.public = httpx.AsyncClient(timeout=5, follow_redirects=False)
    yield
    await app.state.secure.aclose()
    await app.state.public.aclose()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TraceMiddleware, service="gateway")
# One aggregate window deliberately bounds memory independently of attacker IPs.
window_start = time.monotonic()
requests_in_window = 0
keys = {}
keys_until = 0.0
keys_lock = asyncio.Lock()


async def verify(token):
    global keys, keys_until
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "RS256" or not header.get("kid"):
        raise jwt.InvalidTokenError("invalid algorithm or key ID")
    async with keys_lock:
        if time.monotonic() >= keys_until:
            response = await app.state.public.get(IDP + "/.well-known/jwks.json")
            response.raise_for_status()
            keys = {key["kid"]: jwt.PyJWK(key).key for key in response.json()["keys"]}
            keys_until = time.monotonic() + 300
        key = keys.get(header["kid"])
    if key is None:
        raise jwt.InvalidTokenError("unknown signing key")
    claims = jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER,
                        audience=AUDIENCE, options={"require": ["exp", "sub", "iss", "aud"]})
    if not isinstance(claims.get("roles"), list) or not claims["sub"]:
        raise jwt.InvalidTokenError("invalid identity claims")
    return claims


@app.get("/healthz")
async def health():
    return {"status": "ok"}


@app.get("/readyz")
async def ready():
    try:
        checks = await asyncio.gather(
            app.state.public.get(IDP + "/readyz"),
            app.state.secure.get("https://account-service:8082/readyz"),
            app.state.secure.get("https://payment-service:8081/readyz"))
        if any(item.status_code != 200 for item in checks):
            raise RuntimeError("dependency not ready")
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return {"status": "ready"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    global window_start, requests_in_window
    now = time.monotonic()
    if now - window_start >= WINDOW:
        window_start, requests_in_window = now, 0
    requests_in_window += 1
    trace = request.headers.get("traceparent", "")
    address = request.client.host if request.client else "unknown"
    if requests_in_window > RATE:
        log("rate_limited", remote_addr=address, path=request.url.path, traceparent=trace)
        return JSONResponse({"error": "rate_limited"}, status_code=429,
                            headers={"Retry-After": str(max(1, int(WINDOW - (now - window_start))))})

    public_routes = {"login", "token", "jwks.json", ".well-known/jwks.json",
                     ".well-known/openid-configuration"}
    if path in public_routes:
        target, client = IDP, app.state.public
    elif path == "api/v1/payment" or path.startswith("api/v1/payments/"):
        target, client = "https://payment-service:8081", app.state.secure
        if path == "api/v1/payment":
            path = "api/v1/payments/transfer"
    elif path == "api/v1/accounts" or path.startswith("api/v1/accounts/"):
        target, client = "https://account-service:8082", app.state.secure
    else:
        return JSONResponse({"error": "not_found"}, status_code=404)

    if path not in public_routes:
        authorization = request.headers.get("authorization", "")
        try:
            scheme, token = authorization.split(" ", 1)
            if scheme.lower() != "bearer":
                raise jwt.InvalidTokenError("Bearer required")
            await verify(token)
        except (jwt.InvalidTokenError, ValueError, KeyError, TypeError):
            log("token_rejected", reason="invalid_token", traceparent=trace, remote_addr=address)
            return JSONResponse({"error": "unauthorized"}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        except httpx.HTTPError:
            log("verification_unavailable", traceparent=trace)
            return JSONResponse({"error": "verification_unavailable"}, status_code=503)

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 1 << 20:
            return JSONResponse({"error": "body_too_large"}, status_code=413)
    # An allowlist removes spoofed certificate, IP, host and hop-by-hop headers.
    headers = {key: value for key, value in request.headers.items()
               if key in {"authorization", "content-type", "accept", "traceparent", "tracestate"}}
    headers["x-forwarded-for"] = address
    try:
        upstream = await client.request(request.method, target + "/" + path,
                                        params=request.query_params, content=bytes(body), headers=headers)
    except httpx.HTTPError:
        log("upstream_error", dependency=target, traceparent=trace)
        return JSONResponse({"error": "upstream_unavailable"}, status_code=502)
    response_headers = {key: value for key, value in upstream.headers.items()
                        if key in {"content-type", "cache-control", "www-authenticate", "retry-after"}}
    return Response(upstream.content, status_code=upstream.status_code, headers=response_headers)
