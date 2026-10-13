import time
from unittest.mock import patch

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from gateway import main


@pytest.fixture
def gateway():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
    captured = []

    def upstream(request):
        captured.append(request)
        if request.url.path.endswith("jwks.json"):
            return httpx.Response(200, json={"keys": [jwk]})
        return httpx.Response(200, json={"received": True})

    main.app.state.public = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    main.app.state.secure = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    main.keys_until = 0
    main.requests_in_window = 0
    main.window_start = time.monotonic()
    token = jwt.encode({"sub": "customer", "roles": ["customer"], "iss": main.ISSUER,
                        "aud": main.AUDIENCE, "exp": int(time.time()) + 100}, key,
                       algorithm="RS256", headers={"kid": "test-key"})
    return TestClient(main.app), token, captured


def test_proxy_overwrites_untrusted_context(gateway):
    client, token, captured = gateway
    response = client.post("/api/v1/payment", json={"amount": "1"}, headers={
        "Authorization": "Bearer " + token, "X-Forwarded-For": "attacker",
        "X-Forwarded-Client-Cert": "fake", "X-Client-Cert-Present": "true", "Host": "attacker",
        "traceparent": "invalid"})
    assert response.status_code == 200
    forwarded = captured[-1]
    assert forwarded.url.scheme == "https"
    assert forwarded.url.host == "payment-service"
    assert forwarded.url.path == "/api/v1/payments/transfer"
    assert forwarded.headers["x-forwarded-for"] == "testclient"
    assert "x-forwarded-client-cert" not in forwarded.headers
    assert "x-client-cert-present" not in forwarded.headers
    assert forwarded.headers["traceparent"].startswith("00-")


def test_invalid_and_absent_tokens_never_reach_backend(gateway):
    client, _, captured = gateway
    for headers in [{}, {"Authorization": "Basic fake"}, {"Authorization": "Bearer junk"}]:
        assert client.get("/api/v1/accounts", headers=headers).status_code == 401
    assert not captured


def test_body_bound_applies_before_proxy(gateway):
    client, _, captured = gateway
    assert client.post("/login", content=b"x" * ((1 << 20) + 1)).status_code == 413
    assert not captured


def test_global_limit_returns_retry_after(gateway):
    client, _, _ = gateway
    with patch.object(main, "RATE", 2):
        assert client.get("/unknown").status_code == 404
        assert client.get("/unknown").status_code == 404
        response = client.get("/unknown")
        assert response.status_code == 429
        assert int(response.headers["retry-after"]) > 0


def test_jwks_outage_fails_closed(gateway):
    client, token, captured = gateway
    def down(request):
        raise httpx.ConnectError("idp unavailable")
    main.app.state.public = httpx.AsyncClient(transport=httpx.MockTransport(down))
    assert client.get("/api/v1/accounts", headers={"Authorization": "Bearer " + token}).status_code == 503
    assert not captured
