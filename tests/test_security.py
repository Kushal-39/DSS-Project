"""Regression tests for server transport configuration and untrusted headers."""
import sys
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "account-service"))
from src.config import settings
from src.main import app, create_ssl_context
from src.models import DeductRequest
from src.auth import JWTVerifier


@pytest.mark.parametrize("amount", ["0.001", "NaN", "Infinity", "100000000.00", "0", "-1"])
def test_deduction_rejects_unrepresentable_amounts(amount):
    with pytest.raises(ValidationError):
        DeductRequest(user_id="22222222-2222-4222-8222-222222222222", amount=amount)


def test_certificate_headers_cannot_authenticate_a_plain_connection():
    with patch.object(settings, "TLS_REQUIRE_CLIENT_CERT", True):
        response = TestClient(app).get("/api/v1/accounts", headers={
            "X-Forwarded-Client-Cert": "gateway", "X-Client-Cert-Present": "true"})
        assert response.status_code == 403


def test_required_tls_cannot_silently_downgrade():
    with patch.object(settings, "TLS_REQUIRE_CLIENT_CERT", True), \
         patch.object(settings, "TLS_CERT_FILE", None), patch.object(settings, "TLS_KEY_FILE", None):
        with pytest.raises(RuntimeError):
            create_ssl_context()


@pytest.mark.asyncio
async def test_expired_jwks_cache_cannot_authorize_when_idp_is_down():
    verifier = JWTVerifier("http://unreachable.invalid")
    verifier._cached_jwks = {"keys": []}
    verifier._cache_expiry = 0
    with patch("src.auth.httpx.AsyncClient.get", side_effect=httpx.ConnectError("unreachable")):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as failure:
            await verifier._fetch_jwks()
        assert failure.value.status_code == 503


def test_tls_rejection_is_logged_even_after_transport_is_detached():
    import ssl
    from unittest.mock import Mock
    from src.transport import tls_exception_handler

    transport = Mock()
    transport.get_extra_info.side_effect = AttributeError("transport detached")
    with patch("src.middleware.log_audit_event") as audit:
        tls_exception_handler(Mock(), {"exception": ssl.SSLError("rejected"), "transport": transport})
    assert audit.call_args.args[:2] == ("mtls_handshake_rejected", "deny")
