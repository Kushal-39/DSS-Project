"""Telemetry, structured audit logging, W3C trace propagation, and mTLS verification middleware."""

import json
import logging
import sys
import time
from datetime import datetime, timezone
import uuid
import re
from starlette.responses import JSONResponse
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.config import settings

# Setup standard JSON logger for stdout
json_logger = logging.getLogger("audit_logger")
json_logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(message)s"))
json_logger.handlers = [handler]
json_logger.propagate = False


def log_audit_event(
    msg: str,
    decision: str,
    action: str,
    resource: str,
    user_id: Optional[str] = None,
    traceparent: Optional[str] = None,
    reason: Optional[str] = None,
    remote_addr: Optional[str] = None,
    extra: Optional[dict] = None,
):
    """
    Emits structured JSON audit decisions strictly matching Person 6's central
    audit pipeline format (telemetry/docs/integration.md §3.4).
    """
    event = {
        "time": datetime.now(timezone.utc).isoformat(),
        "service": settings.SERVICE_NAME,
        "msg": msg,
        "decision": decision.lower(),  # "permit" or "deny"
        "action": action,
        "resource": resource,
        "user_id": user_id or "anonymous",
    }
    if traceparent:
        event["traceparent"] = traceparent
    if reason:
        event["reason"] = reason
    if remote_addr:
        event["remote_addr"] = remote_addr
    if extra:
        event.update(extra)

    json_logger.info(json.dumps(event))


def generate_traceparent() -> str:
    """Generate a valid W3C traceparent header if none provided."""
    trace_id = uuid.uuid4().hex
    span_id = uuid.uuid4().hex[:16]
    return f"00-{trace_id}-{span_id}-01"


class TelemetryMiddleware(BaseHTTPMiddleware):
    """Intercepts requests to propagate tracing, inspect mTLS status, and log performance."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.perf_counter()

        # 1. W3C traceparent extraction or synthesis
        traceparent = request.headers.get("traceparent")
        if not traceparent or not re.fullmatch(r"00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}", traceparent):
            traceparent = generate_traceparent()
        request.state.traceparent = traceparent

        # 2. Extract Client IP
        client_ip = request.headers.get("X-Forwarded-For")
        if client_ip:
            client_ip = client_ip.split(",")[0].strip()
        elif request.client:
            client_ip = request.client.host
        else:
            client_ip = "127.0.0.1"
        request.state.client_ip = client_ip

        # 3. Detect mTLS verification
        # Checks if TLS client cert was provided or forwarded by proxy
        mtls_verified = False
        certificate = request.scope.get("client_cert")
        if certificate:
            mtls_verified = True
        elif not settings.TLS_REQUIRE_CLIENT_CERT and settings.ENVIRONMENT == "test":
            mtls_verified = True

        request.state.mtls_verified = mtls_verified

        # 4. Emit named audit event for mTLS rejection (telemetry/docs/integration.md §Person 4)
        if not mtls_verified and settings.TLS_REQUIRE_CLIENT_CERT:
            log_audit_event(
                msg="mtls_handshake_rejected",
                decision="deny",
                action="CONNECT",
                resource=str(request.url.path),
                traceparent=traceparent,
                remote_addr=client_ip,
                reason="no_client_certificate",
            )

        if settings.TLS_REQUIRE_CLIENT_CERT:
            if not mtls_verified:
                return JSONResponse({"detail": "Verified client certificate required"}, status_code=403)
            identities = [value for group in certificate.get("subject", ())
                          for name, value in group if name == "commonName"]
            allowed = {"gateway", "payment-service-client", "account-service"}
            if request.url.path not in {"/healthz", "/readyz"} and not allowed.intersection(identities):
                return JSONResponse({"detail": "Client identity not allowed"}, status_code=403)

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Structured request logging
            request_log = {
                "time": datetime.now(timezone.utc).isoformat(),
                "service": settings.SERVICE_NAME,
                "msg": "http_request",
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "traceparent": traceparent,
                "remote_addr": client_ip,
            }
            json_logger.info(json.dumps(request_log))

            # Propagate traceparent downstream in response headers
            response.headers["traceparent"] = traceparent
            return response

        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            error_log = {
                "time": datetime.now(timezone.utc).isoformat(),
                "service": settings.SERVICE_NAME,
                "msg": "http_panic",
                "method": request.method,
                "path": request.url.path,
                "error": str(exc),
                "duration_ms": duration_ms,
                "traceparent": traceparent,
                "remote_addr": client_ip,
            }
            json_logger.error(json.dumps(error_log))
            raise exc
