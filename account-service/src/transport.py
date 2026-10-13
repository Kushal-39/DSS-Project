"""Expose the verified TLS peer from the socket to ASGI, never from headers."""
from uvicorn.protocols.http.h11_impl import H11Protocol


class VerifiedTLSProtocol(H11Protocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        application = self.app

        async def with_peer(scope, receive, send):
            connection = self.transport.get_extra_info("ssl_object")
            scope["client_cert"] = connection.getpeercert() if connection else None
            await application(scope, receive, send)

        self.app = with_peer


def tls_exception_handler(loop, context):
    """Record peers refused before ASGI runs (asyncio reports these in debug mode)."""
    import ssl
    from src.middleware import log_audit_event

    error = context.get("exception")
    if isinstance(error, ssl.SSLError):
        code = getattr(error, "reason", "")
        reason = {"PEER_DID_NOT_RETURN_A_CERTIFICATE": "no_client_certificate",
                  "CERTIFICATE_VERIFY_FAILED": "client_certificate_untrusted"}.get(code, "handshake_failed")
        transport = context.get("transport")
        try:
            peer = transport.get_extra_info("peername") if transport else None
        except (AttributeError, RuntimeError):
            # asyncio may already have detached the failed SSL transport.
            peer = None
        log_audit_event("mtls_handshake_rejected", "deny", "CONNECT", "tls_listener",
                        reason=reason, remote_addr=str(peer[0]) if peer else None)
    else:
        loop.default_exception_handler(context)
