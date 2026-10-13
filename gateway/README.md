# Gateway

The public FastAPI ingress on port 8080 proxies login/discovery to IdP and
routes account/payment APIs over TLS 1.3 with its own CA-issued client identity.
Business requests require an RS256 JWT with an expiration, expected issuer and
audience, signing key ID, subject, and roles array. JWKS caches expire after
five minutes; an unavailable refresh fails closed.

A global window limits all public routes (`GATEWAY_RATE_LIMIT`, default 120;
`GATEWAY_RATE_WINDOW`, default 60 seconds). Requests over the limit return 429
and `Retry-After`. Bodies are bounded to one MiB. Forwarding uses a header
allowlist, replaces the client address with the actual ingress peer, and
propagates a validated W3C trace context. Internal certificate headers supplied
by clients never authenticate a connection. OTLP export uses a bounded queue.

Build through the root Compose file; this Dockerfile uses the repository root
as its context to include the shared tracing module. Readiness checks IdP,
account, and payment. See the root README and `scripts/test-all.sh`.
