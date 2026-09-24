"""Main FastAPI Application for Account Service (Microservice A - Person 4)."""

import os
import ssl
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
import uvicorn

from src.config import settings
from src.database import db
from src.middleware import TelemetryMiddleware
from src.routes.health import router as health_router
from src.routes.accounts import router as accounts_router

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("account-service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: connects to DB, runs migrations, and tears down pool on exit."""
    logger.info("Initializing Account Service...")

    # Database initialization & migrations (docs/database.md §4)
    try:
        await db.connect(max_retries=15, retry_delay=1.0)
        await db.run_migrations()
        logger.info("Database migrations & seed completed.")
    except Exception as e:
        logger.error(f"Database startup failed: {e}")
        # If in testing/dev without DB, allow startup to continue for unit test environments
        if settings.ENVIRONMENT != "test":
            raise e

    logger.info(f"Account Service ready and listening on port {settings.PORT}.")
    yield

    logger.info("Shutting down Account Service...")
    await db.disconnect()


app = FastAPI(
    title="Account Service",
    description="Microservice A for Zero-Trust balance management and atomic deductions.",
    version="1.0.0",
    lifespan=lifespan,
)

# Attach Telemetry and Audit middleware
app.add_middleware(TelemetryMiddleware)

# Register routes
app.include_router(health_router)
app.include_router(accounts_router)


@app.get("/", tags=["Root"])
async def root():
    return {
        "service": settings.SERVICE_NAME,
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/healthz",
        "ready": "/readyz",
    }


def create_ssl_context() -> ssl.SSLContext | None:
    """
    Configure TLS 1.3 server context if certificates are specified
    (Transport Contract: docs/division.md §2).
    """
    cert_file = settings.TLS_CERT_FILE
    key_file = settings.TLS_KEY_FILE
    ca_file = settings.TLS_CA_FILE

    if not cert_file or not key_file:
        return None

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logger.warning(f"TLS certificate files not found ({cert_file}, {key_file}). Running in plain HTTP mode.")
        return None

    # TLS 1.3 is mandated by Transport Contract
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3

    ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    if ca_file and os.path.exists(ca_file):
        ssl_context.load_verify_locations(cafile=ca_file)
        if settings.TLS_REQUIRE_CLIENT_CERT:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            logger.info("mTLS enabled: client certificates are strictly required.")
        else:
            ssl_context.verify_mode = ssl.CERT_OPTIONAL
            logger.info("TLS 1.3 enabled with optional client certificate validation.")

    return ssl_context


if __name__ == "__main__":
    ssl_ctx = create_ssl_context()
    uvicorn.run(
        "src.main:app",
        host=settings.HOST,
        port=settings.PORT,
        ssl_keyfile=settings.TLS_KEY_FILE if ssl_ctx else None,
        ssl_certfile=settings.TLS_CERT_FILE if ssl_ctx else None,
        reload=False,
    )
