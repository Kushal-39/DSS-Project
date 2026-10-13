"""Configuration settings for Account Service."""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    # Service identity
    SERVICE_NAME: str = "account-service"
    ENVIRONMENT: str = "production"
    LOG_LEVEL: str = "INFO"

    # HTTP / Server
    HOST: str = "0.0.0.0"
    PORT: int = 8082

    # Database (Supabase / PostgreSQL)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/postgres")

    # Zero-Trust dependencies
    POLICY_ENGINE_URL: str = os.getenv(
        "POLICY_ENGINE_URL", "http://policy-engine:8181/v1/data/authz/allow"
    )
    IDP_JWKS_URL: str = os.getenv(
        "IDP_JWKS_URL", "http://idp:8080/.well-known/jwks.json"
    )

    JWT_ISSUER: str = "http://idp:8080"
    JWT_AUDIENCE: str = "zerotrust-api-gateway"

    # Policy & Auth timeouts (seconds)
    POLICY_TIMEOUT_SECONDS: float = 2.0
    JWKS_CACHE_TTL_SECONDS: int = 300

    # Transport Contract (mTLS / TLS 1.3)
    TLS_CERT_FILE: Optional[str] = os.getenv("ACCOUNT_TLS_CERT_FILE")
    TLS_KEY_FILE: Optional[str] = os.getenv("ACCOUNT_TLS_KEY_FILE")
    TLS_CA_FILE: Optional[str] = os.getenv("ACCOUNT_TLS_CA_FILE")
    TLS_REQUIRE_CLIENT_CERT: bool = os.getenv("ACCOUNT_TLS_REQUIRE_CLIENT_CERT", "false").lower() in ("1", "true", "yes")

    model_config = SettingsConfigDict(
        extra="ignore"
    )


settings = Settings()
