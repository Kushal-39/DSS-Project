"""JWT Authentication and IdP JWKS signature verification."""

import time
import logging
from typing import Dict, Any, Optional
import httpx
import jwt
from jwt import PyJWKClient
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.config import settings
from src.models import TokenClaims

logger = logging.getLogger("account-service")

security_scheme = HTTPBearer(auto_error=False)


class JWTVerifier:
    def __init__(self, jwks_url: str):
        self.jwks_url = jwks_url
        self._cached_jwks: Optional[Dict[str, Any]] = None
        self._cache_expiry: float = 0.0

    async def _fetch_jwks(self) -> Dict[str, Any]:
        """Fetch JWKS keyset from IdP with in-memory caching."""
        now = time.time()
        if self._cached_jwks and now < self._cache_expiry:
            return self._cached_jwks

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(self.jwks_url)
                resp.raise_for_status()
                data = resp.json()
                self._cached_jwks = data
                self._cache_expiry = now + settings.JWKS_CACHE_TTL_SECONDS
                return data
        except Exception as e:
            logger.warning(f"Failed to fetch JWKS from IdP ({self.jwks_url}): {e}")
            raise HTTPException(status_code=503, detail="Identity verification unavailable")

    async def verify_token(self, token: str) -> TokenClaims:
        """Verify RS256 JWT signature against IdP JWKS and return claims."""
        try:
            # Unverified header to find kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            alg = unverified_header.get("alg", "RS256")

            if alg != "RS256":
                logger.warning(f"Rejected token with invalid algorithm: {alg}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token algorithm (RS256 required)",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            if not kid:
                raise HTTPException(status_code=401, detail="Token missing signing key ID")

            # Get public key
            jwks = await self._fetch_jwks()
            keys = jwks.get("keys", [])
            key_data = None
            for k in keys:
                if kid and k.get("kid") == kid:
                    key_data = k
                    break
                elif not kid:
                    # fallback to first key if no kid specified
                    key_data = k
                    break

            if not key_data:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Signing key not found in JWKS",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)

            # Decode and verify
            payload = jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
                audience=settings.JWT_AUDIENCE,
                issuer=settings.JWT_ISSUER,
                options={"require": ["exp", "sub", "iss", "aud"]},
            )

            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing 'sub' claim",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            roles = payload.get("roles", [])
            if isinstance(roles, str):
                roles = [roles]

            return TokenClaims(
                sub=str(user_id),
                roles=list(roles),
                device_id=payload.get("device_id"),
            )

        except jwt.ExpiredSignatureError:
            logger.info("Token verification failed: signature expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {e}",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during token verification: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            )


jwt_verifier = JWTVerifier(settings.IDP_JWKS_URL)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
) -> TokenClaims:
    """Dependency to extract and verify Bearer JWT from Authorization header."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await jwt_verifier.verify_token(credentials.credentials)
