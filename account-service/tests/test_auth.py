"""Unit tests for JWT Authentication and JWKS signature verification."""

import unittest
import time
from unittest.mock import patch, AsyncMock
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from fastapi import HTTPException

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.auth import JWTVerifier


class TestAuth(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Generate temporary RSA keypair for testing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        
        # Serialize public key to JWK
        public_numbers = self.public_key.public_numbers()
        import base64
        def int_to_b64(val):
            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
            return base64.urlsafe_b64encode(val_bytes).decode("utf-8").rstrip("=")

        self.jwk_dict = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "test-key-id",
            "n": int_to_b64(public_numbers.n),
            "e": int_to_b64(public_numbers.e),
        }
        self.jwks = {"keys": [self.jwk_dict]}
        self.verifier = JWTVerifier("http://mock-idp/.well-known/jwks.json")

    def _generate_token(self, payload, headers=None):
        hdr = {"kid": "test-key-id"}
        if headers:
            hdr.update(headers)
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers=hdr)

    async def test_valid_token_verification(self):
        payload = {
            "sub": "22222222-2222-4222-8222-222222222222",
            "roles": ["customer"],
            "device_id": "phone-1",
            "exp": time.time() + 3600,
        }
        token = self._generate_token(payload)

        with patch.object(self.verifier, "_fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = self.jwks
            claims = await self.verifier.verify_token(token)
            self.assertEqual(claims.sub, "22222222-2222-4222-8222-222222222222")
            self.assertIn("customer", claims.roles)
            self.assertEqual(claims.device_id, "phone-1")

    async def test_expired_token_rejected(self):
        payload = {
            "sub": "22222222-2222-4222-8222-222222222222",
            "roles": ["customer"],
            "exp": time.time() - 60,  # Expired
        }
        token = self._generate_token(payload)

        with patch.object(self.verifier, "_fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = self.jwks
            with self.assertRaises(HTTPException) as ctx:
                await self.verifier.verify_token(token)
            self.assertEqual(ctx.exception.status_code, 401)
            self.assertIn("expired", ctx.exception.detail.lower())

    async def test_invalid_algorithm_rejected(self):
        token = jwt.encode({"sub": "user-1"}, "secret", algorithm="HS256")
        with self.assertRaises(HTTPException) as ctx:
            await self.verifier.verify_token(token)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("RS256 required", ctx.exception.detail)

    async def test_missing_sub_rejected(self):
        payload = {"roles": ["customer"], "exp": time.time() + 3600}
        token = self._generate_token(payload)

        with patch.object(self.verifier, "_fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = self.jwks
            with self.assertRaises(HTTPException) as ctx:
                await self.verifier.verify_token(token)
            self.assertEqual(ctx.exception.status_code, 401)
            self.assertIn("sub", ctx.exception.detail.lower())


if __name__ == "__main__":
    unittest.main()
