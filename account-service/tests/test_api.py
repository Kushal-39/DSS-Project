"""Integration tests for Account Service HTTP endpoints."""

import unittest
from decimal import Decimal
from uuid import UUID
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.main import app
from src.models import TokenClaims


class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, raise_server_exceptions=False)
        self.user_id = UUID("22222222-2222-4222-8222-222222222222")

    def test_healthz_endpoint(self):
        resp = self.client.get("/healthz")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})

    def test_readyz_endpoint_healthy(self):
        with patch("src.routes.health.db.is_healthy", new_callable=AsyncMock) as mock_db_health, \
             patch("src.routes.health.httpx.AsyncClient.get", new_callable=AsyncMock) as mock_policy_health:
            mock_policy_health.return_value.status_code = 200
            mock_db_health.return_value = True
            resp = self.client.get("/readyz")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["status"], "ready")

    def test_deduct_endpoint_without_auth_returns_401(self):
        resp = self.client.post(
            "/api/v1/accounts/deduct",
            json={"user_id": str(self.user_id), "amount": 50.00},
        )
        self.assertEqual(resp.status_code, 401)

    def test_deduct_endpoint_with_auth_success(self):
        claims = TokenClaims(sub=str(self.user_id), roles=["customer"])

        with patch("src.auth.jwt_verifier.verify_token", new_callable=AsyncMock) as mock_verify, \
             patch("src.service.db.get_account", new_callable=AsyncMock) as mock_account, \
             patch("src.service.policy_client.evaluate", new_callable=AsyncMock) as mock_policy, \
             patch("src.service.db.deduct_balance", new_callable=AsyncMock) as mock_deduct:

            mock_verify.return_value = claims
            mock_account.return_value = {
                "user_id": self.user_id,
                "balance": Decimal("1000.00"),
                "status": "ACTIVE",
            }
            mock_policy.return_value = (True, "policy_allowed")
            mock_deduct.return_value = Decimal("950.00")

            headers = {
                "Authorization": "Bearer mock-token",
                "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            }
            resp = self.client.post(
                "/api/v1/accounts/deduct",
                json={"user_id": str(self.user_id), "amount": 50.00},
                headers=headers,
            )

            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["user_id"], str(self.user_id))
            self.assertEqual(data["remaining_balance"], "950.00")
            # Verify traceparent was propagated in response header
            self.assertIn("traceparent", resp.headers)


if __name__ == "__main__":
    unittest.main()
