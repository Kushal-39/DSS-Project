"""Unit tests for OPA Policy Engine integration (docs/policymaker.md)."""

import unittest
from decimal import Decimal
from unittest.mock import patch, MagicMock
import httpx

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.policy import PolicyClient


class TestPolicyClient(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = PolicyClient("http://mock-policy-engine:8181/v1/data/authz/allow")

    async def test_policy_allow_payload_and_result(self):
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"result": {"allow": True}}
            mock_post.return_value = mock_resp

            allowed, reason = await self.client.evaluate(
                user_id="22222222-2222-4222-8222-222222222222",
                roles=["customer"],
                action="TRANSFER",
                resource="account_22222222-2222-4222-8222-222222222222",
                amount=Decimal("50.00"),
                ip_address="192.168.1.50",
                mtls_verified=True,
            )

            self.assertTrue(allowed)
            self.assertEqual(reason, "policy_allowed")

            # Verify the exact nested "input" structure was sent
            call_kwargs = mock_post.call_args[1]
            sent_payload = call_kwargs["json"]
            self.assertIn("input", sent_payload)
            self.assertEqual(sent_payload["input"]["subject"]["user_id"], "22222222-2222-4222-8222-222222222222")
            self.assertEqual(sent_payload["input"]["subject"]["roles"], ["customer"])
            self.assertEqual(sent_payload["input"]["action"], "TRANSFER")
            self.assertEqual(sent_payload["input"]["context"]["amount"], 50.0)
            self.assertTrue(sent_payload["input"]["context"]["mTLS_verified"])

    async def test_policy_deny(self):
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"result": {"allow": False}}
            mock_post.return_value = mock_resp

            allowed, reason = await self.client.evaluate(
                user_id="22222222-2222-4222-8222-222222222222",
                roles=["customer"],
                action="TRANSFER",
                resource="account_22222222-2222-4222-8222-222222222222",
                amount=Decimal("60000.00"),  # Above fraud limit
                ip_address="192.168.1.50",
                mtls_verified=True,
            )

            self.assertFalse(allowed)
            self.assertEqual(reason, "policy_denied")

    async def test_policy_timeout_fails_closed(self):
        with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Timeout")):
            allowed, reason = await self.client.evaluate(
                user_id="user-1",
                roles=["customer"],
                action="TRANSFER",
                resource="account_user-1",
                amount=Decimal("50.00"),
                ip_address="127.0.0.1",
            )
            self.assertFalse(allowed)
            self.assertEqual(reason, "policy_engine_timeout")

    async def test_policy_connect_error_fails_closed(self):
        with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
            allowed, reason = await self.client.evaluate(
                user_id="user-1",
                roles=["customer"],
                action="TRANSFER",
                resource="account_user-1",
                amount=Decimal("50.00"),
                ip_address="127.0.0.1",
            )
            self.assertFalse(allowed)
            self.assertEqual(reason, "policy_engine_unreachable")


if __name__ == "__main__":
    unittest.main()
