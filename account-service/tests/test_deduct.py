"""Unit tests for Account Service deduction business logic (docs/contacts.md)."""

import unittest
from decimal import Decimal
from uuid import UUID
from unittest.mock import patch, AsyncMock
from fastapi import HTTPException

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import DeductRequest, TokenClaims
from src.service import AccountService


class TestAccountServiceDeduct(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.service = AccountService()
        self.user_id = UUID("22222222-2222-4222-8222-222222222222")
        self.claims = TokenClaims(
            sub=str(self.user_id),
            roles=["customer"],
            device_id="device-test",
        )

    async def test_deduct_success(self):
        req = DeductRequest(user_id=self.user_id, amount=Decimal("50.00"))

        with patch("src.service.db.get_account", new_callable=AsyncMock) as mock_get_account, \
             patch("src.service.policy_client.evaluate", new_callable=AsyncMock) as mock_policy, \
             patch("src.service.db.deduct_balance", new_callable=AsyncMock) as mock_deduct:

            mock_get_account.return_value = {
                "user_id": self.user_id,
                "balance": Decimal("1000.00"),
                "status": "ACTIVE",
            }
            mock_policy.return_value = (True, "policy_allowed")
            mock_deduct.return_value = Decimal("950.00")

            res = await self.service.deduct(
                request=req,
                claims=self.claims,
                traceparent="00-test-span-01",
                client_ip="127.0.0.1",
                mtls_verified=True,
            )

            self.assertEqual(res.status, "success")
            self.assertEqual(res.deducted_amount, Decimal("50.00"))
            self.assertEqual(res.remaining_balance, Decimal("950.00"))

    async def test_deduct_insufficient_balance_returns_403(self):
        req = DeductRequest(user_id=self.user_id, amount=Decimal("1500.00"))

        with patch("src.service.db.get_account", new_callable=AsyncMock) as mock_get_account:
            mock_get_account.return_value = {
                "user_id": self.user_id,
                "balance": Decimal("1000.00"),
                "status": "ACTIVE",
            }

            with self.assertRaises(HTTPException) as ctx:
                await self.service.deduct(
                    request=req,
                    claims=self.claims,
                    traceparent="00-test-span-01",
                    client_ip="127.0.0.1",
                    mtls_verified=True,
                )

            # docs/contacts.md rule 5: return 403 Forbidden
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertIn("Insufficient balance", ctx.exception.detail)

    async def test_deduct_inactive_account_returns_403(self):
        req = DeductRequest(user_id=self.user_id, amount=Decimal("50.00"))

        with patch("src.service.db.get_account", new_callable=AsyncMock) as mock_get_account:
            mock_get_account.return_value = {
                "user_id": self.user_id,
                "balance": Decimal("1000.00"),
                "status": "SUSPENDED",
            }

            with self.assertRaises(HTTPException) as ctx:
                await self.service.deduct(
                    request=req,
                    claims=self.claims,
                    traceparent="00-test-span-01",
                    client_ip="127.0.0.1",
                    mtls_verified=True,
                )

            self.assertEqual(ctx.exception.status_code, 403)
            self.assertIn("inactive", ctx.exception.detail.lower())

    async def test_deduct_policy_denial_returns_403(self):
        req = DeductRequest(user_id=self.user_id, amount=Decimal("60000.00"))

        with patch("src.service.db.get_account", new_callable=AsyncMock) as mock_get_account, \
             patch("src.service.policy_client.evaluate", new_callable=AsyncMock) as mock_policy, \
             patch("src.service.db.deduct_balance", new_callable=AsyncMock) as mock_deduct:

            mock_get_account.return_value = {
                "user_id": self.user_id,
                "balance": Decimal("100000.00"),
                "status": "ACTIVE",
            }
            # Policy Engine blocks over 50,000 fraud threshold
            mock_policy.return_value = (False, "policy_denied")

            with self.assertRaises(HTTPException) as ctx:
                await self.service.deduct(
                    request=req,
                    claims=self.claims,
                    traceparent="00-test-span-01",
                    client_ip="127.0.0.1",
                    mtls_verified=True,
                )

            self.assertEqual(ctx.exception.status_code, 403)
            # Ensure database deduct was NEVER called
            mock_deduct.assert_not_called()


if __name__ == "__main__":
    unittest.main()
