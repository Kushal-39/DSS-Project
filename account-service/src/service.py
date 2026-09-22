"""Account Service business logic and transaction orchestration."""

import logging
from decimal import Decimal
from uuid import UUID
from fastapi import HTTPException, status

from src.database import db
from src.models import DeductRequest, DeductResponse, AccountResponse, TokenClaims
from src.policy import policy_client
from src.middleware import log_audit_event

logger = logging.getLogger("account-service")


class AccountService:
    async def get_account_details(self, user_id: UUID) -> AccountResponse:
        """Retrieve user account balance and status."""
        account = await db.get_account(user_id)
        if not account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Account for user_id {user_id} not found",
            )
        return AccountResponse(
            user_id=account["user_id"],
            balance=account["balance"],
            status=account["status"],
        )

    async def deduct(
        self,
        request: DeductRequest,
        claims: TokenClaims,
        traceparent: str,
        client_ip: str,
        mtls_verified: bool,
    ) -> DeductResponse:
        """
        Execute mandatory deduction logic (docs/contacts.md Person 4):
        1. Token is validated (via claims).
        2. Query database to check if the user exists, is active, and has enough balance.
        3. Call Policy Engine (Person 3) to verify if user is authorized.
        4. If Policy Engine returns true, atomically deduct from database and return 200 OK.
        5. If balance is too low or Policy Engine returns false, return 403 Forbidden and do not touch database.
        """
        user_id = request.user_id
        amount = request.amount
        resource = f"account_{user_id}"

        # 1b. Enforce account ownership: caller must own the account unless admin
        if str(claims.sub) != str(user_id) and "admin" not in claims.roles:
            log_audit_event(
                msg="access_decision",
                decision="deny",
                action="TRANSFER",
                resource=resource,
                user_id=str(claims.sub),
                traceparent=traceparent,
                reason="account_ownership_violation",
                remote_addr=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Cannot deduct from another user's account",
            )

        # 2. Query database for account balance and status
        account = await db.get_account(user_id)
        if not account:
            log_audit_event(
                msg="access_decision",
                decision="deny",
                action="TRANSFER",
                resource=resource,
                user_id=str(user_id),
                traceparent=traceparent,
                reason="account_not_found",
                remote_addr=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account not found or access denied",
            )

        if account["status"] != "ACTIVE":
            log_audit_event(
                msg="access_decision",
                decision="deny",
                action="TRANSFER",
                resource=resource,
                user_id=str(user_id),
                traceparent=traceparent,
                reason="account_inactive",
                remote_addr=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is inactive or suspended",
            )

        current_balance = Decimal(str(account["balance"]))
        if current_balance < amount:
            log_audit_event(
                msg="access_decision",
                decision="deny",
                action="TRANSFER",
                resource=resource,
                user_id=str(user_id),
                traceparent=traceparent,
                reason="insufficient_balance",
                remote_addr=client_ip,
                extra={"requested_amount": float(amount), "current_balance": float(current_balance)},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient balance",
            )

        # 3. Synchronous Policy Engine check
        # Roles from token claims; if claims.sub != user_id and not admin, policy will check roles
        is_allowed, policy_reason = await policy_client.evaluate(
            user_id=claims.sub,
            roles=claims.roles,
            action="TRANSFER",
            resource=resource,
            amount=amount,
            ip_address=client_ip,
            mtls_verified=mtls_verified,
        )

        if not is_allowed:
            log_audit_event(
                msg="access_decision",
                decision="deny",
                action="TRANSFER",
                resource=resource,
                user_id=str(user_id),
                traceparent=traceparent,
                reason=policy_reason,
                remote_addr=client_ip,
                extra={"amount": float(amount)},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Policy authorization rejected: {policy_reason}",
            )

        # 4. Atomic balance deduction in database
        remaining_balance = await db.deduct_balance(user_id, amount)
        if remaining_balance is None:
            # Race condition check: balance changed concurrently
            log_audit_event(
                msg="access_decision",
                decision="deny",
                action="TRANSFER",
                resource=resource,
                user_id=str(user_id),
                traceparent=traceparent,
                reason="concurrent_balance_exhaustion",
                remote_addr=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient balance during concurrent transaction",
            )

        # Log permit decision
        log_audit_event(
            msg="access_decision",
            decision="permit",
            action="TRANSFER",
            resource=resource,
            user_id=str(user_id),
            traceparent=traceparent,
            reason="policy_allowed",
            remote_addr=client_ip,
            extra={
                "deducted_amount": float(amount),
                "remaining_balance": float(remaining_balance),
            },
        )

        return DeductResponse(
            status="success",
            user_id=user_id,
            deducted_amount=amount,
            remaining_balance=remaining_balance,
        )


account_service = AccountService()
