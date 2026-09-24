"""Account API endpoints."""

from uuid import UUID
from fastapi import APIRouter, Depends, Request, HTTPException, status

from src.models import DeductRequest, DeductResponse, AccountResponse, TokenClaims
from src.auth import get_current_user
from src.service import account_service

router = APIRouter(prefix="/api/v1/accounts", tags=["Accounts"])


@router.post(
    "/deduct",
    response_model=DeductResponse,
    status_code=status.HTTP_200_OK,
    summary="Deduct balance from user account (Person 4 Contract)",
)
async def deduct_balance(
    deduct_req: DeductRequest,
    raw_request: Request,
    claims: TokenClaims = Depends(get_current_user),
):
    """
    Mandatory Deduct API (docs/contacts.md):
    - Validates incoming JWT.
    - Validates balance in database.
    - Evaluates authorization with Policy Engine (Person 3).
    - If allowed, updates balance atomically in DB.
    - If balance is too low or policy denies, returns 403 Forbidden.
    """
    traceparent = getattr(raw_request.state, "traceparent", "")
    client_ip = getattr(raw_request.state, "client_ip", "127.0.0.1")
    mtls_verified = getattr(raw_request.state, "mtls_verified", True)

    return await account_service.deduct(
        request=deduct_req,
        claims=claims,
        traceparent=traceparent,
        client_ip=client_ip,
        mtls_verified=mtls_verified,
    )


@router.get(
    "/{user_id}",
    response_model=AccountResponse,
    status_code=status.HTTP_200_OK,
    summary="Get user account balance and status",
)
async def get_account(
    user_id: UUID,
    claims: TokenClaims = Depends(get_current_user),
):
    """
    Fetch account balance and status.
    Requires caller to be the account owner or an admin.
    """
    if claims.sub != str(user_id) and "admin" not in claims.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot view another user's account",
        )

    return await account_service.get_account_details(user_id)
