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


async def read_authorized_account(user_id: UUID, request: Request, claims: TokenClaims):
    from decimal import Decimal
    from src.policy import policy_client
    from src.middleware import log_audit_event

    if claims.sub != str(user_id) and "admin" not in claims.roles:
        raise HTTPException(status_code=403, detail="Forbidden: Cannot view another user's account")
    resource = f"account_{user_id}"
    allowed, reason = await policy_client.evaluate(
        user_id=claims.sub, roles=claims.roles, action="READ_ACCOUNT", resource=resource,
        amount=Decimal("0"), ip_address=request.state.client_ip,
        mtls_verified=request.state.mtls_verified)
    log_audit_event("access_decision", "permit" if allowed else "deny", "READ_ACCOUNT", resource,
                    user_id=claims.sub, traceparent=request.state.traceparent, reason=reason)
    if not allowed:
        raise HTTPException(status_code=403, detail="Policy authorization rejected")
    return await account_service.get_account_details(user_id)


@router.get("", response_model=AccountResponse)
async def get_own_account(request: Request, claims: TokenClaims = Depends(get_current_user)):
    return await read_authorized_account(UUID(claims.sub), request, claims)


@router.get("/{user_id}", response_model=AccountResponse)
async def get_account(user_id: UUID, request: Request, claims: TokenClaims = Depends(get_current_user)):
    return await read_authorized_account(user_id, request, claims)
