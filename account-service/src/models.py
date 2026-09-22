"""Pydantic data models and schemas for Account Service."""

from decimal import Decimal
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, Field


class DeductRequest(BaseModel):
    """Request contract for POST /api/v1/accounts/deduct (docs/contacts.md)."""
    user_id: UUID = Field(..., description="UUID of the account owner to deduct from")
    amount: Decimal = Field(..., gt=Decimal("0.00"), description="Positive deduction amount")


class DeductResponse(BaseModel):
    """Response returned upon successful balance deduction."""
    status: str = "success"
    user_id: UUID
    deducted_amount: Decimal
    remaining_balance: Decimal


class AccountResponse(BaseModel):
    """Account profile and balance representation."""
    user_id: UUID
    balance: Decimal
    status: str


class TokenClaims(BaseModel):
    """Claims extracted from verified JWT."""
    sub: str
    roles: List[str] = Field(default_factory=list)
    device_id: Optional[str] = None


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: str
    code: Optional[str] = None
