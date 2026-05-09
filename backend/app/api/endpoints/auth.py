"""Authentication endpoints — login and token refresh."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import LoginRequest, TokenResponse, get_current_user, TokenPayload
from app.core.security import create_access_token, verify_password
from app.db.session import get_db

router = APIRouter()


@router.post("/login", response_model=TokenResponse, summary="Obtain JWT access token")
async def login(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Exchange email + password for a signed JWT.

    The returned token must be included in the Authorization header as:
        Authorization: Bearer <token>
    """
    # Look up the user by email
    result = await db.execute(
        text("SELECT id, tenant_id, hashed_password, role, is_active FROM users WHERE email = :email"),
        {"email": body.email},
    )
    row = result.mappings().first()

    if not row:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not row["is_active"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is disabled")

    if not verify_password(body.password, row["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(
        subject=row["id"],
        tenant_id=row["tenant_id"],
        role=row["role"],
    )
    return TokenResponse(access_token=token)


@router.get("/me", response_model=TokenPayload, summary="Return the caller's token payload")
async def me(
    current_user: TokenPayload = Depends(get_current_user),
) -> TokenPayload:
    """Return the decoded JWT claims for the currently authenticated user."""
    return current_user
