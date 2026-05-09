"""
FastAPI dependency functions for AegisTwin.

Usage in endpoint files:

    from app.core.deps import get_current_user, require_tenant

    @router.get("/assets")
    async def list_assets(
        db: AsyncSession = Depends(get_db),
        current_user: TokenPayload = Depends(get_current_user),
    ):
        # current_user.tenant_id is cryptographically verified — never use
        # query params for tenant scoping.
        ...
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from pydantic import BaseModel

from app.core.security import decode_access_token

# ─── Token payload schema ─────────────────────────────────────────────────────
class TokenPayload(BaseModel):
    sub: str           # user ID
    tenant_id: str     # tenant ID — always sourced from JWT, never from request
    role: str = "analyst"
    jti: str | None = None


# ─── Bearer scheme (auto-generates 401 when header is missing) ────────────────
bearer_scheme = HTTPBearer(auto_error=True)


# ─── Core dependency ──────────────────────────────────────────────────────────
async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
) -> TokenPayload:
    """
    Validate the Bearer JWT and return the decoded payload.

    This is the single source of truth for tenant_id in every authenticated
    endpoint.  Callers MUST NOT accept tenant_id from query parameters or
    request bodies for data-scoping purposes.
    """
    _credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(credentials.credentials)
        user_id: str | None = payload.get("sub")
        tenant_id: str | None = payload.get("tenant_id")
        role: str = payload.get("role", "analyst")
        if not user_id or not tenant_id:
            raise _credentials_exception
    except JWTError:
        raise _credentials_exception

    return TokenPayload(sub=user_id, tenant_id=tenant_id, role=role, jti=payload.get("jti"))


# ─── Role-based access shortcuts ─────────────────────────────────────────────
def require_role(*allowed_roles: str):
    """
    Dependency factory for role-based access control.

    Usage:
        @router.delete("/missions/{id}")
        async def delete_mission(
            current_user: TokenPayload = Depends(require_role("admin", "red_team")),
        ): ...
    """
    async def _check(
        current_user: Annotated[TokenPayload, Depends(get_current_user)],
    ) -> TokenPayload:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not permitted for this operation.",
            )
        return current_user
    return _check


# ─── Auth endpoint schemas ────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


__all__ = [
    "TokenPayload",
    "get_current_user",
    "require_role",
    "LoginRequest",
    "TokenResponse",
]
