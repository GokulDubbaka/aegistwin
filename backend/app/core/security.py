"""JWT authentication helpers for AegisTwin backend."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# ─── Password hashing ────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if plain_password matches the stored bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Return a bcrypt hash of the given password."""
    return pwd_context.hash(password)


# ─── JWT token creation ───────────────────────────────────────────────────────
def create_access_token(
    subject: str,
    tenant_id: str,
    role: str = "analyst",
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a signed JWT.

    Payload claims:
      sub        — user ID (opaque string)
      tenant_id  — tenant the user belongs to (cannot be changed by caller)
      role       — user role for RBAC
      jti        — unique token ID (for future revocation support)
      exp / iat  — standard expiry / issued-at
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    payload: dict[str, Any] = {
        "sub": subject,
        "tenant_id": tenant_id,
        "role": role,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


# ─── JWT token decoding ───────────────────────────────────────────────────────
def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT.  Raises jose.JWTError on any failure.
    The caller (deps.py) is responsible for converting this to an HTTP 401.
    """
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


__all__ = [
    "verify_password",
    "hash_password",
    "create_access_token",
    "decode_access_token",
]
