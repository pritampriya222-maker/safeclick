"""
backend/services/auth_service.py
────────────────────────────────────────────────────────────────────────────
Phase 5: Authentication helpers — bcrypt password hashing, JWT token
issuance/verification, and a FastAPI dependency for the current user.

JWT Token Design (extension-side tradeoff documented in docs/architecture.md):
  Access token: 15 minutes TTL, signed HS256 JWT
  Refresh token: 7-day TTL, stored hashed in the `devices` table.

  TRADEOFF: Chrome extensions cannot use httpOnly cookies since the background
  service worker has no HTTP context for cookie jar management. Tokens are
  therefore stored in chrome.storage.local (extension side). While this
  is less secure than httpOnly cookies in a browser tab, it is the only
  viable option for MV3 extensions. Mitigations:
    - Short access token lifetime (15 min)
    - Refresh tokens are hashed in the DB (bcrypt), not stored plaintext
    - Extension origin is a unique chrome-extension:// scheme, isolated from web origins
"""

import os
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database.db import get_db
from database.models import User, Device


# ── Config ────────────────────────────────────────────────────────────────────

JWT_SECRET: str = os.getenv("JWT_SECRET", "INSECURE_DEFAULT_CHANGE_IN_PRODUCTION")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))

_http_bearer = HTTPBearer(auto_error=False)


# ── Password hashing (direct bcrypt) ──────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt (truncated to 72 bytes per bcrypt standard)."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        return bcrypt.checkpw(pwd_bytes, hashed_password.encode("utf-8"))
    except Exception:
        return False


def hash_refresh_token(token: str) -> str:
    """SHA-256 hash a refresh token for DB storage (not stored plaintext)."""
    return hashlib.sha256(token.encode()).hexdigest()


# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_access_token(user_id: str, email: str) -> str:
    """Create a short-lived JWT access token (15 min default)."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "email": email,
        "type": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str, device_id: str) -> str:
    """Create a long-lived refresh token (7 days default). Stored hashed in DB."""
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": str(user_id),
        "device_id": str(device_id),
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),   # unique ID for revocation
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    Raises HTTPException 401 on any validation failure.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token invalid or expired: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI dependencies ──────────────────────────────────────────────────────

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_http_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency: extract and validate the Bearer token, return the User.
    Raises 401 if token is missing, invalid, or user not found/inactive.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type — expected access token",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account deactivated",
        )

    return user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_http_bearer),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    Like get_current_user but returns None instead of raising if not authenticated.
    Used for endpoints that work both authenticated and anonymously (e.g. report submission).
    """
    if credentials is None or not credentials.credentials:
        return None
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None
