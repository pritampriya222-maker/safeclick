"""
backend/api/auth.py
────────────────────────────────────────────────────────────────────────────
Phase 5: Auth endpoints — register, login, refresh, logout.

Token storage note (documented tradeoff):
  Tokens are returned in JSON response bodies so the extension can store them
  in chrome.storage.local (the only viable storage for MV3 background service
  workers). httpOnly cookies are NOT used because the extension background
  context has no cookie jar. See docs/architecture.md for full discussion.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database.db import get_db
from database.models import User, Device
from services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_refresh_token,
    get_current_user,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    email: str


class UserOut(BaseModel):
    user_id: str
    email: str
    history_sync_enabled: bool


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _create_tokens_and_device(user: User, db: AsyncSession) -> dict:
    """Issue new access + refresh tokens, create a Device record for this session."""
    device_id = uuid.uuid4()
    access_token = create_access_token(str(user.id), user.email)
    refresh_token = create_refresh_token(str(user.id), str(device_id))

    device = Device(
        id=device_id,
        user_id=user.id,
        refresh_token_hash=hash_refresh_token(refresh_token),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(device)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user_id": str(user.id),
        "email": user.email,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    Create a new user account.
    Returns access + refresh tokens immediately so the user is logged in.
    No email verification required in Phase 5 — documented as a Phase 6 improvement.
    """
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        is_active=True,
        history_sync_enabled=False,  # off by default — explicit separate opt-in
    )
    db.add(user)
    await db.flush()  # get user.id before creating device

    tokens = await _create_tokens_and_device(user, db)
    return AuthResponse(**tokens)


@router.post("/login", response_model=AuthResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate with email + password, return tokens."""
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account deactivated",
        )

    tokens = await _create_tokens_and_device(user, db)
    return AuthResponse(**tokens)


@router.post("/refresh", response_model=AuthResponse)
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """
    Exchange a valid refresh token for a new access + refresh token pair.
    Implements token rotation: old refresh token is invalidated on use.
    """
    payload = decode_token(body.refresh_token)

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = payload.get("sub")
    device_id = payload.get("device_id")

    if not user_id or not device_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token")

    # Verify device + token hash match
    device_result = await db.execute(
        select(Device).where(
            Device.id == uuid.UUID(device_id),
            Device.user_id == uuid.UUID(user_id),
        )
    )
    device = device_result.scalar_one_or_none()

    if not device or device.refresh_token_hash != hash_refresh_token(body.refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked or invalid",
        )

    user_result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Token rotation: issue new tokens, update device record
    new_access = create_access_token(str(user.id), user.email)
    new_refresh = create_refresh_token(str(user.id), str(device.id))
    device.refresh_token_hash = hash_refresh_token(new_refresh)
    device.last_seen = datetime.now(timezone.utc)

    return AuthResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        user_id=str(user.id),
        email=user.email,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Invalidate the refresh token (clear the device record's token hash).
    The client must discard both tokens from chrome.storage.local.
    """
    try:
        payload = decode_token(body.refresh_token)
        device_id = payload.get("device_id")
        if device_id:
            result = await db.execute(select(Device).where(Device.id == uuid.UUID(device_id)))
            device = result.scalar_one_or_none()
            if device:
                device.refresh_token_hash = None
    except Exception:
        pass  # logout is always "successful" from client perspective
    return None


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    """Return the current authenticated user's profile."""
    return UserOut(
        user_id=str(current_user.id),
        email=current_user.email,
        history_sync_enabled=current_user.history_sync_enabled,
    )
