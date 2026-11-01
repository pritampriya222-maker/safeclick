"""
backend/tests/test_auth.py
────────────────────────────────────────────────────────────────────────────
Unit and integration tests for Phase 5 authentication flow.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_register_success(async_client: AsyncClient):
    """Test user registration returns valid tokens."""
    payload = {
        "email": "user@safeclick.io",
        "password": "SecurePassword123!",
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["email"] == "user@safeclick.io"
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_register_duplicate_email(async_client: AsyncClient):
    """Test registering with an existing email returns 409 conflict."""
    payload = {
        "email": "dup@safeclick.io",
        "password": "SecurePassword123!",
    }
    res1 = await async_client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = await async_client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_register_short_password(async_client: AsyncClient):
    """Test password under 8 characters is rejected."""
    payload = {
        "email": "short@safeclick.io",
        "password": "short",
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient):
    """Test login with correct password returns access + refresh tokens."""
    # Register first
    reg_payload = {"email": "login_user@safeclick.io", "password": "Password12345!"}
    await async_client.post("/api/v1/auth/register", json=reg_payload)

    # Login
    login_payload = {"email": "login_user@safeclick.io", "password": "Password12345!"}
    response = await async_client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["email"] == "login_user@safeclick.io"


@pytest.mark.asyncio
async def test_login_invalid_password(async_client: AsyncClient):
    """Test login with incorrect password returns 401."""
    reg_payload = {"email": "wrong_pwd@safeclick.io", "password": "Password12345!"}
    await async_client.post("/api/v1/auth/register", json=reg_payload)

    login_payload = {"email": "wrong_pwd@safeclick.io", "password": "WrongPassword!"}
    response = await async_client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_token_refresh_and_rotation(async_client: AsyncClient):
    """Test token refresh produces a new access token and new rotated refresh token."""
    reg_payload = {"email": "refresh_user@safeclick.io", "password": "Password12345!"}
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    orig_refresh = reg_res.json()["refresh_token"]

    # Refresh
    ref_res = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": orig_refresh})
    assert ref_res.status_code == 200
    ref_data = ref_res.json()
    assert "access_token" in ref_data
    assert "refresh_token" in ref_data
    assert ref_data["refresh_token"] != orig_refresh  # rotated!

    # Old refresh token is now invalid
    invalid_res = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": orig_refresh})
    assert invalid_res.status_code == 401


@pytest.mark.asyncio
async def test_get_me_profile(async_client: AsyncClient):
    """Test /me endpoint requires bearer token and returns profile."""
    # Unauthenticated
    unauth_res = await async_client.get("/api/v1/auth/me")
    assert unauth_res.status_code == 401

    # Authenticated
    reg_payload = {"email": "me_user@safeclick.io", "password": "Password12345!"}
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    access_token = reg_res.json()["access_token"]

    auth_res = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert auth_res.status_code == 200
    assert auth_res.json()["email"] == "me_user@safeclick.io"
    assert auth_res.json()["history_sync_enabled"] is False  # default off


@pytest.mark.asyncio
async def test_logout(async_client: AsyncClient):
    """Test logout invalidates the refresh token."""
    reg_payload = {"email": "logout_user@safeclick.io", "password": "Password12345!"}
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    refresh_token = reg_res.json()["refresh_token"]

    # Logout
    logout_res = await async_client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token})
    assert logout_res.status_code == 204

    # Refreshing with logged out token fails
    ref_res = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert ref_res.status_code == 401
