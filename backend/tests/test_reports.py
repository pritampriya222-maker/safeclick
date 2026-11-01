"""
backend/tests/test_reports.py
────────────────────────────────────────────────────────────────────────────
Unit and integration tests for Phase 5 reported sites and submissions.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_submit_report_anonymous(async_client: AsyncClient):
    """Anonymous users can submit reports without authentication."""
    payload = {
        "url": "https://suspicious-login-portal.fake/login",
        "report_type": "phishing",
        "engine_score": 85.5,
        "notes": "Phishing credential harvest form detected",
    }
    res = await async_client.post("/api/v1/reports", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["domain"] == "suspicious-login-portal.fake"
    assert data["report_type"] == "phishing"
    assert data["status"] == "pending"
    assert data["engine_score"] == 85.5


@pytest.mark.asyncio
async def test_submit_report_authenticated_and_list(async_client: AsyncClient):
    """Authenticated users can submit reports and view their own report history."""
    # Register & get token
    reg = await async_client.post(
        "/api/v1/auth/register",
        json={"email": "reporter@safeclick.io", "password": "Password123!"},
    )
    token = reg.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Submit 2 reports
    r1 = await async_client.post(
        "/api/v1/reports",
        json={"url": "https://malicious1.example/page", "report_type": "phishing"},
        headers=headers,
    )
    assert r1.status_code == 201

    r2 = await async_client.post(
        "/api/v1/reports",
        json={"url": "https://false-alarm.example/home", "report_type": "false_positive"},
        headers=headers,
    )
    assert r2.status_code == 201

    # List own reports
    list_res = await async_client.get("/api/v1/reports", headers=headers)
    assert list_res.status_code == 200
    my_reports = list_res.json()
    assert len(my_reports) == 2
    domains = [r["domain"] for r in my_reports]
    assert "malicious1.example" in domains
    assert "false-alarm.example" in domains


@pytest.mark.asyncio
async def test_list_reports_unauthenticated_fails(async_client: AsyncClient):
    """Listing reports without auth returns 401."""
    res = await async_client.get("/api/v1/reports")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_submit_report_validation(async_client: AsyncClient):
    """Invalid URL or score outside 0-100 returns 422."""
    # Bad URL (no scheme)
    res1 = await async_client.post(
        "/api/v1/reports",
        json={"url": "ftp://not-supported.org"},
    )
    assert res1.status_code == 422

    # Score > 100
    res2 = await async_client.post(
        "/api/v1/reports",
        json={"url": "https://example.com", "engine_score": 150.0},
    )
    assert res2.status_code == 422
