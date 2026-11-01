"""
backend/tests/test_threat_intel.py
────────────────────────────────────────────────────────────────────────────
Tests for crowdsourced threat intelligence lookup, promotion logic, and analytics.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database.models import ReportedSite, SharedThreatIntel, ReportType, ReportStatus
from services.threat_intel_aggregator import check_and_promote_domain
from services.analytics_service import log_event, get_platform_stats, EventType


@pytest.mark.asyncio
async def test_threat_intel_lookup_clean_domain(async_client: AsyncClient):
    """Unknown or unconfirmed domain returns is_threat=False with low confidence."""
    res = await async_client.get("/api/v1/threat-intel/lookup?domain=clean-site.org")
    assert res.status_code == 200
    data = res.json()
    assert data["domain"] == "clean-site.org"
    assert data["is_threat"] is False
    assert data["report_count"] == 0
    assert "No community reports" in data["label"]


@pytest.mark.asyncio
async def test_threat_intel_promotion_threshold(db_session: AsyncSession, async_client: AsyncClient):
    """
    Test promotion conditions:
      1. Less than MIN_REPORTS (3) reports -> NOT promoted
      2. 3 reports but low engine_score (< 60) -> NOT promoted
      3. 3 reports with engine_score >= 60 -> PROMOTED to SharedThreatIntel
    """
    domain = "phish-bank-secure.xyz"

    # Case 1: Only 2 reports
    db_session.add_all([
        ReportedSite(url=f"https://{domain}/login1", domain=domain, report_type=ReportType.phishing, engine_score=75.0),
        ReportedSite(url=f"https://{domain}/login2", domain=domain, report_type=ReportType.phishing, engine_score=80.0),
    ])
    await db_session.flush()

    promoted = await check_and_promote_domain(domain, db_session)
    assert promoted is None  # 2 reports < threshold 3

    # Case 2: 3rd report added, but with very low engine score bringing average below 60
    db_session.add(
        ReportedSite(url=f"https://{domain}/low", domain=domain, report_type=ReportType.phishing, engine_score=10.0)
    )
    await db_session.flush()
    # avg = (75 + 80 + 10) / 3 = 55 < 60
    promoted = await check_and_promote_domain(domain, db_session)
    assert promoted is None

    # Case 3: 4th report with high score pushes average above 60
    db_session.add(
        ReportedSite(url=f"https://{domain}/high", domain=domain, report_type=ReportType.phishing, engine_score=90.0)
    )
    await db_session.flush()
    # avg = (75 + 80 + 10 + 90) / 4 = 63.75 >= 60

    promoted = await check_and_promote_domain(domain, db_session)
    assert promoted is not None
    assert promoted.domain == domain
    assert promoted.report_count == 4
    await db_session.commit()

    # Now verify the lookup endpoint reflects the newly promoted threat!
    res = await async_client.get(f"/api/v1/threat-intel/lookup?domain={domain}")
    assert res.status_code == 200
    intel_data = res.json()
    assert intel_data["is_threat"] is True
    assert intel_data["report_count"] == 4
    assert "Flagged by 4 SafeClick users" in intel_data["label"]


@pytest.mark.asyncio
async def test_analytics_logging_and_stats(db_session: AsyncSession, async_client: AsyncClient):
    """Test privacy-preserving analytics logs domain hashes only and computes aggregate stats."""
    # Log several events
    await log_event(db_session, EventType.verdict_served, verdict_level="safe", domain="example.com", latency_ms=12.5)
    await log_event(db_session, EventType.verdict_served, verdict_level="dangerous", domain="malware.test", latency_ms=18.2)
    await log_event(db_session, EventType.threat_intel_hit, domain="threat.test")
    await db_session.commit()

    stats = await get_platform_stats(db_session, days=7)
    assert stats["period_days"] == 7
    assert stats["verdicts"].get("safe") == 1
    assert stats["verdicts"].get("dangerous") == 1
    assert stats["threat_intel_hits"] == 1
    assert stats["api"]["total_events"] == 2

    # Verify via endpoint
    res = await async_client.get("/api/v1/analytics/stats?days=7")
    assert res.status_code == 200
    data = res.json()
    assert "verdicts" in data
    assert "api" in data
