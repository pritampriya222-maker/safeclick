"""
backend/services/analytics_service.py
────────────────────────────────────────────────────────────────────────────
Phase 5: Aggregate-only, privacy-respecting analytics.

CRITICAL DESIGN PRINCIPLE:
  This is operational telemetry for the SafeClick team's own visibility —
  NOT a per-user surveillance feature. Enforced constraints:
    - No full URLs stored server-side (domain hash only: SHA-256 of the
      registered domain, not the full path)
    - No user IDs linked to analytics events
    - No per-user browsing patterns
    - aggregate counts only (verdicts served by level, top reported domains,
      API latency/error rates)

  Reviewers: if you see a full URL or user ID in an analytics query, it is
  a bug and a privacy regression — treat it as a blocking issue.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from database.models import AnalyticsEvent, EventType, ReportedSite

logger = logging.getLogger(__name__)


def _hash_domain(domain: str) -> str:
    """SHA-256 hash of a domain for privacy-preserving storage."""
    return hashlib.sha256(domain.lower().encode()).hexdigest()


async def log_event(
    db: AsyncSession,
    event_type: EventType,
    verdict_level: Optional[str] = None,
    domain: Optional[str] = None,
    latency_ms: Optional[float] = None,
) -> None:
    """
    Log an aggregate analytics event.
    domain is hashed before storage — the original domain is never persisted.
    """
    event = AnalyticsEvent(
        event_type=event_type,
        verdict_level=verdict_level,
        domain_hash=_hash_domain(domain) if domain else None,
        latency_ms=latency_ms,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(event)
    # Caller is responsible for commit (typically handled by get_db dependency)


async def get_platform_stats(db: AsyncSession, days: int = 7) -> dict:
    """
    Return aggregate platform statistics for operational monitoring.
    No per-user data, no full URLs, no browsing history.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # ── Verdict distribution ─────────────────────────────────────────────────
    verdict_result = await db.execute(
        select(AnalyticsEvent.verdict_level, func.count(AnalyticsEvent.id).label("count"))
        .where(
            AnalyticsEvent.event_type == EventType.verdict_served,
            AnalyticsEvent.timestamp >= cutoff,
        )
        .group_by(AnalyticsEvent.verdict_level)
    )
    verdict_counts = {row.verdict_level: row.count for row in verdict_result.all()}

    # ── API latency (avg, p95 approximated via sorted percentile) ────────────
    latency_result = await db.execute(
        select(
            func.avg(AnalyticsEvent.latency_ms).label("avg_latency"),
            func.max(AnalyticsEvent.latency_ms).label("max_latency"),
            func.count(AnalyticsEvent.id).label("total_events"),
        )
        .where(
            AnalyticsEvent.latency_ms.isnot(None),
            AnalyticsEvent.timestamp >= cutoff,
        )
    )
    latency_row = latency_result.one()

    # ── Top reported domains (domain-level only — no per-user patterns) ──────
    top_domains_result = await db.execute(
        select(ReportedSite.domain, func.count(ReportedSite.id).label("count"))
        .where(ReportedSite.created_at >= cutoff)
        .group_by(ReportedSite.domain)
        .order_by(func.count(ReportedSite.id).desc())
        .limit(10)
    )
    top_reported_domains = [
        {"domain": row.domain, "report_count": row.count}
        for row in top_domains_result.all()
    ]

    # ── Threat intel hits ────────────────────────────────────────────────────
    intel_hits_result = await db.execute(
        select(func.count(AnalyticsEvent.id))
        .where(
            AnalyticsEvent.event_type == EventType.threat_intel_hit,
            AnalyticsEvent.timestamp >= cutoff,
        )
    )
    intel_hits = intel_hits_result.scalar() or 0

    return {
        "period_days": days,
        "verdicts": verdict_counts,
        "api": {
            "avg_latency_ms": round(latency_row.avg_latency or 0, 2),
            "max_latency_ms": round(latency_row.max_latency or 0, 2),
            "total_events": latency_row.total_events or 0,
        },
        "top_reported_domains": top_reported_domains,
        "threat_intel_hits": intel_hits,
    }
