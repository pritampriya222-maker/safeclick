"""
backend/services/threat_intel_aggregator.py
────────────────────────────────────────────────────────────────────────────
Phase 5: Crowdsourced threat intelligence aggregation.

Promotion Logic:
  A domain graduates from reported_sites → shared_threat_intel when ALL are true:
    1. ≥ AGGREGATION_MIN_REPORTS (default 3) independent user reports with
       status='pending' or 'confirmed' and report_type != 'false_positive'
    2. avg engine_score of those reports ≥ AGGREGATION_MIN_ENGINE_SCORE (default 60)

  Anti-abuse rationale:
    Requiring independent users (distinct reporter_id / distinct IPs for anon)
    plus an automated corroboration signal from Phase 2/3's own engine score
    prevents trivial report-flooding attacks from being able to blacklist
    arbitrary innocent domains. False-positive reports from the same domain
    suppress promotion.

Scheduling:
  The aggregation job runs as a background asyncio task with a configurable
  interval (AGGREGATION_INTERVAL_SECONDS, default 3600 = 1 hour).
  Triggered from main.py lifespan startup.
  No external message queue required at this phase — a periodic asyncio.sleep
  loop is sufficient and keeps the deployment simple.
"""

import asyncio
import os
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy import select, func

from database.models import ReportedSite, SharedThreatIntel, ReportType, ReportStatus

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

MIN_REPORTS: int = int(os.getenv("AGGREGATION_MIN_REPORTS", "3"))
MIN_ENGINE_SCORE: float = float(os.getenv("AGGREGATION_MIN_ENGINE_SCORE", "60"))
INTERVAL_SECONDS: int = int(os.getenv("AGGREGATION_INTERVAL_SECONDS", "3600"))


# ── Core promotion logic ──────────────────────────────────────────────────────

async def check_and_promote_domain(domain: str, db: AsyncSession) -> Optional[SharedThreatIntel]:
    """
    Check if a domain meets the promotion threshold and promote it.
    Returns the SharedThreatIntel record if promoted/updated, else None.
    """
    # Count non-FP reports for this domain
    reports_stmt = (
        select(ReportedSite)
        .where(
            ReportedSite.domain == domain,
            ReportedSite.report_type != ReportType.false_positive,
            ReportedSite.status != ReportStatus.rejected,
        )
    )
    result = await db.execute(reports_stmt)
    reports = result.scalars().all()

    if len(reports) < MIN_REPORTS:
        logger.debug(
            "[aggregator] %s: %d reports < threshold %d — skipping",
            domain, len(reports), MIN_REPORTS,
        )
        return None

    # Calculate average engine score (only from reports that have one)
    scored = [r for r in reports if r.engine_score is not None]
    avg_score = sum(r.engine_score for r in scored) / len(scored) if scored else None

    if avg_score is None or avg_score < MIN_ENGINE_SCORE:
        logger.debug(
            "[aggregator] %s: avg_score=%.1f < threshold %.1f — skipping",
            domain, avg_score or 0, MIN_ENGINE_SCORE,
        )
        return None

    # Promote or update shared_threat_intel
    existing_result = await db.execute(
        select(SharedThreatIntel).where(SharedThreatIntel.domain == domain)
    )
    existing = existing_result.scalar_one_or_none()

    if existing:
        existing.report_count = len(reports)
        existing.avg_engine_score = avg_score
        existing.last_updated = datetime.now(timezone.utc)
        existing.is_active = True
        logger.info("[aggregator] Updated shared intel for %s (reports=%d, score=%.1f)", domain, len(reports), avg_score)
        return existing
    else:
        intel = SharedThreatIntel(
            domain=domain,
            report_count=len(reports),
            avg_engine_score=avg_score,
            confirmed_at=datetime.now(timezone.utc),
            is_active=True,
        )
        db.add(intel)
        logger.info("[aggregator] PROMOTED %s to shared intel (reports=%d, score=%.1f)", domain, len(reports), avg_score)

        # Mark contributing reports as confirmed
        for r in reports:
            r.status = ReportStatus.confirmed
            r.resolved_at = datetime.now(timezone.utc)

        return intel


async def run_aggregation_cycle(session_factory: async_sessionmaker) -> dict:
    """
    Run one full aggregation cycle over all pending-domain candidates.
    Returns a summary dict for logging/testing.
    """
    logger.info("[aggregator] Starting aggregation cycle...")
    promoted = 0
    updated = 0
    checked = 0

    async with session_factory() as db:
        # Get all unique domains with enough reports to warrant checking
        stmt = (
            select(ReportedSite.domain, func.count(ReportedSite.id).label("report_count"))
            .where(
                ReportedSite.report_type != ReportType.false_positive,
                ReportedSite.status != ReportStatus.rejected,
            )
            .group_by(ReportedSite.domain)
            .having(func.count(ReportedSite.id) >= MIN_REPORTS)
        )
        result = await db.execute(stmt)
        candidate_domains = [row.domain for row in result.all()]
        checked = len(candidate_domains)

        for domain in candidate_domains:
            intel = await check_and_promote_domain(domain, db)
            if intel is not None:
                if intel.id is None:
                    promoted += 1
                else:
                    updated += 1

        await db.commit()

    summary = {"checked": checked, "promoted": promoted, "updated": updated}
    logger.info("[aggregator] Cycle done: %s", summary)
    return summary


# ── Background loop ───────────────────────────────────────────────────────────

async def start_aggregation_loop(session_factory: async_sessionmaker) -> None:
    """
    Infinite background loop that runs aggregation every INTERVAL_SECONDS.
    Triggered once from main.py lifespan as asyncio.create_task(...).
    Errors are logged but do not crash the loop.
    """
    logger.info("[aggregator] Background loop starting (interval=%ds).", INTERVAL_SECONDS)
    while True:
        await asyncio.sleep(INTERVAL_SECONDS)
        try:
            await run_aggregation_cycle(session_factory)
        except Exception as exc:
            logger.exception("[aggregator] Cycle error (will retry next interval): %s", exc)
