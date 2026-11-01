"""
backend/api/analytics.py
────────────────────────────────────────────────────────────────────────────
Phase 5: Aggregate platform analytics endpoint.
This is operational monitoring data for the SafeClick team — not per-user data.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from database.db import get_db
from services.analytics_service import get_platform_stats

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])


@router.get("/stats")
async def platform_stats(
    days: int = Query(7, ge=1, le=90, description="Number of days to aggregate"),
    db: AsyncSession = Depends(get_db),
):
    """
    Return aggregate platform statistics.
    No per-user data, no full URLs, no browsing history.
    Suitable for operational dashboards — not per-user reporting.
    """
    return await get_platform_stats(db, days=days)
