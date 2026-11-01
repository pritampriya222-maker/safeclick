"""
backend/api/reports.py
────────────────────────────────────────────────────────────────────────────
Phase 5: CRUD endpoints for crowdsourced phishing/FP reports.

Rate limiting: 10 reports per hour per IP (slowapi).
Anonymous reports are allowed (reporter_id nullable) but authenticated
reports carry more weight in the aggregation threshold.
"""

import uuid
from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, HttpUrl, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from slowapi import Limiter
from slowapi.util import get_remote_address

from database.db import get_db
from database.models import ReportedSite, ReportType, ReportStatus, User
from services.auth_service import get_optional_user

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])
limiter = Limiter(key_func=get_remote_address)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class SubmitReportRequest(BaseModel):
    url: str
    report_type: ReportType = ReportType.phishing
    engine_score: Optional[float] = None   # Phase 2/3 score at time of report
    notes: Optional[str] = None

    @field_validator("url")
    @classmethod
    def url_must_have_scheme(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v

    @field_validator("engine_score")
    @classmethod
    def score_range(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not (0 <= v <= 100):
            raise ValueError("engine_score must be between 0 and 100")
        return v


class ReportOut(BaseModel):
    id: str
    url: str
    domain: str
    report_type: str
    status: str
    engine_score: Optional[float]
    created_at: datetime


def _extract_domain(url: str) -> str:
    """Extract the registered domain from a URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def _report_to_out(r: ReportedSite) -> ReportOut:
    return ReportOut(
        id=str(r.id),
        url=r.url,
        domain=r.domain,
        report_type=r.report_type.value,
        status=r.status.value,
        engine_score=r.engine_score,
        created_at=r.created_at,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")
async def submit_report(
    request: Request,
    body: SubmitReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    """
    Submit a phishing / false-positive / malware report.
    Rate limited: 10 per hour per IP.
    Authentication is optional — anonymous reports are accepted.
    """
    domain = _extract_domain(body.url)

    report = ReportedSite(
        url=body.url,
        domain=domain,
        reporter_id=current_user.id if current_user else None,
        report_type=body.report_type,
        status=ReportStatus.pending,
        engine_score=body.engine_score,
        notes=body.notes,
        created_at=datetime.now(timezone.utc),
    )
    db.add(report)
    await db.flush()
    return _report_to_out(report)


@router.get("", response_model=list[ReportOut])
async def list_my_reports(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_optional_user),
    limit: int = 50,
    offset: int = 0,
):
    """List the authenticated user's own submitted reports (requires auth)."""
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to list your reports",
        )

    result = await db.execute(
        select(ReportedSite)
        .where(ReportedSite.reporter_id == current_user.id)
        .order_by(ReportedSite.created_at.desc())
        .limit(min(limit, 100))
        .offset(offset)
    )
    reports = result.scalars().all()
    return [_report_to_out(r) for r in reports]


@router.get("/{report_id}", response_model=ReportOut)
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_optional_user),
):
    """Get a specific report by ID (must be the report's owner)."""
    if current_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid report ID")

    result = await db.execute(
        select(ReportedSite).where(
            ReportedSite.id == rid,
            ReportedSite.reporter_id == current_user.id,
        )
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    return _report_to_out(report)
