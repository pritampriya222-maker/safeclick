"""
backend/api/threat_intel.py
────────────────────────────────────────────────────────────────────────────
Phase 5: Shared threat intelligence lookup endpoint.

Open endpoint — no authentication required.
The extension's Phase 2 reputation client queries this in addition to
OpenPhish and VirusTotal. Results are labeled with provenance so they
are never presented as indistinguishable from automated detection.

Example response:
  {
    "domain": "evil-phish.example.com",
    "is_threat": true,
    "report_count": 7,
    "avg_engine_score": 82.4,
    "confidence": "high",
    "label": "Flagged by 7 SafeClick users"
  }
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database.db import get_db
from database.models import SharedThreatIntel

router = APIRouter(prefix="/api/v1/threat-intel", tags=["threat-intel"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ThreatIntelResponse(BaseModel):
    domain: str
    is_threat: bool
    report_count: int
    avg_engine_score: Optional[float]
    confidence: str   # "low" | "medium" | "high"
    label: str        # human-readable provenance string for extension UI


def _confidence_level(report_count: int, avg_score: Optional[float]) -> str:
    score = avg_score or 0
    if report_count >= 10 and score >= 80:
        return "high"
    elif report_count >= 5 and score >= 60:
        return "medium"
    return "low"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/lookup", response_model=ThreatIntelResponse)
async def lookup_domain(
    domain: str = Query(..., min_length=1, max_length=255, description="Domain to look up"),
    db: AsyncSession = Depends(get_db),
):
    """
    Look up a domain in the shared threat intelligence table.
    Open endpoint — no auth required.
    Returns is_threat=false if the domain is not in the shared intel table.

    Provenance label in the response MUST be shown to users as distinct from
    automated detection signals ("Flagged by N SafeClick users") — never merged
    silently with VirusTotal/OpenPhish as if from the same source.
    """
    # Normalize domain (strip www., lowercase)
    clean_domain = domain.lower().removeprefix("www.")

    result = await db.execute(
        select(SharedThreatIntel).where(
            SharedThreatIntel.domain == clean_domain,
            SharedThreatIntel.is_active == True,
        )
    )
    intel = result.scalar_one_or_none()

    if intel is None:
        return ThreatIntelResponse(
            domain=clean_domain,
            is_threat=False,
            report_count=0,
            avg_engine_score=None,
            confidence="low",
            label="No community reports found",
        )

    confidence = _confidence_level(intel.report_count, intel.avg_engine_score)
    label = f"Flagged by {intel.report_count} SafeClick user{'s' if intel.report_count != 1 else ''}"

    return ThreatIntelResponse(
        domain=clean_domain,
        is_threat=True,
        report_count=intel.report_count,
        avg_engine_score=intel.avg_engine_score,
        confidence=confidence,
        label=label,
    )
