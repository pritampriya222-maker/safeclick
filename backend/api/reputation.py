"""
backend/api/reputation.py
────────────────────────────────────────────────────────────────────────────
GET /api/v1/reputation?domain=example.com

Contract (documented in docs/api-contracts.md):
    Request:  GET /api/v1/reputation?domain=example.com
    Response: {
        "domain": "example.com",
        "known_malicious": false,
        "source": "openphish" | "virustotal" | "local_blocklist" | "unavailable",
        "last_checked": "2024-01-15T12:00:00Z",
        "confidence": 0.95,
        "detail": "..."  // optional human-readable note
    }

Error cases:
    400 — domain param missing or invalid
    422 — Pydantic validation error
    503 — upstream service error (should be rare; most errors degrade to 'unavailable')
"""

from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Query, Request, HTTPException
from pydantic import BaseModel, Field


router = APIRouter(tags=["Reputation"])


# ── Response schema ────────────────────────────────────────────────────────────

class ReputationResponse(BaseModel):
    """
    Domain reputation lookup result.
    All fields documented in docs/api-contracts.md.
    """
    domain: str = Field(..., description="The domain that was checked.")
    known_malicious: bool = Field(..., description="True if this domain is known to be malicious.")
    source: Literal[
        "virustotal", "openphish", "local_blocklist",
        "top_domain_list", "unavailable", "cache"
    ] = Field(..., description="Data source for this verdict.")
    last_checked: str = Field(..., description="ISO 8601 timestamp of when this was checked.")
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confidence in the verdict (0 = unknown, 1 = high confidence)."
    )
    detail: str | None = Field(None, description="Human-readable note about the finding.")

    model_config = {"json_schema_extra": {
        "example": {
            "domain": "example.com",
            "known_malicious": False,
            "source": "unavailable",
            "last_checked": "2024-01-15T12:00:00Z",
            "confidence": 0.0,
            "detail": "Domain not found in any reputation database."
        }
    }}


# ── Endpoint ───────────────────────────────────────────────────────────────────

@router.get(
    "/reputation",
    response_model=ReputationResponse,
    summary="Check domain reputation",
    description=(
        "Look up whether a domain is known to be malicious. "
        "Checks VirusTotal (if configured), then OpenPhish community feed, "
        "then falls back to 'unavailable' if both are unreachable. "
        "Results are cached for up to 6 hours to respect free-tier rate limits."
    ),
)
async def get_reputation(
    request: Request,
    domain: str = Query(
        ...,
        min_length=1,
        max_length=255,
        description="Registered domain to check (e.g. 'example.com').",
        examples=["example.com"],
    ),
) -> ReputationResponse:
    """Look up domain reputation."""
    # Basic domain validation
    domain = domain.strip().lower().lstrip("www.")
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format.")

    # Get the shared reputation service from app state
    service = request.app.state.reputation_service
    result = await service.check_domain(domain)

    return ReputationResponse(
        domain=result.domain,
        known_malicious=result.known_malicious,
        source=result.source,
        last_checked=result.last_checked,
        confidence=result.confidence,
        detail=result.detail,
    )
