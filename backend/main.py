"""
SafeClick Backend — FastAPI Application Entry Point
────────────────────────────────────────────────────────────────────────────
Phase 5: Cloud Backend added on top of Phase 3 Intelligence Layer.

Start:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Or:
    python -m uvicorn main:app --reload

Phase 5 features (all opt-in, Phase 1–4 fully functional without them):
  - PostgreSQL via SQLAlchemy asyncpg (requires DATABASE_URL in .env)
  - JWT authentication (register/login/refresh/logout)
  - Crowdsourced threat intelligence reports + aggregation
  - Shared threat intel lookup (/api/v1/threat-intel/lookup)
  - Aggregate analytics (/api/v1/analytics/stats)
  - Background aggregation loop (1-hour interval)
"""

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from api.reputation import router as reputation_router
from api.predict import router as predict_router
from api.auth import router as auth_router
from api.reports import router as reports_router
from api.threat_intel import router as threat_intel_router
from api.analytics import router as analytics_router
from services.reputation_service import ReputationService
from services.ml_service import MlService
from services.rule_engine import get_rule_engine
from database.db import init_db, close_db, get_session_factory
from services.threat_intel_aggregator import start_aggregation_loop


# ── Shared service instances ───────────────────────────────────────────────────
reputation_service = ReputationService()
ml_service = MlService()
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context: runs startup and shutdown logic."""
    # Phase 2: Reputation service
    if not getattr(app.state, "reputation_service", None):
        print("[SafeClick] Starting up — loading reputation data...")
        await reputation_service.initialize()
        app.state.reputation_service = reputation_service
        print("[SafeClick] Reputation service ready.")

    # Phase 3: ML service (loads model from disk once)
    if not getattr(app.state, "ml_service", None):
        ml_service.load()
        app.state.ml_service = ml_service

    # Phase 3: Rule engine (lazy singleton — warm up now)
    _ = get_rule_engine()
    print("[SafeClick] Rule engine ready.")

    # Phase 5: Database (gracefully disabled if DATABASE_URL not set)
    db_available = await init_db()
    app.state.db_available = db_available

    # Phase 5: Threat intel aggregation background loop
    if db_available:
        session_factory = get_session_factory()
        app.state.aggregation_task = asyncio.create_task(
            start_aggregation_loop(session_factory)
        )
        print("[SafeClick] Threat intel aggregation loop started.")

    yield

    # Shutdown
    if hasattr(app.state, "aggregation_task"):
        app.state.aggregation_task.cancel()
        try:
            await app.state.aggregation_task
        except asyncio.CancelledError:
            pass

    await close_db()
    print("[SafeClick] Shutting down.")


# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SafeClick Intelligence API",
    description=(
        "Phase 5 backend for the SafeClick browser extension. "
        "Provides domain reputation (Phase 2), ML-powered phishing prediction (Phase 3), "
        "declarative rule engine, confidence-scored explainable verdicts, "
        "and opt-in cloud features: user accounts, crowdsourced threat intelligence, "
        "and shared reports (Phase 5)."
    ),
    version="0.5.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Rate limiter ───────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Extension origin is chrome-extension://<id>; wildcard for dev
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Accept", "Content-Type", "Authorization"],
)

# ── Routers ────────────────────────────────────────────────────────────────────
# Phase 1–3 (local-first, always available)
app.include_router(reputation_router, prefix="/api/v1")
app.include_router(predict_router, prefix="/api/v1")

# Phase 5 (cloud features — gracefully degrade if DB unavailable)
app.include_router(auth_router)
app.include_router(reports_router)
app.include_router(threat_intel_router)
app.include_router(analytics_router)


@app.get("/health", tags=["System"])
async def health_check(request: Request):
    """Health check endpoint for monitoring."""
    return {
        "status": "ok",
        "version": "0.5.0",
        "service": "safeclick-intelligence",
        "ml_model_loaded": ml_service.is_loaded,
        "db_available": getattr(request.app.state, "db_available", False),
    }
