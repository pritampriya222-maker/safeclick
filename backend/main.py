"""
SafeClick Backend — FastAPI Application Entry Point
────────────────────────────────────────────────────────────────────────────
Phase 3: Intelligence Layer added on top of Phase 2 reputation service.

Start:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Or:
    python -m uvicorn main:app --reload
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.reputation import router as reputation_router
from api.predict import router as predict_router
from services.reputation_service import ReputationService
from services.ml_service import MlService
from services.rule_engine import get_rule_engine


# ── Shared service instances ───────────────────────────────────────────────────
reputation_service = ReputationService()
ml_service = MlService()


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

    yield

    print("[SafeClick] Shutting down.")


# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SafeClick Intelligence API",
    description=(
        "Phase 3 backend for the SafeClick browser extension. "
        "Provides domain reputation (Phase 2), ML-powered phishing prediction, "
        "declarative rule engine, and confidence-scored explainable verdicts."
    ),
    version="0.3.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Phase 5: restrict to extension origin
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Accept", "Content-Type"],
)

# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(reputation_router, prefix="/api/v1")
app.include_router(predict_router, prefix="/api/v1")


@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "ok",
        "version": "0.3.0",
        "service": "safeclick-intelligence",
        "ml_model_loaded": ml_service.is_loaded,
    }
