"""
SafeClick Backend — FastAPI Application Entry Point
────────────────────────────────────────────────────────────────────────────
Phase 2: Minimal reputation service backend.
Only introduces the API surface that the extension needs; no auth, no DB yet.
Those are Phase 5 concerns.

Start:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Or:
    python -m uvicorn main:app --reload
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.reputation import router as reputation_router
from services.reputation_service import ReputationService


# ── Shared service instance ────────────────────────────────────────────────────
reputation_service = ReputationService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context: runs startup and shutdown logic."""
    # Startup: fetch/cache the OpenPhish community blocklist
    print("[SafeClick] Starting up — loading reputation data...")
    await reputation_service.initialize()
    print("[SafeClick] Reputation service ready.")

    # Inject into app state so routers can access it
    app.state.reputation_service = reputation_service

    yield

    # Shutdown cleanup (graceful)
    print("[SafeClick] Shutting down reputation service.")


# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SafeClick Reputation API",
    description=(
        "Phase 2 backend reputation service for the SafeClick browser extension. "
        "Checks domain reputation using VirusTotal (optional) and OpenPhish community feed, "
        "with TTL caching to respect free-tier rate limits."
    ),
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS ───────────────────────────────────────────────────────────────────────
# Allow the Chrome extension to call this local backend.
# In production (Phase 5), restrict to specific origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Phase 5: restrict to extension origin
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Accept"],
)

# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(reputation_router, prefix="/api/v1")


@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "ok",
        "version": "0.2.0",
        "service": "safeclick-reputation",
    }
