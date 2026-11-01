"""
backend/database/db.py
────────────────────────────────────────────────────────────────────────────
Phase 5: Async SQLAlchemy engine, session factory, and FastAPI dependency.

Uses asyncpg driver (postgresql+asyncpg://...).
DATABASE_URL must be set in .env or environment.

For local dev without PostgreSQL, the app degrades gracefully:
  - if DATABASE_URL is not set, DB features are disabled at startup with a warning
  - all Phase 1-4 features remain fully functional
"""

import os
from typing import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.pool import NullPool

from database.models import Base


DATABASE_URL: str | None = os.getenv("DATABASE_URL")

# ── Engine & session factory ───────────────────────────────────────────────────

_engine = None
_async_session_factory = None


def get_engine():
    global _engine
    if _engine is None and DATABASE_URL:
        _engine = create_async_engine(
            DATABASE_URL,
            echo=os.getenv("DB_ECHO", "false").lower() == "true",
            # NullPool avoids connection leaks in test environments
            poolclass=NullPool if os.getenv("TESTING") == "true" else None,
        )
    return _engine


def get_session_factory():
    global _async_session_factory
    engine = get_engine()
    if _async_session_factory is None and engine:
        _async_session_factory = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
    return _async_session_factory


# ── DB init ───────────────────────────────────────────────────────────────────

async def init_db() -> bool:
    """
    Create all tables if they do not exist.
    Returns True if DB is available, False if DATABASE_URL is not configured.
    In production, prefer Alembic migrations over create_all.
    """
    engine = get_engine()
    if engine is None:
        print("[SafeClick] WARNING: DATABASE_URL not set — cloud features disabled. "
              "All Phase 1–4 features remain fully functional.")
        return False

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[SafeClick] Database tables ready.")
    return True


async def close_db():
    """Dispose the engine cleanly on shutdown."""
    engine = get_engine()
    if engine:
        await engine.dispose()


# ── FastAPI dependency ────────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an async DB session.
    Raises RuntimeError if DATABASE_URL is not configured (graceful degradation).
    """
    factory = get_session_factory()
    if factory is None:
        raise RuntimeError("Database not configured. Set DATABASE_URL to enable cloud features.")
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
