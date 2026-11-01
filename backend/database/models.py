"""
backend/database/models.py
────────────────────────────────────────────────────────────────────────────
Phase 5: SQLAlchemy ORM models for the SafeClick cloud backend.

Tables:
  users               — registered accounts
  devices             — devices associated with accounts
  reported_sites      — crowdsourced phishing/FP report submissions
  shared_threat_intel — promoted, confirmed malicious domains
  analytics_events    — aggregate-only, privacy-preserving event log

Data Retention Policy (documented per spec):
  - reported_sites:    retained 90 days after resolution (confirmed/rejected).
                       Anonymous reports retained 30 days.
  - analytics_events:  retained 365 days. No full URLs stored — domain hash only.
  - shared_threat_intel: retained indefinitely until manually removed by admin.

Crowdsourcing Promotion Threshold:
  A domain graduates from reported_sites → shared_threat_intel when ALL are true:
    1. ≥ AGGREGATION_MIN_REPORTS (default 3) independent user reports
    2. Phase 2/3 engine_score ≥ AGGREGATION_MIN_ENGINE_SCORE (default 60)
  This prevents trivial report-flooding from blacklisting innocent domains.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, Float, DateTime, ForeignKey, Enum, Text, Uuid
)
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────

class ReportType(str, enum.Enum):
    phishing = "phishing"
    false_positive = "false_positive"
    malware = "malware"


class ReportStatus(str, enum.Enum):
    pending = "pending"
    confirmed = "confirmed"
    rejected = "rejected"


class EventType(str, enum.Enum):
    verdict_served = "verdict_served"
    report_submitted = "report_submitted"
    threat_intel_hit = "threat_intel_hit"


# ── Models ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    # Separate opt-in: explicitly off by default; requires user to enable
    history_sync_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    reports = relationship("ReportedSite", back_populates="reporter")

    def __repr__(self):
        return f"<User id={self.id} email={self.email}>"


class Device(Base):
    __tablename__ = "devices"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_name = Column(String(255), nullable=True)
    refresh_token_hash = Column(String(255), nullable=True)  # hashed refresh token
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="devices")

    def __repr__(self):
        return f"<Device id={self.id} user_id={self.user_id}>"


class ReportedSite(Base):
    """
    Crowdsourced report from a user. reporter_id is nullable for anonymous reports.
    engine_score records the Phase 2/3 detection score at submission time —
    used as a corroboration signal when promoting to shared_threat_intel.
    """
    __tablename__ = "reported_sites"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    reporter_id = Column(Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    report_type = Column(Enum(ReportType), nullable=False, default=ReportType.phishing)
    status = Column(Enum(ReportStatus), nullable=False, default=ReportStatus.pending, index=True)
    engine_score = Column(Float, nullable=True)   # Phase 2/3 score at submission time
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)

    reporter = relationship("User", back_populates="reports")

    def __repr__(self):
        return f"<ReportedSite domain={self.domain} type={self.report_type} status={self.status}>"


class SharedThreatIntel(Base):
    """
    Promoted, confirmed malicious domains derived from reported_sites.
    Only populated after meeting the crowdsourcing threshold:
      - >= AGGREGATION_MIN_REPORTS independent user reports
      - >= AGGREGATION_MIN_ENGINE_SCORE engine corroboration score
    """
    __tablename__ = "shared_threat_intel"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    report_count = Column(Integer, nullable=False, default=0)
    avg_engine_score = Column(Float, nullable=True)
    confirmed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True, nullable=False)   # allows manual removal

    def __repr__(self):
        return f"<SharedThreatIntel domain={self.domain} reports={self.report_count}>"


class AnalyticsEvent(Base):
    """
    Aggregate-only, privacy-preserving event log.
    CRITICAL: No full URLs stored. domain_hash is a SHA-256 of the registered domain.
    This is infrastructure telemetry for operational visibility, NOT per-user surveillance.
    """
    __tablename__ = "analytics_events"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(Enum(EventType), nullable=False, index=True)
    verdict_level = Column(String(20), nullable=True)   # safe / suspicious / dangerous
    domain_hash = Column(String(64), nullable=True)     # SHA-256(domain), not the domain itself
    latency_ms = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return f"<AnalyticsEvent type={self.event_type} ts={self.timestamp}>"
