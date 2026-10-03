"""Database models. SQLite by default, any SQLAlchemy URL (Postgres) in production."""
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from app.config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Alert(Base):
    """A security alert as it arrived from the (simulated) SIEM."""
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    external_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    alert_type: Mapped[str] = mapped_column(String(32), index=True)  # phishing | login
    payload: Mapped[dict] = mapped_column(JSON)
    # Ground truth stands in for the human analyst's verdict in shadow mode.
    human_verdict: Mapped[str] = mapped_column(String(16))  # malicious | benign
    scenario: Mapped[str] = mapped_column(String(64))  # generator scenario, for analysis only
    intel_snapshot: Mapped[list] = mapped_column(JSON, default=list)  # intel records relevant to this alert
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    investigation: Mapped["Investigation"] = relationship(back_populates="alert", uselist=False)


class Intel(Base):
    """Mock threat-intel / directory facts the agent's tools can query."""
    __tablename__ = "intel"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # domain | ip | user_device | user_profile
    key: Mapped[str] = mapped_column(String(255), index=True)
    attrs: Mapped[dict] = mapped_column(JSON)


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), unique=True)
    alert_type: Mapped[str] = mapped_column(String(32), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    ai_verdict: Mapped[str] = mapped_column(String(16))  # malicious | benign | needs_human
    proposed_verdict: Mapped[str] = mapped_column(String(16))  # before grading rules applied
    summary: Mapped[str] = mapped_column(Text, default="")
    findings: Mapped[list] = mapped_column(JSON, default=list)
    grading_violations: Mapped[list] = mapped_column(JSON, default=list)
    outcome: Mapped[str] = mapped_column(String(16), index=True)  # agree | disagree | deferred
    critical_miss: Mapped[bool] = mapped_column(Boolean, default=False)
    autonomy_at_time: Mapped[str] = mapped_column(String(16))
    action_status: Mapped[str] = mapped_column(String(16))  # shadow | drafted | executed | none
    used_precedent: Mapped[bool] = mapped_column(Boolean, default=False)
    steps_used: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    corrected: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    alert: Mapped[Alert] = relationship(back_populates="investigation")
    steps: Mapped[list["AuditStep"]] = relationship(
        back_populates="investigation", order_by="AuditStep.seq", cascade="all, delete-orphan"
    )


class AuditStep(Base):
    """One entry on the single, ordered audit trail of an investigation."""
    __tablename__ = "audit_steps"
    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    step_ref: Mapped[str] = mapped_column(String(16))  # e.g. "s3", cited by findings
    kind: Mapped[str] = mapped_column(String(24))  # tool_call | reasoning | verdict | grading
    tool: Mapped[str] = mapped_column(String(64), default="")
    input: Mapped[dict] = mapped_column(JSON, default=dict)
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    investigation: Mapped[Investigation] = relationship(back_populates="steps")


class Correction(Base):
    """An analyst correcting an AI verdict. Feeds memory and the regression suite."""
    __tablename__ = "corrections"
    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    alert_type: Mapped[str] = mapped_column(String(32))
    signature: Mapped[str] = mapped_column(Text)
    corrected_verdict: Mapped[str] = mapped_column(String(16))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LadderState(Base):
    __tablename__ = "ladder_state"
    alert_type: Mapped[str] = mapped_column(String(32), primary_key=True)
    level: Mapped[str] = mapped_column(String(16), default="assisted")
    recommendation: Mapped[str] = mapped_column(String(16), default="")  # level recommended, awaiting approval
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LadderEvent(Base):
    """Every promotion, demotion and recommendation, with the evidence snapshot behind it."""
    __tablename__ = "ladder_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    alert_type: Mapped[str] = mapped_column(String(32), index=True)
    event: Mapped[str] = mapped_column(String(24))  # recommend | promote | demote
    from_level: Mapped[str] = mapped_column(String(16))
    to_level: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON)
    actor: Mapped[str] = mapped_column(String(32), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


_settings = get_settings()
_connect_args = {"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {}
engine = create_engine(_settings.database_url, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db(drop: bool = False) -> None:
    if drop:
        Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
