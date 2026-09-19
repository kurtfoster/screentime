"""SQLAlchemy 2.x models.

The database is authoritative for sessions and accounting; pf tables are derived state.
Durations are stored in whole seconds so charging is exact; ``*_minutes`` properties
provide the whole-minute views the specification names.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.db import UTCDateTime

SESSION_ACTIVE = "active"
SESSION_COMPLETED = "completed"
SESSION_ENFORCEMENT_FAILED = "enforcement_failed"

TYPE_CHILD = "child"
TYPE_PARENT = "parent"

OVERRIDE_GRANT = "grant"
OVERRIDE_DEVICE_ENABLE = "device_enable"


class Base(DeclarativeBase):
    pass


class Meta(Base):
    __tablename__ = "meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class User(Base):
    """Identity mirror of users.yaml. Password hashes deliberately stay in the YAML file."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    role: Mapped[str] = mapped_column(String(16))
    child_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(40))
    ip: Mapped[str] = mapped_column(String(45))
    type: Mapped[str] = mapped_column(String(16))
    owner_child_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class SessionRecord(Base):
    """One charge (or parent) session. Shared-TV participants are separate rows sharing group_id."""

    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_status", "status"),
        Index("ix_sessions_child_start", "child_id", "start_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[str] = mapped_column(String(32))
    child_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    session_type: Mapped[str] = mapped_column(String(16))
    start_at: Mapped[datetime] = mapped_column(UTCDateTime)
    planned_end_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    actual_end_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default=SESSION_ACTIVE)
    reserved_seconds: Mapped[int] = mapped_column(Integer, default=0)
    charged_seconds: Mapped[int] = mapped_column(Integer, default=0)
    end_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    until_stopped: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(32))
    idempotency_key: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)

    @property
    def reserved_minutes(self) -> int:
        return self.reserved_seconds // 60

    @property
    def charged_minutes(self) -> int:
        return self.charged_seconds // 60

    @property
    def is_active(self) -> bool:
        return self.status == SESSION_ACTIVE


class AllowanceAdjustment(Base):
    __tablename__ = "allowance_adjustments"
    __table_args__ = (Index("ix_adjustments_child_day", "child_id", "logical_day"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    child_id: Mapped[str] = mapped_column(String(64))
    logical_day: Mapped[date] = mapped_column(Date)
    delta_minutes: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(String(200), default="")
    created_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    override_id: Mapped[int | None] = mapped_column(
        ForeignKey("parent_overrides.id"), nullable=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)


class DayLock(Base):
    __tablename__ = "day_locks"
    __table_args__ = (Index("ix_day_locks_child_day", "child_id", "logical_day"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    child_id: Mapped[str] = mapped_column(String(64))
    logical_day: Mapped[date] = mapped_column(Date)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    cleared_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    cleared_by: Mapped[str | None] = mapped_column(String(32), nullable=True)


class ParentOverride(Base):
    __tablename__ = "parent_overrides"
    __table_args__ = (Index("ix_overrides_child_window", "child_id", "starts_at", "ends_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    child_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    starts_at: Mapped[datetime] = mapped_column(UTCDateTime)
    ends_at: Mapped[datetime] = mapped_column(UTCDateTime)
    override_type: Mapped[str] = mapped_column(String(24))
    created_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    note: Mapped[str] = mapped_column(String(200), default="")


class FirewallEvent(Base):
    __tablename__ = "firewall_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    action: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(200), default="")
    success: Mapped[bool] = mapped_column(Boolean)
    command_summary: Mapped[str] = mapped_column(String(300), default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    error_text: Mapped[str] = mapped_column(Text, default="")


class AuditEvent(Base):
    """Append-only record of who did what and how it went."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(48))
    subject: Mapped[str] = mapped_column(String(128), default="")
    result: Mapped[str] = mapped_column(String(16), default="ok")
    details_json: Mapped[str] = mapped_column(Text, default="{}")


class PushSubscription(Base):
    __tablename__ = "push_subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), index=True)
    role: Mapped[str] = mapped_column(String(16))
    endpoint: Mapped[str] = mapped_column(String(1024), unique=True)
    keys_encrypted: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)


class NotificationEvent(Base):
    """Durable notification record; dedupe_key makes each event fire exactly once."""

    __tablename__ = "notification_events"
    __table_args__ = (UniqueConstraint("dedupe_key", name="uq_notification_dedupe"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    audience: Mapped[str] = mapped_column(String(16))  # child | parent
    child_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    session_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(160))
    title: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    dispatched_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class WebSession(Base):
    """Server-side login session. Only a hash of the cookie token is stored."""

    __tablename__ = "web_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(32))
    role: Mapped[str] = mapped_column(String(16))
    child_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)


class LoginFailure(Base):
    __tablename__ = "login_failures"

    key: Mapped[str] = mapped_column(String(96), primary_key=True)
    username: Mapped[str] = mapped_column(String(32))
    failures: Mapped[int] = mapped_column(Integer, default=0)
    window_started_at: Mapped[datetime] = mapped_column(UTCDateTime)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
