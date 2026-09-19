"""Read-side helpers: allowance accounting, policy facts and the desired firewall state.

Nothing here mutates the database. All history is kept; "reset" happens only because
every query is keyed to the current logical day.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.clock import LogicalCalendar
from app.config import AppConfig
from app.models import (
    SESSION_ACTIVE,
    SESSION_ENFORCEMENT_FAILED,
    TYPE_CHILD,
    AllowanceAdjustment,
    DayLock,
    Device,
    ParentOverride,
    SessionRecord,
)
from app.policy import ChildFacts, Interval


@dataclass(frozen=True)
class AllowanceSummary:
    day: date
    base_seconds: int
    adjustment_seconds: int
    charged_seconds: int
    remaining_seconds: int
    unelapsed_reserved_seconds: int

    @property
    def uncommitted_seconds(self) -> int:
        return max(0, self.remaining_seconds - self.unelapsed_reserved_seconds)

    @property
    def remaining_minutes(self) -> int:
        """Whole minutes, rounded down so display never overstates what is left."""
        return self.remaining_seconds // 60


def _overlap_seconds(a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime) -> int:
    start, end = max(a_start, b_start), min(a_end, b_end)
    return max(0, int((end - start).total_seconds()))


def session_charge_seconds(
    session: SessionRecord, day_start: datetime, day_end: datetime, now: datetime
) -> int:
    """Seconds of ``session`` charged to the logical day [day_start, day_end)."""
    if session.session_type != TYPE_CHILD or session.status == SESSION_ENFORCEMENT_FAILED:
        return 0
    if session.status == SESSION_ACTIVE:
        end = now if session.planned_end_at is None else min(now, session.planned_end_at)
    else:
        end = session.start_at + timedelta(seconds=session.charged_seconds)
    return _overlap_seconds(session.start_at, end, day_start, day_end)


def base_allowance_seconds(
    config: AppConfig, cal: LogicalCalendar, child_id: str, day: date
) -> int:
    child = config.children[child_id]
    minutes = (
        child.weekend_allowance_minutes if cal.is_weekend(day) else child.weekday_allowance_minutes
    )
    return minutes * 60


def allowance_summary(
    db: Session, config: AppConfig, cal: LogicalCalendar, child_id: str, now: datetime
) -> AllowanceSummary:
    day = cal.logical_day(now)
    day_start, day_end = cal.day_bounds(day)
    adjustments = db.scalars(
        select(AllowanceAdjustment).where(
            AllowanceAdjustment.child_id == child_id, AllowanceAdjustment.logical_day == day
        )
    ).all()
    adjustment_seconds = sum(a.delta_minutes for a in adjustments) * 60

    sessions = db.scalars(
        select(SessionRecord).where(
            SessionRecord.child_id == child_id,
            SessionRecord.session_type == TYPE_CHILD,
            SessionRecord.start_at < day_end,
            SessionRecord.start_at >= day_start - timedelta(days=2),
            or_(SessionRecord.actual_end_at.is_(None), SessionRecord.actual_end_at > day_start),
        )
    ).all()
    charged = sum(session_charge_seconds(s, day_start, day_end, now) for s in sessions)
    unelapsed = sum(
        max(0, int((s.planned_end_at - now).total_seconds()))
        for s in sessions
        if s.status == SESSION_ACTIVE and s.planned_end_at is not None
    )
    base = base_allowance_seconds(config, cal, child_id, day)
    remaining = max(0, base + adjustment_seconds - charged)
    return AllowanceSummary(day, base, adjustment_seconds, charged, remaining, unelapsed)


def _effective_override_interval(o: ParentOverride) -> Interval | None:
    end = o.ends_at if o.revoked_at is None else min(o.ends_at, o.revoked_at)
    return Interval(o.starts_at, end) if end > o.starts_at else None


def override_intervals(
    db: Session, cal: LogicalCalendar, child_id: str | None, device_id: str | None, day: date
) -> tuple[Interval, ...]:
    day_start, _ = cal.day_bounds(day)
    stmt = select(ParentOverride).where(ParentOverride.ends_at > day_start)
    rows = db.scalars(stmt).all()
    out: list[Interval] = []
    for o in rows:
        if o.child_id is not None and o.child_id != child_id:
            continue
        if o.device_id is not None and o.device_id != device_id:
            continue
        interval = _effective_override_interval(o)
        if interval is not None:
            out.append(interval)
    return tuple(out)


def lock_intervals(db: Session, child_id: str, day: date) -> tuple[Interval, ...]:
    rows = db.scalars(
        select(DayLock).where(DayLock.child_id == child_id, DayLock.logical_day == day)
    ).all()
    return tuple(Interval(lock.created_at, lock.cleared_at) for lock in rows)


def active_child_sessions(db: Session, child_id: str) -> list[SessionRecord]:
    return list(
        db.scalars(
            select(SessionRecord).where(
                SessionRecord.child_id == child_id,
                SessionRecord.session_type == TYPE_CHILD,
                SessionRecord.status == SESSION_ACTIVE,
            )
        )
    )


def load_facts(
    db: Session,
    config: AppConfig,
    cal: LogicalCalendar,
    child_id: str,
    device_id: str,
    now: datetime,
    *,
    summary: AllowanceSummary | None = None,
) -> ChildFacts:
    summary = summary or allowance_summary(db, config, cal, child_id, now)
    day = summary.day
    # A session past its planned end is no longer "in use", even if the timer has not closed it yet.
    active = [
        s
        for s in active_child_sessions(db, child_id)
        if s.planned_end_at is None or s.planned_end_at > now
    ]
    return ChildFacts(
        child_id=child_id,
        day=day,
        remaining_seconds=summary.remaining_seconds,
        uncommitted_seconds=summary.uncommitted_seconds,
        locks=lock_intervals(db, child_id, day),
        overrides=override_intervals(db, cal, child_id, device_id, day),
        active_device_ids=frozenset(s.device_id for s in active),
    )


def desired_active_ips(db: Session, now: datetime) -> set[str]:
    """IPs that should be in the active table right now (spec section 12).

    Sessions past their planned end are excluded even if the timer has not yet closed
    them, so the firewall converges on the safe answer regardless of timer latency.
    """
    devices = {d.id: d for d in db.scalars(select(Device)) if d.enabled}
    ips: set[str] = set()
    for s in db.scalars(select(SessionRecord).where(SessionRecord.status == SESSION_ACTIVE)):
        if s.planned_end_at is not None and s.planned_end_at <= now:
            continue
        device = devices.get(s.device_id)
        if device is not None:
            ips.add(device.ip)
    for o in db.scalars(
        select(ParentOverride).where(
            ParentOverride.device_id.is_not(None),
            ParentOverride.child_id.is_(None),
            ParentOverride.override_type == "device_enable",
            ParentOverride.starts_at <= now,
            ParentOverride.ends_at > now,
            ParentOverride.revoked_at.is_(None),
        )
    ):
        device = devices.get(o.device_id or "")
        if device is not None:
            ips.add(device.ip)
    return ips
