"""Read models for the child and parent dashboards. Pure reads; no side effects."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.clock import LogicalCalendar
from app.config import AppConfig
from app.models import (
    SESSION_ACTIVE,
    SESSION_ENFORCEMENT_FAILED,
    TYPE_CHILD,
    TYPE_PARENT,
    AuditEvent,
    DayLock,
    ParentOverride,
    SessionRecord,
    User,
)
from app.policy import PolicyEngine, Reason, format_duration
from app.state import active_child_sessions, allowance_summary, load_facts


@dataclass
class DeviceOption:
    id: str
    name: str
    is_personal: bool
    available: bool
    reason: str
    message: str


@dataclass
class DurationOption:
    minutes: int
    available: bool
    selected: bool


@dataclass
class ActiveView:
    id: int
    group_id: str
    device_id: str
    device_name: str
    is_shared: bool
    end_at: datetime
    end_epoch: float
    end_local: str
    seconds_remaining: int
    extension_available: bool
    extension_message: str
    extension_reason: str
    extension_minutes: int
    warning: bool
    participants: list[str]
    ineligible: list[str]
    pending: bool  # started, not yet acknowledged by the firewall (plan 5.1)


@dataclass
class ChildView:
    child_id: str
    name: str
    remaining_seconds: int
    remaining_text: str
    start_rule: str | None
    cutoff_lines: list[str]
    devices: list[DeviceOption]
    durations: list[DurationOption]
    active: ActiveView | None
    locked: bool
    degraded: bool
    siblings: list[tuple[str, str]]
    override_note: str | None
    not_enforced_note: str | None
    server_epoch: float
    warning_minutes: int
    warning_seconds: int
    poll_seconds: int
    state_key: str


@dataclass
class ChildRow:
    child_id: str
    username: str
    has_password: bool
    login_locked: bool
    name: str
    remaining_minutes: int
    remaining_text: str
    sessions: list[tuple[int, str, str]]  # id, device, ends
    locked: bool
    override_until: str | None
    status: str


@dataclass
class TvRow:
    device_id: str
    name: str
    in_use: bool
    users: list[tuple[int, str, str]]  # session id, label, ends


@dataclass
class SessionRow:
    id: int
    who: str
    device: str
    ends: str
    kind: str
    pending: bool


@dataclass
class ParentView:
    children: list[ChildRow]
    tvs: list[TvRow]
    sessions: list[SessionRow]
    overrides: list[tuple[int, str, str]]  # id, who, until
    locked_accounts: list[str]
    degraded: bool
    degraded_error: str
    clock_synchronised: bool
    poll_seconds: int
    grants: list[int]
    tv_choices: list[int]
    allow_until_stopped: bool
    account_lines: list[str]
    state_key: str


# How long a child sees "the Internet did not turn on" after a refund (plan 5.1).
_NOT_ENFORCED_NOTE_FOR = timedelta(minutes=10)
# Password events shown on the parent dashboard for this long (plan 7.1).
_RECENT_ACCOUNT_EVENTS = timedelta(hours=24)


def _fingerprint(*parts: object) -> str:
    return hashlib.sha1(
        "|".join(str(p) for p in parts).encode(), usedforsecurity=False
    ).hexdigest()[:12]


class ViewBuilder:
    def __init__(self, config: AppConfig, calendar: LogicalCalendar, policy: PolicyEngine) -> None:
        self.cfg = config
        self.cal = calendar
        self.policy = policy

    def _poll_seconds(self, ends: list[datetime | None], now: datetime) -> int:
        """Fast polling while any session is within warning_minutes + 1 of its planned end."""
        window = (self.cfg.warning_minutes + 1) * 60
        near = any(end is not None and (end - now).total_seconds() <= window for end in ends)
        return self.cfg.ui.poll_fast_seconds if near else self.cfg.ui.poll_idle_seconds

    def _end_text(self, when: datetime | None) -> str:
        return "when stopped" if when is None else self.cal.format_local(when)

    def child_view(self, db: Session, child_id: str, now: datetime, *, degraded: bool) -> ChildView:
        cfg, cal = self.cfg, self.cal
        child = cfg.children[child_id]
        summary = allowance_summary(db, cfg, cal, child_id, now)
        day = summary.day
        weekday = not cal.is_weekend(day)

        device_ids = cfg.devices_owned_by(child_id) + [
            d for d in child.permitted_shared_devices if d in cfg.devices
        ]
        options: list[DeviceOption] = []
        cutoff_lines: list[str] = []
        for dev_id in device_ids:
            dev = cfg.devices[dev_id]
            if not dev.enabled:
                continue
            facts = load_facts(db, cfg, cal, child_id, dev_id, now, summary=summary)
            decision = self.policy.device_status(facts, dev_id, now)
            personal = dev.type == "personal"
            options.append(
                DeviceOption(
                    id=dev_id,
                    name=f"My {dev.display_name}" if personal else dev.display_name,
                    is_personal=personal,
                    available=decision.allowed,
                    reason=str(decision.reason),
                    message="" if decision.allowed else decision.message,
                )
            )
            if dev.weekday_cutoff and weekday:
                cutoff_lines.append(
                    f"{dev.display_name} ends: {dev.weekday_cutoff.strftime('%H:%M')}"
                )

        facts_any = (
            load_facts(
                db, cfg, cal, child_id, device_ids[0] if device_ids else "", now, summary=summary
            )
            if device_ids
            else None
        )
        fits = self.policy.allowed_durations(facts_any) if facts_any else []
        choices = list(cfg.sessions.child_choices_minutes)
        leftover = summary.uncommitted_seconds // 60
        if 1 <= leftover < min(choices):
            choices.append(leftover)
        default = (
            cfg.sessions.default_minutes
            if cfg.sessions.default_minutes in fits
            else (max(fits) if fits else None)
        )
        durations = [DurationOption(m, m in fits, m == default) for m in choices]

        active_view = self._active_view(db, child_id, now)
        locks = db.scalars(
            select(DayLock).where(
                DayLock.child_id == child_id,
                DayLock.logical_day == day,
                DayLock.cleared_at.is_(None),
            )
        ).all()
        override = db.scalars(
            select(ParentOverride).where(
                ParentOverride.child_id == child_id,
                ParentOverride.revoked_at.is_(None),
                ParentOverride.starts_at <= now,
                ParentOverride.ends_at > now,
            )
        ).first()
        start = child.weekday_earliest_start
        rule = f"Weekday access starts: {start.strftime('%H:%M')}" if start and weekday else None
        siblings = [(cid, c.display_name) for cid, c in cfg.children.items() if cid != child_id]
        view = ChildView(
            child_id=child_id,
            name=child.display_name,
            remaining_seconds=summary.remaining_seconds,
            remaining_text=format_duration(summary.remaining_seconds),
            start_rule=rule,
            cutoff_lines=cutoff_lines,
            devices=options,
            durations=durations,
            active=active_view,
            locked=bool(locks),
            degraded=degraded,
            siblings=siblings,
            override_note=(
                f"A parent has given you extra time until {cal.format_local(override.ends_at)}."
                if override
                else None
            ),
            not_enforced_note=self._not_enforced_note(db, child_id, now, active_view),
            server_epoch=now.timestamp(),
            warning_minutes=cfg.warning_minutes,
            warning_seconds=cfg.warning_minutes * 60,
            poll_seconds=self._poll_seconds([active_view.end_at] if active_view else [], now),
            state_key="",
        )
        view.state_key = _fingerprint(
            view.remaining_seconds // 60,
            [(o.id, o.available, o.reason) for o in options],
            [(d.minutes, d.available) for d in durations],
            (
                active_view.id,
                active_view.end_epoch,
                active_view.extension_available,
                active_view.warning,
            )
            if active_view
            else None,
            view.locked,
            degraded,
            view.override_note,
            view.not_enforced_note,
            active_view.pending if active_view else None,
            view.poll_seconds,  # a new interval needs a fresh fragment, not a 204
        )
        return view

    def _active_view(self, db: Session, child_id: str, now: datetime) -> ActiveView | None:
        cfg = self.cfg
        active = [
            s
            for s in active_child_sessions(db, child_id)
            if s.planned_end_at and s.planned_end_at > now
        ]
        if not active:
            return None
        s = active[0]
        assert s.planned_end_at is not None
        dev = cfg.devices[s.device_id]
        facts = load_facts(db, cfg, self.cal, child_id, s.device_id, now)
        decision = self.policy.evaluate_extension(facts, s.device_id, s.planned_end_at, now)
        group = [
            m
            for m in db.scalars(select(SessionRecord).where(SessionRecord.group_id == s.group_id))
            if m.status == SESSION_ACTIVE and m.child_id
        ]
        participants = [cfg.children[m.child_id].display_name for m in group if m.child_id]
        ineligible: list[str] = []
        for m in group:
            if m.child_id and m.child_id != child_id and m.planned_end_at:
                mf = load_facts(db, cfg, self.cal, m.child_id, m.device_id, now)
                if not self.policy.evaluate_extension(
                    mf, m.device_id, m.planned_end_at, now
                ).allowed:
                    ineligible.append(cfg.children[m.child_id].display_name)
        remaining = int((s.planned_end_at - now).total_seconds())
        in_window = remaining <= cfg.warning_minutes * 60
        return ActiveView(
            id=s.id,
            group_id=s.group_id,
            device_id=s.device_id,
            device_name=dev.display_name,
            is_shared=dev.type == "shared_tv",
            end_at=s.planned_end_at,
            end_epoch=s.planned_end_at.timestamp(),
            end_local=self.cal.format_local(s.planned_end_at),
            seconds_remaining=remaining,
            extension_available=decision.allowed,
            extension_message=(
                f"Add {cfg.sessions.child_extension_minutes} more minutes?"
                if decision.allowed
                else ("" if decision.reason is Reason.EXTENSION_NOT_YET else decision.message)
            ),
            extension_reason=str(decision.reason),
            extension_minutes=cfg.sessions.child_extension_minutes,
            warning=in_window,
            participants=participants,
            ineligible=ineligible,
            pending=s.enforced_at is None,
        )

    def _not_enforced_note(
        self, db: Session, child_id: str, now: datetime, active: ActiveView | None
    ) -> str | None:
        """Tell the child, for a while, when a session they started was refunded (plan 5.1)."""
        if active is not None:
            return None
        last = db.scalars(
            select(SessionRecord)
            .where(SessionRecord.child_id == child_id)
            .order_by(SessionRecord.start_at.desc())
            .limit(1)
        ).first()
        if (
            last is None
            or last.status != SESSION_ENFORCEMENT_FAILED
            or last.actual_end_at is None
            or now - last.actual_end_at > _NOT_ENFORCED_NOTE_FOR
        ):
            return None
        return "The Internet did not turn on. Your time has been given back."

    def parent_view(
        self,
        db: Session,
        now: datetime,
        *,
        degraded: bool,
        degraded_error: str,
        locked: list[str],
        clock_synchronised: bool = True,
    ) -> ParentView:
        cfg, cal = self.cfg, self.cal
        day = cal.logical_day(now)
        rows: list[ChildRow] = []
        accounts = {u.username: u for u in db.scalars(select(User))}
        for child_id, child in cfg.children.items():
            summary = allowance_summary(db, cfg, cal, child_id, now)
            sessions = [
                (s.id, cfg.devices[s.device_id].display_name, self._end_text(s.planned_end_at))
                for s in active_child_sessions(db, child_id)
            ]
            lock = db.scalars(
                select(DayLock).where(
                    DayLock.child_id == child_id,
                    DayLock.logical_day == day,
                    DayLock.cleared_at.is_(None),
                )
            ).first()
            override = db.scalars(
                select(ParentOverride).where(
                    ParentOverride.child_id == child_id,
                    ParentOverride.revoked_at.is_(None),
                    ParentOverride.starts_at <= now,
                    ParentOverride.ends_at > now,
                )
            ).first()
            if lock and not override:
                status = "Ended for today"
            elif sessions:
                status = "Active"
            elif summary.remaining_seconds < 60:
                status = "No time left"
            else:
                status = "Idle"
            rows.append(
                ChildRow(
                    child_id=child_id,
                    username=child.username,
                    login_locked=child.username in locked,
                    has_password=bool(
                        child.username in accounts
                        and accounts[child.username].enabled
                        and accounts[child.username].password_hash
                    ),
                    name=child.display_name,
                    remaining_minutes=summary.remaining_minutes,
                    remaining_text=format_duration(summary.remaining_seconds),
                    sessions=sessions,
                    locked=lock is not None,
                    override_until=cal.format_local(override.ends_at) if override else None,
                    status=status,
                )
            )

        active_sessions = list(
            db.scalars(select(SessionRecord).where(SessionRecord.status == SESSION_ACTIVE))
        )
        tv_rows: list[TvRow] = []
        for dev_id, dev in cfg.devices.items():
            if dev.type != "shared_tv":
                continue
            users: list[tuple[int, str, str]] = []
            for s in active_sessions:
                if s.device_id != dev_id:
                    continue
                label = (
                    "Parent"
                    if s.session_type == TYPE_PARENT
                    else cfg.children[s.child_id or ""].display_name
                )
                if s.until_stopped:
                    label += " (until stopped)"
                users.append((s.id, label, self._end_text(s.planned_end_at)))
            tv_rows.append(TvRow(dev_id, dev.display_name, bool(users), users))

        session_rows = [
            SessionRow(
                id=s.id,
                who="Parent"
                if s.session_type == TYPE_PARENT
                else cfg.children[s.child_id or ""].display_name,
                device=cfg.devices[s.device_id].display_name,
                ends=self._end_text(s.planned_end_at),
                kind="parent" if s.session_type == TYPE_PARENT else "child",
                pending=s.enforced_at is None,
            )
            for s in active_sessions
        ]
        override_rows = [
            (
                o.id,
                cfg.children[o.child_id].display_name
                if o.child_id
                else cfg.devices[o.device_id or ""].display_name,
                cal.format_local(o.ends_at),
            )
            for o in db.scalars(
                select(ParentOverride).where(
                    ParentOverride.revoked_at.is_(None), ParentOverride.ends_at > now
                )
            )
        ]
        view = ParentView(
            children=rows,
            tvs=tv_rows,
            sessions=session_rows,
            overrides=override_rows,
            locked_accounts=locked,
            degraded=degraded,
            degraded_error=degraded_error,
            clock_synchronised=clock_synchronised,
            poll_seconds=self._poll_seconds([s.planned_end_at for s in active_sessions], now),
            grants=list(cfg.parents.allowance_grants_minutes),
            tv_choices=list(cfg.parents.tv_session_choices_minutes),
            allow_until_stopped=cfg.parents.allow_until_stopped,
            account_lines=self._account_lines(db, now, accounts),
            state_key="",
        )
        view.state_key = _fingerprint(
            [
                (
                    r.child_id,
                    r.remaining_minutes,
                    r.status,
                    r.sessions,
                    r.override_until,
                    r.has_password,
                    r.login_locked,
                )
                for r in rows
            ],
            view.account_lines,
            [(s.id, s.pending) for s in session_rows],
            [(t.device_id, t.users) for t in tv_rows],
            override_rows,
            locked,
            degraded,
            clock_synchronised,
            view.poll_seconds,
        )
        return view

    def _account_lines(self, db: Session, now: datetime, users: dict[str, User]) -> list[str]:
        """ "Last parent sign-in" (D9 compensating control) and the last day's password changes."""

        def name(username: str) -> str:
            user = users.get(username)
            if user is not None and user.child_id in self.cfg.children:
                return self.cfg.children[user.child_id].display_name
            return (user.display_name if user else None) or username

        def where(ip: str) -> str:
            for dev in self.cfg.devices.values():
                if dev.ip == ip:
                    return f"{dev.display_name} ({ip})"
            return ip

        lines: list[str] = []
        parents = [u for u, row in users.items() if row.role == TYPE_PARENT]
        login = db.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.event_type == "login",
                AuditEvent.result == "ok",
                AuditEvent.actor.in_(parents),
            )
            .order_by(AuditEvent.id.desc())
            .limit(1)
        ).first()
        if login is not None:
            ip = str(json.loads(login.details_json).get("ip", "unknown address"))
            when = self.cal.format_local(login.timestamp, "%a %H:%M")
            lines.append(f"Last parent sign-in: {name(login.actor)}, {when}, {where(ip)}")
        changes = db.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.event_type.in_(("password_changed", "password_reset")),
                AuditEvent.result == "ok",
                AuditEvent.timestamp > now - _RECENT_ACCOUNT_EVENTS,
            )
            .order_by(AuditEvent.id.desc())
            .limit(3)
        ).all()
        for event in changes:
            when = self.cal.format_local(event.timestamp, "%a %H:%M")
            if event.event_type == "password_changed":
                lines.append(f"{name(event.subject)} changed their password, {when}")
            else:
                lines.append(f"{name(event.actor)} set {name(event.subject)}'s password, {when}")
        return lines


__all__ = ["TYPE_CHILD", "ActiveView", "ChildView", "ParentView", "ViewBuilder"]
