"""Session, grant and lock commands (spec sections 8, 10, 11, 17, 18).

Every command runs in one ``BEGIN IMMEDIATE`` transaction: re-read state, evaluate
policy, write. Denials are audited and *returned*, not raised, so the audit row commits.
Commands never touch the firewall; the orchestrator reconciles afterwards and, if that
fails, calls :meth:`SessionService.mark_enforcement_failed`.
"""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.clock import Clock, LogicalCalendar
from app.config import AppConfig
from app.db import Database
from app.models import (
    OVERRIDE_DEVICE_ENABLE,
    OVERRIDE_GRANT,
    SESSION_ACTIVE,
    SESSION_COMPLETED,
    SESSION_ENFORCEMENT_FAILED,
    TYPE_CHILD,
    TYPE_PARENT,
    AllowanceAdjustment,
    DayLock,
    NotificationEvent,
    ParentOverride,
    SessionRecord,
)
from app.policy import Decision, PolicyEngine, Reason
from app.state import active_child_sessions, allowance_summary, load_facts

_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{8,40}$")

_DENIAL_END_REASON = {
    Reason.DAY_LOCKED: "day_locked",
    Reason.DEVICE_CUTOFF: "cutoff",
    Reason.BEFORE_EARLIEST_START: "before_start_time",
}


@dataclass
class CommandResult:
    ok: bool
    reason: Reason = Reason.OK
    message: str = ""
    sessions: list[SessionRecord] = field(default_factory=list)
    ended_device_ids: set[str] = field(default_factory=set)
    duplicate: bool = False
    ineligible: list[str] = field(default_factory=list)
    extra: dict[str, object] = field(default_factory=dict)

    @classmethod
    def denied(cls, decision: Decision, **kwargs: object) -> CommandResult:
        return cls(ok=False, reason=decision.reason, message=decision.message, **kwargs)  # type: ignore[arg-type]

    @classmethod
    def fail(cls, reason: Reason, message: str) -> CommandResult:
        return cls(ok=False, reason=reason, message=message)


@dataclass
class TickResult:
    ended: list[SessionRecord] = field(default_factory=list)
    warned: list[int] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.ended)

    @property
    def ended_device_ids(self) -> set[str]:
        return {s.device_id for s in self.ended}


def _ceil_seconds(delta: timedelta) -> int:
    return max(0, math.ceil(delta.total_seconds()))


class SessionService:
    def __init__(
        self, db: Database, config: AppConfig, calendar: LogicalCalendar, clock: Clock
    ) -> None:
        self.db = db
        self.cfg = config
        self.cal = calendar
        self.clock = clock
        self.policy = PolicyEngine(config, calendar)

    # -- helpers ----------------------------------------------------------------------

    def _now(self) -> datetime:
        return self.clock.now().replace(microsecond=0)

    def _username(self, child_id: str) -> str:
        return self.cfg.children[child_id].username

    def _display(self, child_id: str) -> str:
        return self.cfg.children[child_id].display_name

    @staticmethod
    def _valid_key(key: str | None) -> str | None:
        if key is None:
            return None
        if not _KEY_RE.match(key):
            raise ValueError("idempotency key must be 8-40 characters of letters, digits, - or _")
        return key

    def _notify(
        self,
        db: Session,
        now: datetime,
        *,
        kind: str,
        audience: str,
        title: str,
        body: str,
        dedupe: str,
        child_id: str | None = None,
        session_id: int | None = None,
    ) -> bool:
        if (
            db.scalar(select(NotificationEvent.id).where(NotificationEvent.dedupe_key == dedupe))
            is not None
        ):
            return False
        db.add(
            NotificationEvent(
                kind=kind,
                audience=audience,
                child_id=child_id,
                session_id=session_id,
                dedupe_key=dedupe,
                title=title,
                body=body,
                created_at=now,
            )
        )
        return True

    def _finish(
        self,
        db: Session,
        s: SessionRecord,
        end_at: datetime,
        reason: str,
        now: datetime,
        actor: str,
    ) -> None:
        """Close a session, charging exact elapsed seconds (rounded up) to the child."""
        end_at = max(end_at, s.start_at)
        elapsed = _ceil_seconds(end_at - s.start_at)
        if s.session_type == TYPE_CHILD:
            if reason == "stopped" and not self.cfg.sessions.stop_returns_unused_reserved_time:
                charged = s.reserved_seconds
            else:
                charged = min(elapsed, s.reserved_seconds)
        else:
            charged = 0
        s.actual_end_at = end_at
        s.charged_seconds = charged
        s.status = SESSION_COMPLETED
        s.end_reason = reason
        who = self._display(s.child_id) if s.child_id else "Parent"
        device = self.cfg.devices[s.device_id].display_name
        record_audit(
            db,
            now,
            actor,
            "session_end",
            subject=f"session:{s.id}",
            child=s.child_id,
            device=s.device_id,
            reason=reason,
            charged_seconds=charged,
            type=s.session_type,
        )
        if s.session_type == TYPE_CHILD and s.child_id:
            self._notify(
                db,
                now,
                kind="session_ended",
                audience="child",
                title="Screen time finished",
                body=f"{device} has been switched off.",
                dedupe=f"ended:{s.id}",
                child_id=s.child_id,
                session_id=s.id,
            )
            if self.cfg.notifications.parent_notifications_enabled:
                self._notify(
                    db,
                    now,
                    kind="session_ended",
                    audience="parent",
                    title=f"{who} finished on {device}",
                    body=f"Reason: {reason.replace('_', ' ')}.",
                    dedupe=f"ended-parent:{s.id}",
                    child_id=s.child_id,
                    session_id=s.id,
                )

    def _group(self, db: Session, s: SessionRecord) -> list[SessionRecord]:
        return list(db.scalars(select(SessionRecord).where(SessionRecord.group_id == s.group_id)))

    # -- child commands ---------------------------------------------------------------

    def start_child_session(
        self,
        child_id: str,
        device_id: str,
        minutes: int,
        *,
        participants: tuple[str, ...] = (),
        idempotency_key: str | None = None,
    ) -> CommandResult:
        key = self._valid_key(idempotency_key)
        if child_id not in self.cfg.children:
            return CommandResult.fail(Reason.NOT_FOUND, "Unknown child.")
        ids = [child_id] + [p for p in dict.fromkeys(participants) if p != child_id]
        with self.db.session(write=True) as db:
            now = self._now()
            actor = self._username(child_id)
            if key:
                existing = db.scalar(
                    select(SessionRecord).where(SessionRecord.idempotency_key == key)
                )
                if existing is not None:
                    return CommandResult(
                        ok=True,
                        sessions=self._group(db, existing),
                        duplicate=True,
                        message="Already started.",
                    )
            device_cfg = self.cfg.devices.get(device_id)
            if device_cfg is not None and len(ids) > 1 and device_cfg.type != "shared_tv":
                decision = Decision(False, Reason.NOT_PERMITTED, "Only shared TVs can be shared.")
                record_audit(
                    db, now, actor, "session_rejected", device_id, "denied", reason=decision.reason
                )
                return CommandResult.denied(decision)
            decisions: dict[str, Decision] = {}
            for cid in ids:
                if cid not in self.cfg.children:
                    return CommandResult.fail(Reason.NOT_FOUND, "Unknown child.")
                facts = load_facts(db, self.cfg, self.cal, cid, device_id, now)
                decision = self.policy.evaluate_start(facts, device_id, minutes * 60, now)
                if not decision.allowed:
                    record_audit(
                        db, now, actor, "session_rejected", device_id, "denied",
                        child=cid, reason=decision.reason, minutes=minutes,
                    )  # fmt: skip
                    if cid != child_id:
                        decision = Decision(
                            False,
                            decision.reason,
                            f"{self._display(cid)} can't join: {decision.message}",
                        )
                    return CommandResult.denied(decision)
                decisions[cid] = decision
            group = uuid.uuid4().hex
            created: list[SessionRecord] = []
            for cid in ids:
                end = now + timedelta(minutes=minutes)
                cap = decisions[cid].max_end_at
                if cap is not None:
                    end = min(end, cap)
                rec = SessionRecord(
                    group_id=group,
                    child_id=cid,
                    device_id=device_id,
                    session_type=TYPE_CHILD,
                    start_at=now,
                    planned_end_at=end,
                    status=SESSION_ACTIVE,
                    reserved_seconds=int((end - now).total_seconds()),
                    created_by=actor,
                    idempotency_key=key if cid == child_id else None,
                )
                db.add(rec)
                created.append(rec)
            db.flush()
            for rec in created:
                record_audit(
                    db, now, actor, "session_start", f"session:{rec.id}",
                    child=rec.child_id, device=device_id, minutes=rec.reserved_minutes,
                    group=group, override=decisions[rec.child_id or ""].override_used,
                )  # fmt: skip
            return CommandResult(ok=True, sessions=created)

    def add_participant(
        self, session_id: int, requester_child_id: str, sibling_child_id: str
    ) -> CommandResult:
        with self.db.session(write=True) as db:
            now = self._now()
            actor = self._username(requester_child_id)
            base = db.get(SessionRecord, session_id)
            if (
                base is None
                or base.child_id != requester_child_id
                or base.session_type != TYPE_CHILD
                or sibling_child_id not in self.cfg.children
            ):
                return CommandResult.fail(Reason.NOT_FOUND, "Session not found.")
            if (
                base.status != SESSION_ACTIVE
                or base.planned_end_at is None
                or base.planned_end_at <= now
            ):
                return CommandResult.fail(
                    Reason.SESSION_NOT_ACTIVE, "That session has already ended."
                )
            if self.cfg.devices[base.device_id].type != "shared_tv":
                return CommandResult.fail(Reason.NOT_PERMITTED, "Only shared TVs can be shared.")
            remaining = int((base.planned_end_at - now).total_seconds())
            facts = load_facts(db, self.cfg, self.cal, sibling_child_id, base.device_id, now)
            decision = self.policy.evaluate_start(
                facts, base.device_id, remaining, now, check_duration=False
            )
            if not decision.allowed:
                record_audit(
                    db, now, actor, "participant_rejected", f"session:{base.id}", "denied",
                    child=sibling_child_id, reason=decision.reason,
                )  # fmt: skip
                return CommandResult.denied(
                    Decision(
                        False,
                        decision.reason,
                        f"{self._display(sibling_child_id)} can't join: {decision.message}",
                    )
                )
            end = (
                min(base.planned_end_at, decision.max_end_at)
                if decision.max_end_at
                else base.planned_end_at
            )
            rec = SessionRecord(
                group_id=base.group_id,
                child_id=sibling_child_id,
                device_id=base.device_id,
                session_type=TYPE_CHILD,
                start_at=now,
                planned_end_at=end,
                status=SESSION_ACTIVE,
                reserved_seconds=int((end - now).total_seconds()),
                created_by=actor,
            )
            db.add(rec)
            db.flush()
            record_audit(
                db, now, actor, "participant_added", f"session:{rec.id}",
                child=sibling_child_id, device=base.device_id, group=base.group_id,
            )  # fmt: skip
            return CommandResult(ok=True, sessions=[rec])

    def extend_session(
        self, session_id: int, child_id: str, *, mode: str = "eligible"
    ) -> CommandResult:
        """Extend by the configured step. Re-reads allowance inside the transaction (atomic)."""
        with self.db.session(write=True) as db:
            now = self._now()
            actor = self._username(child_id)
            sess = db.get(SessionRecord, session_id)
            if sess is None or sess.child_id != child_id or sess.session_type != TYPE_CHILD:
                return CommandResult.fail(Reason.NOT_FOUND, "Session not found.")
            if sess.status != SESSION_ACTIVE or sess.planned_end_at is None:
                return CommandResult.fail(
                    Reason.SESSION_NOT_ACTIVE, "That session has already ended."
                )
            members = [
                m for m in self._group(db, sess) if m.status == SESSION_ACTIVE and m.child_id
            ]
            decisions: dict[int, Decision] = {}
            for m in members:
                assert m.child_id is not None and m.planned_end_at is not None
                facts = load_facts(db, self.cfg, self.cal, m.child_id, m.device_id, now)
                decisions[m.id] = self.policy.evaluate_extension(
                    facts, m.device_id, m.planned_end_at, now
                )
            mine = decisions[sess.id]
            ineligible = [
                self._display(m.child_id or "") for m in members if not decisions[m.id].allowed
            ]
            if not mine.allowed or (mode == "all" and ineligible):
                blocked = (
                    mine
                    if not mine.allowed
                    else next(d for d in decisions.values() if not d.allowed)
                )
                record_audit(
                    db, now, actor, "extension_rejected", f"session:{sess.id}", "denied",
                    reason=blocked.reason, ineligible=ineligible,
                )  # fmt: skip
                return CommandResult.denied(blocked, ineligible=ineligible)
            step = timedelta(minutes=self.cfg.sessions.child_extension_minutes)
            extended: list[SessionRecord] = []
            for m in members:
                if decisions[m.id].allowed and m.planned_end_at is not None:
                    m.planned_end_at = m.planned_end_at + step
                    m.reserved_seconds += int(step.total_seconds())
                    extended.append(m)
                    record_audit(
                        db, now, actor, "session_extended", f"session:{m.id}",
                        child=m.child_id, minutes=int(step.total_seconds() // 60),
                    )  # fmt: skip
            return CommandResult(ok=True, sessions=extended, ineligible=ineligible)

    def stop_session(
        self, session_id: int, *, actor: str, role: str, child_id: str | None = None
    ) -> CommandResult:
        """Stop early. Children may stop only their own; parents may stop anything."""
        with self.db.session(write=True) as db:
            now = self._now()
            sess = db.get(SessionRecord, session_id)
            if sess is None:
                return CommandResult.fail(Reason.NOT_FOUND, "Session not found.")
            if role != "parent" and (sess.session_type != TYPE_CHILD or sess.child_id != child_id):
                record_audit(db, now, actor, "stop_forbidden", f"session:{session_id}", "denied")
                return CommandResult.fail(Reason.NOT_FOUND, "Session not found.")
            if sess.status != SESSION_ACTIVE:
                return CommandResult(
                    ok=True, sessions=[sess], message="Already finished.", duplicate=True
                )
            reason = "parent_stopped" if role == "parent" else "stopped"
            self._finish(db, sess, now, reason, now, actor)
            return CommandResult(ok=True, sessions=[sess], ended_device_ids={sess.device_id})

    def mark_enforcement_failed(self, session_ids: list[int], error: str) -> None:
        """Firewall could not grant access: terminate and refund so nothing is charged."""
        with self.db.session(write=True) as db:
            now = self._now()
            for sid in session_ids:
                s = db.get(SessionRecord, sid)
                if s is None or s.status != SESSION_ACTIVE:
                    continue
                s.status = SESSION_ENFORCEMENT_FAILED
                s.actual_end_at = now
                s.charged_seconds = 0
                s.end_reason = "enforcement_failed"
                record_audit(
                    db, now, "system", "session_enforcement_failed", f"session:{sid}", "error",
                    child=s.child_id, device=s.device_id, error=error[:200],
                )  # fmt: skip

    # -- parent commands --------------------------------------------------------------

    def parent_grant(
        self, child_id: str, minutes: int, actor: str, *, idempotency_key: str | None = None
    ) -> CommandResult:
        key = self._valid_key(idempotency_key)
        if child_id not in self.cfg.children:
            return CommandResult.fail(Reason.NOT_FOUND, "Unknown child.")
        if minutes not in self.cfg.parents.allowance_grants_minutes:
            return CommandResult.fail(Reason.INVALID_DURATION, "That grant size is not allowed.")
        with self.db.session(write=True) as db:
            now = self._now()
            if key and db.scalar(
                select(AllowanceAdjustment.id).where(AllowanceAdjustment.idempotency_key == key)
            ):
                return CommandResult(ok=True, duplicate=True, message="Already applied.")
            summary = allowance_summary(db, self.cfg, self.cal, child_id, now)
            override_id: int | None = None
            window_end: datetime | None = None
            if self.cfg.parents.grants_override_all_child_restrictions:
                # Long enough to consume the grant plus whatever the child already has reserved.
                window_end = now + timedelta(
                    minutes=minutes, seconds=summary.unelapsed_reserved_seconds
                )
                override = ParentOverride(
                    child_id=child_id,
                    device_id=None,
                    starts_at=now,
                    ends_at=window_end,
                    override_type=OVERRIDE_GRANT,
                    created_by=actor,
                    created_at=now,
                    note=f"+{minutes} min grant",
                )
                db.add(override)
                db.flush()
                override_id = override.id
            db.add(
                AllowanceAdjustment(
                    child_id=child_id,
                    logical_day=summary.day,
                    delta_minutes=minutes,
                    reason="parent grant",
                    created_by=actor,
                    created_at=now,
                    override_id=override_id,
                    idempotency_key=key,
                )
            )
            record_audit(
                db, now, actor, "parent_grant", f"child:{child_id}",
                minutes=minutes, override_id=override_id, window_end=window_end,
            )  # fmt: skip
            return CommandResult(ok=True, extra={"window_end": window_end})

    def end_today(self, child_id: str, actor: str) -> CommandResult:
        if child_id not in self.cfg.children:
            return CommandResult.fail(Reason.NOT_FOUND, "Unknown child.")
        with self.db.session(write=True) as db:
            now = self._now()
            day = self.cal.logical_day(now)
            already = db.scalar(
                select(DayLock.id).where(
                    DayLock.child_id == child_id,
                    DayLock.logical_day == day,
                    DayLock.cleared_at.is_(None),
                )
            )
            if already is None:
                db.add(
                    DayLock(
                        child_id=child_id,
                        logical_day=day,
                        active=True,
                        created_by=actor,
                        reason="end for today",
                        created_at=now,
                    )
                )
            # The parent's latest decision wins: earlier grant windows would otherwise bypass this lock.
            for o in db.scalars(
                select(ParentOverride).where(
                    ParentOverride.child_id == child_id,
                    ParentOverride.revoked_at.is_(None),
                    ParentOverride.ends_at > now,
                )
            ):
                o.revoked_at = now
            ended: set[str] = set()
            for s in active_child_sessions(db, child_id):
                self._finish(db, s, now, "day_locked", now, actor)
                ended.add(s.device_id)
            record_audit(
                db, now, actor, "end_today", f"child:{child_id}", ended_devices=sorted(ended)
            )
            return CommandResult(ok=True, ended_device_ids=ended)

    def clear_day_lock(self, child_id: str, actor: str) -> CommandResult:
        if child_id not in self.cfg.children:
            return CommandResult.fail(Reason.NOT_FOUND, "Unknown child.")
        with self.db.session(write=True) as db:
            now = self._now()
            day = self.cal.logical_day(now)
            locks = db.scalars(
                select(DayLock).where(
                    DayLock.child_id == child_id,
                    DayLock.logical_day == day,
                    DayLock.cleared_at.is_(None),
                )
            ).all()
            for lock in locks:
                lock.cleared_at = now
                lock.cleared_by = actor
                lock.active = False
            record_audit(db, now, actor, "clear_day_lock", f"child:{child_id}", cleared=len(locks))
            return CommandResult(ok=True, extra={"cleared": len(locks)})

    def start_tv(
        self, device_id: str, minutes: int | None, actor: str, *, idempotency_key: str | None = None
    ) -> CommandResult:
        """Parent TV grant: 15/30/60 minutes or until stopped. Never charges a child."""
        key = self._valid_key(idempotency_key)
        device = self.cfg.devices.get(device_id)
        if device is None or device.type != "shared_tv":
            return CommandResult.fail(Reason.UNKNOWN_DEVICE, "That TV is not known.")
        if not device.enabled:
            return CommandResult.fail(
                Reason.DEVICE_DISABLED, f"{device.display_name} is switched off."
            )
        if minutes is None and not self.cfg.parents.allow_until_stopped:
            return CommandResult.fail(Reason.INVALID_DURATION, "'Until stopped' is disabled.")
        if minutes is not None and minutes not in self.cfg.parents.tv_session_choices_minutes:
            return CommandResult.fail(Reason.INVALID_DURATION, "That duration is not allowed.")
        with self.db.session(write=True) as db:
            now = self._now()
            if key:
                existing = db.scalar(
                    select(SessionRecord).where(SessionRecord.idempotency_key == key)
                )
                if existing is not None:
                    return CommandResult(
                        ok=True, sessions=[existing], duplicate=True, message="Already started."
                    )
            end: datetime | None
            if minutes is not None:
                end = now + timedelta(minutes=minutes)
            elif self.cfg.parents.until_stopped_end_at_logical_day_reset:
                end = self.cal.day_start(self.cal.logical_day(now) + timedelta(days=1))
            else:
                end = None
            rec = SessionRecord(
                group_id=uuid.uuid4().hex,
                child_id=None,
                device_id=device_id,
                session_type=TYPE_PARENT,
                start_at=now,
                planned_end_at=end,
                status=SESSION_ACTIVE,
                reserved_seconds=int((end - now).total_seconds()) if end else 0,
                until_stopped=minutes is None,
                created_by=actor,
                idempotency_key=key,
            )
            db.add(rec)
            db.flush()
            record_audit(
                db, now, actor, "tv_start", f"session:{rec.id}",
                device=device_id, minutes=minutes, until_stopped=minutes is None,
            )  # fmt: skip
            return CommandResult(ok=True, sessions=[rec])

    def enable_device(self, device_id: str, minutes: int, actor: str) -> CommandResult:
        """Scoped override that forces a device on for a window (used by the admin CLI)."""
        if device_id not in self.cfg.devices:
            return CommandResult.fail(Reason.UNKNOWN_DEVICE, "Unknown device.")
        with self.db.session(write=True) as db:
            now = self._now()
            override = ParentOverride(
                child_id=None,
                device_id=device_id,
                starts_at=now,
                ends_at=now + timedelta(minutes=minutes),
                override_type=OVERRIDE_DEVICE_ENABLE,
                created_by=actor,
                created_at=now,
                note=f"enable {device_id} for {minutes} min",
            )
            db.add(override)
            db.flush()
            record_audit(
                db,
                now,
                actor,
                "device_enable",
                f"device:{device_id}",
                minutes=minutes,
                override_id=override.id,
            )
            return CommandResult(ok=True, extra={"override_id": override.id})

    def revoke_override(self, override_id: int, actor: str) -> CommandResult:
        with self.db.session(write=True) as db:
            now = self._now()
            o = db.get(ParentOverride, override_id)
            if o is None:
                return CommandResult.fail(Reason.NOT_FOUND, "Override not found.")
            if o.revoked_at is None and o.ends_at > now:
                o.revoked_at = now
                record_audit(db, now, actor, "override_revoked", f"override:{override_id}")
            return CommandResult(ok=True, ended_device_ids={o.device_id} if o.device_id else set())

    def end_all_sessions(self, actor: str, reason: str = "admin_reset") -> CommandResult:
        with self.db.session(write=True) as db:
            now = self._now()
            ended: set[str] = set()
            for s in db.scalars(
                select(SessionRecord).where(SessionRecord.status == SESSION_ACTIVE)
            ):
                self._finish(db, s, now, reason, now, actor)
                ended.add(s.device_id)
            record_audit(db, now, actor, "end_all_sessions", "", ended_devices=sorted(ended))
            return CommandResult(ok=True, ended_device_ids=ended)

    # -- timers -----------------------------------------------------------------------

    def tick(self, now: datetime | None = None) -> TickResult:
        """Expire sessions, enforce continuing policy and raise warnings exactly once."""
        result = TickResult()
        with self.db.session(write=True) as db:
            now = (now or self.clock.now()).replace(microsecond=0)
            day_start, _ = self.cal.day_bounds(self.cal.logical_day(now))
            for s in db.scalars(
                select(SessionRecord).where(SessionRecord.status == SESSION_ACTIVE)
            ):
                end_at: datetime | None = None
                reason = ""
                if s.planned_end_at is not None and s.planned_end_at <= now:
                    end_at, reason = s.planned_end_at, "expired"
                if s.session_type == TYPE_CHILD and s.child_id:
                    facts = load_facts(db, self.cfg, self.cal, s.child_id, s.device_id, now)
                    stop = self.policy.first_denied(facts, s.device_id, max(s.start_at, day_start))
                    if stop is not None and stop[0] <= now and (end_at is None or stop[0] < end_at):
                        end_at, reason = stop[0], _DENIAL_END_REASON[stop[1]]
                if end_at is not None:
                    self._finish(db, s, end_at, reason, now, "system")
                    result.ended.append(s)
                    continue
                if (
                    s.session_type == TYPE_CHILD
                    and s.child_id
                    and s.planned_end_at is not None
                    and (s.planned_end_at - now).total_seconds() <= self.cfg.warning_minutes * 60
                ):
                    minutes_left = max(1, math.ceil((s.planned_end_at - now).total_seconds() / 60))
                    created = self._notify(
                        db,
                        now,
                        kind="session_warning",
                        audience="child",
                        title=f"{minutes_left} minutes left",
                        body=f"{self.cfg.devices[s.device_id].display_name} will switch off soon.",
                        dedupe=f"warning:{s.id}:{s.planned_end_at.isoformat()}",
                        child_id=s.child_id,
                        session_id=s.id,
                    )
                    if created:
                        result.warned.append(s.id)
                        record_audit(
                            db, now, "system", "session_warning", f"session:{s.id}",
                            child=s.child_id, planned_end=s.planned_end_at,
                        )  # fmt: skip
        return result
