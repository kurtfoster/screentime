"""Pure policy evaluation (spec section 9). No I/O, no clock: everything is passed in.

Precedence, highest first:

1. Explicit parent override for the child/device/time. It bypasses rules 3-5 for its
   window; any extra *allowance* it grants arrives as an explicit adjustment, so rule 6
   still measures against base + adjustments. Rules 7-8 protect accounting integrity
   (no overlapping charges, no borrowing another child's device) and are never bypassed.
2. Parent TV sessions are not child sessions and are never evaluated here.
3. Child End-for-Today day lock.
4. Device hard cutoff (weekdays).
5. Weekday earliest start.
6. Remaining daily allowance.
7. One active device per child.
8. Device entitlement.

Restrictions are modelled as *denied intervals* on the timeline. That lets the same
model answer both "may this start now?" and "when must this session stop?", which keeps
session end times, timers and downtime catch-up consistent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from enum import StrEnum

from app.clock import LogicalCalendar
from app.config import AppConfig


class Reason(StrEnum):
    OK = "OK"
    OVERRIDE_ACTIVE = "OVERRIDE_ACTIVE"
    PARENT_SESSION = "PARENT_SESSION"
    DAY_LOCKED = "DAY_LOCKED"
    DEVICE_CUTOFF = "DEVICE_CUTOFF"
    BEFORE_EARLIEST_START = "BEFORE_EARLIEST_START"
    NO_ALLOWANCE = "NO_ALLOWANCE"
    INSUFFICIENT_ALLOWANCE = "INSUFFICIENT_ALLOWANCE"
    ALREADY_ACTIVE = "ALREADY_ACTIVE"
    NOT_OWNER = "NOT_OWNER"
    NOT_PERMITTED = "NOT_PERMITTED"
    UNKNOWN_DEVICE = "UNKNOWN_DEVICE"
    DEVICE_DISABLED = "DEVICE_DISABLED"
    INVALID_DURATION = "INVALID_DURATION"
    ENFORCEMENT_DEGRADED = "ENFORCEMENT_DEGRADED"
    ENFORCEMENT_FAILED = "ENFORCEMENT_FAILED"
    EXTENSION_NOT_YET = "EXTENSION_NOT_YET"
    EXTENSION_NO_ALLOWANCE = "EXTENSION_NO_ALLOWANCE"
    SESSION_NOT_ACTIVE = "SESSION_NOT_ACTIVE"
    NOT_FOUND = "NOT_FOUND"
    FORBIDDEN = "FORBIDDEN"


@dataclass(frozen=True)
class Interval:
    start: datetime
    end: datetime | None = None  # None = open-ended

    def covers(self, instant: datetime) -> bool:
        return self.start <= instant and (self.end is None or instant < self.end)


@dataclass(frozen=True)
class ChildFacts:
    """Everything the evaluator needs to know about one child, for one device, at one moment."""

    child_id: str
    day: date
    remaining_seconds: int
    uncommitted_seconds: int
    locks: tuple[Interval, ...] = ()
    overrides: tuple[Interval, ...] = ()
    active_device_ids: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: Reason
    message: str
    max_end_at: datetime | None = None  # latest instant a session may run to, if capped

    @property
    def override_used(self) -> bool:
        return self.reason is Reason.OVERRIDE_ACTIVE


def format_duration(seconds: int) -> str:
    minutes = max(0, seconds) // 60
    hours, mins = divmod(minutes, 60)
    if hours and mins:
        return f"{hours}h {mins}m"
    if hours:
        return f"{hours}h"
    return f"{mins}m"


def _denial_message(
    cfg: AppConfig, cal: LogicalCalendar, reason: Reason, device_id: str, child_id: str
) -> str:
    device = cfg.devices[device_id]
    match reason:
        case Reason.DAY_LOCKED:
            return "Screen time has finished for today."
        case Reason.DEVICE_CUTOFF:
            cutoff = device.weekday_cutoff.strftime("%H:%M") if device.weekday_cutoff else ""
            return f"{device.display_name} is finished for today (it stops at {cutoff})."
        case Reason.BEFORE_EARLIEST_START:
            start = cfg.children[child_id].weekday_earliest_start
            at = start.strftime("%H:%M") if start else ""
            return f"Screen time starts at {at} on school days."
        case _:
            return "Not allowed right now."


class PolicyEngine:
    def __init__(self, config: AppConfig, calendar: LogicalCalendar) -> None:
        self.cfg = config
        self.cal = calendar

    # -- timeline model ---------------------------------------------------------------

    def _denied_intervals(
        self, facts: ChildFacts, device_id: str
    ) -> list[tuple[Reason, datetime, datetime | None]]:
        """Restriction windows in rule order (lock, cutoff, start), around ``facts.day``."""
        cal, cfg = self.cal, self.cfg
        day = facts.day
        day_start, day_end = cal.day_bounds(day)
        child = cfg.children[facts.child_id]
        device = cfg.devices[device_id]
        out: list[tuple[Reason, datetime, datetime | None]] = []
        for lock in facts.locks:
            out.append(
                (Reason.DAY_LOCKED, lock.start, min(lock.end, day_end) if lock.end else day_end)
            )
        if device.weekday_cutoff and not cal.is_weekend(day):
            out.append(
                (Reason.DEVICE_CUTOFF, cal.instant_on_day(day, device.weekday_cutoff), day_end)
            )
        if child.weekday_earliest_start:
            if not cal.is_weekend(day):
                out.append(
                    (
                        Reason.BEFORE_EARLIEST_START,
                        day_start,
                        cal.instant_on_day(day, child.weekday_earliest_start),
                    )
                )
            next_day = day + timedelta(days=1)
            if not cal.is_weekend(next_day):
                out.append(
                    (
                        Reason.BEFORE_EARLIEST_START,
                        day_end,
                        cal.instant_on_day(next_day, child.weekday_earliest_start),
                    )
                )
        return out

    @staticmethod
    def _denial_at(
        instant: datetime,
        denied: list[tuple[Reason, datetime, datetime | None]],
        overrides: tuple[Interval, ...],
    ) -> Reason | None:
        if any(o.covers(instant) for o in overrides):
            return None
        for reason, start, end in denied:
            if start <= instant and (end is None or instant < end):
                return reason
        return None

    def first_denied(
        self, facts: ChildFacts, device_id: str, frm: datetime
    ) -> tuple[datetime, Reason] | None:
        """Earliest instant >= ``frm`` at which a child session on this device is not permitted."""
        denied = self._denied_intervals(facts, device_id)
        points = {frm}
        for _, start, end in denied:
            points.update(p for p in (start, end) if p is not None and p > frm)
        for override in facts.overrides:
            points.update(p for p in (override.start, override.end) if p is not None and p > frm)
        for instant in sorted(points):
            reason = self._denial_at(instant, denied, facts.overrides)
            if reason is not None:
                return instant, reason
        return None

    def bypassed_by_override(self, facts: ChildFacts, device_id: str, now: datetime) -> bool:
        denied = self._denied_intervals(facts, device_id)
        return (
            self._denial_at(now, denied, ()) is not None
            and self._denial_at(now, denied, facts.overrides) is None
        )

    # -- durations --------------------------------------------------------------------

    def allowed_durations(self, facts: ChildFacts) -> list[int]:
        """Minutes the child may pick now: configured choices that fit, plus a final 'last minutes' option."""
        choices = self.cfg.sessions.child_choices_minutes
        fits = [m for m in choices if m * 60 <= facts.uncommitted_seconds]
        leftover = facts.uncommitted_seconds // 60
        if 1 <= leftover < min(choices):
            fits.append(leftover)
        return fits

    # -- evaluators -------------------------------------------------------------------

    def evaluate_start(
        self,
        facts: ChildFacts,
        device_id: str,
        requested_seconds: int,
        now: datetime,
        *,
        check_duration: bool = True,
    ) -> Decision:
        cfg = self.cfg
        device = cfg.devices.get(device_id)
        if device is None:
            return Decision(False, Reason.UNKNOWN_DEVICE, "That device is not known.")
        if not device.enabled:
            return Decision(
                False, Reason.DEVICE_DISABLED, f"{device.display_name} is switched off."
            )
        if check_duration and requested_seconds // 60 not in self.allowed_durations_all(facts):
            return Decision(
                False, Reason.INVALID_DURATION, "Please choose one of the time options."
            )
        if requested_seconds < 60:
            return Decision(False, Reason.INVALID_DURATION, "That is too short to start.")

        # Rules 3-5 (rule 1 lifts them for the override window).
        denied = self._denied_intervals(facts, device_id)
        without_override = self._denial_at(now, denied, ())
        with_override = self._denial_at(now, denied, facts.overrides)
        if with_override is not None:
            return Decision(
                False,
                with_override,
                _denial_message(cfg, self.cal, with_override, device_id, facts.child_id),
            )
        override_used = without_override is not None

        # Rule 6: allowance (base + explicit adjustments, less uncommitted reservations).
        if facts.uncommitted_seconds < requested_seconds:
            if facts.uncommitted_seconds < 60:
                return Decision(False, Reason.NO_ALLOWANCE, "No screen time left today.")
            return Decision(
                False,
                Reason.INSUFFICIENT_ALLOWANCE,
                f"Only {format_duration(facts.uncommitted_seconds)} left today. Pick a shorter time.",
            )

        # Rule 7: one active device per child.
        if device_id in facts.active_device_ids:
            return Decision(
                False, Reason.ALREADY_ACTIVE, f"You are already using {device.display_name}."
            )
        if len(facts.active_device_ids) >= cfg.sessions.max_concurrent_devices_per_child:
            names = ", ".join(sorted(cfg.devices[d].display_name for d in facts.active_device_ids))
            return Decision(False, Reason.ALREADY_ACTIVE, f"You are already using {names}.")

        # Rule 8: entitlement.
        if device.type == "personal":
            if device.owner != facts.child_id:
                return Decision(False, Reason.NOT_OWNER, f"{device.display_name} is not yours.")
        elif device_id not in cfg.children[facts.child_id].permitted_shared_devices:
            return Decision(False, Reason.NOT_PERMITTED, f"You can't use {device.display_name}.")

        # Cap the session where the next restriction begins (e.g. the TV cutoff).
        stop = self.first_denied(facts, device_id, now)
        max_end = stop[0] if stop else None
        if max_end is not None and (max_end - now).total_seconds() < 60:
            assert stop is not None
            return Decision(
                False, stop[1], _denial_message(cfg, self.cal, stop[1], device_id, facts.child_id)
            )
        reason = Reason.OVERRIDE_ACTIVE if override_used else Reason.OK
        return Decision(True, reason, "OK", max_end_at=max_end)

    def allowed_durations_all(self, facts: ChildFacts) -> list[int]:
        """Duration values that are *valid* choices (fit or not); fitting is checked separately."""
        choices = list(self.cfg.sessions.child_choices_minutes)
        leftover = facts.uncommitted_seconds // 60
        if 1 <= leftover < min(choices):
            choices.append(leftover)
        return choices

    def evaluate_extension(
        self,
        facts: ChildFacts,
        device_id: str,
        planned_end: datetime,
        now: datetime,
    ) -> Decision:
        cfg = self.cfg
        extension = cfg.sessions.child_extension_minutes * 60
        if planned_end <= now:
            return Decision(False, Reason.SESSION_NOT_ACTIVE, "That session has already ended.")
        if (planned_end - now).total_seconds() > cfg.warning_minutes * 60:
            return Decision(
                False,
                Reason.EXTENSION_NOT_YET,
                f"You can ask for more time in the last {cfg.warning_minutes} minutes.",
            )
        new_end = planned_end + timedelta(seconds=extension)
        stop = self.first_denied(facts, device_id, now)
        if stop is not None and stop[0] < new_end:
            return Decision(
                False, stop[1], _denial_message(cfg, self.cal, stop[1], device_id, facts.child_id)
            )
        if facts.uncommitted_seconds < extension:
            return Decision(
                False,
                Reason.EXTENSION_NO_ALLOWANCE,
                f"Not enough time left today for +{cfg.sessions.child_extension_minutes} minutes. "
                "Ask a parent for more.",
            )
        return Decision(True, Reason.OK, "OK", max_end_at=stop[0] if stop else None)

    def device_status(self, facts: ChildFacts, device_id: str, now: datetime) -> Decision:
        """Can this child start *something* on this device right now? Used for dashboard hints."""
        shortest = min(self.cfg.sessions.child_choices_minutes) * 60
        seconds = shortest
        options = self.allowed_durations(facts)
        if options:
            seconds = min(options) * 60
        return self.evaluate_start(facts, device_id, seconds, now, check_duration=False)
