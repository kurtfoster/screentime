"""Time sources and the logical-day calendar.

All instants are timezone-aware UTC internally. Policy is evaluated in the household
timezone via :class:`LogicalCalendar`. The logical day starts at ``logical_day_reset``
(02:00 by default) so late-evening use still counts against the day it belongs to.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta, tzinfo
from pathlib import Path
from typing import Protocol
from zoneinfo import ZoneInfo


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FakeClock:
    """Manually driven clock for tests and simulations."""

    def __init__(self, start: datetime) -> None:
        if start.tzinfo is None:
            raise ValueError("FakeClock requires an aware datetime")
        self._now = start.astimezone(UTC)

    def now(self) -> datetime:
        return self._now

    def set(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("FakeClock requires an aware datetime")
        self._now = value.astimezone(UTC)

    def advance(self, **kwargs: float) -> datetime:
        self._now += timedelta(**kwargs)
        return self._now


class ClockSync(Protocol):
    def synchronised(self) -> bool: ...


class TimesyncdMarker:
    """True once systemd-timesyncd has synchronised the clock since boot.

    The Pi has no real-time clock: after a power cut ``fake-hwclock`` restores the last saved
    time, which is in the past. timesyncd creates the marker file on its first successful
    synchronisation and keeps it for the rest of the boot, so once seen it is latched.
    """

    DEFAULT = Path("/run/systemd/timesync/synchronized")

    def __init__(self, marker: Path = DEFAULT) -> None:
        self._marker = marker
        self._seen = False

    def synchronised(self) -> bool:
        if not self._seen:
            self._seen = self._marker.exists()
        return self._seen


class AssumeSynchronised:
    """For development machines and tests, where the host clock is trusted."""

    def synchronised(self) -> bool:
        return True


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("naive datetime not allowed")
    return value.astimezone(UTC)


class LogicalCalendar:
    """Maps instants to logical days and resolves wall-clock rules to instants."""

    def __init__(self, zone: ZoneInfo | tzinfo, reset: time) -> None:
        self.zone = zone
        self.reset = reset

    def local(self, instant: datetime) -> datetime:
        return ensure_utc(instant).astimezone(self.zone)

    def _wall_to_utc(self, day: date, at: time) -> datetime:
        # fold=0 resolves a repeated wall time to its first occurrence, and a skipped
        # wall time (spring-forward gap) to the instant the clocks jump.
        return datetime.combine(day, at, tzinfo=self.zone).astimezone(UTC)

    def day_start(self, day: date) -> datetime:
        return self._wall_to_utc(day, self.reset)

    def day_bounds(self, day: date) -> tuple[datetime, datetime]:
        return self.day_start(day), self.day_start(day + timedelta(days=1))

    def logical_day(self, instant: datetime) -> date:
        """The logical day containing ``instant``; consistent with :meth:`day_bounds` across DST."""
        instant = ensure_utc(instant)
        local_date = instant.astimezone(self.zone).date()
        if instant < self.day_start(local_date):
            return local_date - timedelta(days=1)
        return local_date

    def is_weekend(self, day: date) -> bool:
        return day.weekday() >= 5

    def instant_on_day(self, day: date, at: time) -> datetime:
        """Resolve a wall-clock time belonging to logical ``day``.

        Times at or after the reset fall on the same calendar date; earlier times
        (e.g. a 01:00 cutoff) belong to the following calendar date.
        """
        calendar_day = day if at >= self.reset else day + timedelta(days=1)
        return self._wall_to_utc(calendar_day, at)

    def format_local(self, instant: datetime, fmt: str = "%H:%M") -> str:
        return self.local(instant).strftime(fmt)
