from datetime import UTC, date, datetime, time, timedelta

import pytest

from app.clock import FakeClock, LogicalCalendar
from tests.conftest import MELBOURNE, at


@pytest.fixture
def cal() -> LogicalCalendar:
    return LogicalCalendar(MELBOURNE, time(2, 0))


def spec_logical_day(now_local: datetime) -> date:
    """The reference implementation from specification section 8.1."""
    if now_local.time() < time(2, 0):
        return now_local.date() - timedelta(days=1)
    return now_local.date()


def test_before_and_after_reset(cal: LogicalCalendar) -> None:
    assert cal.logical_day(at(1, 59, day=date(2026, 9, 22))) == date(2026, 9, 21)
    assert cal.logical_day(at(2, 0, day=date(2026, 9, 22))) == date(2026, 9, 22)
    assert cal.logical_day(at(23, 59, day=date(2026, 9, 22))) == date(2026, 9, 22)
    assert cal.logical_day(at(0, 0, day=date(2026, 9, 22))) == date(2026, 9, 21)


def test_matches_spec_function_on_ordinary_days(cal: LogicalCalendar) -> None:
    start = datetime(2026, 9, 1, tzinfo=UTC)
    for step in range(0, 60 * 24 * 30, 37):
        instant = start + timedelta(minutes=step)
        assert cal.logical_day(instant) == spec_logical_day(instant.astimezone(MELBOURNE))


def test_spring_forward_day_boundary(cal: LogicalCalendar) -> None:
    # 2026-10-04: clocks jump 02:00 AEST -> 03:00 AEDT, so 02:00 does not exist.
    before = datetime(2026, 10, 3, 15, 59, 59, tzinfo=UTC)  # 01:59:59 AEST
    after = datetime(2026, 10, 3, 16, 0, 0, tzinfo=UTC)  # 03:00:00 AEDT
    assert cal.logical_day(before) == date(2026, 10, 3)
    assert cal.logical_day(after) == date(2026, 10, 4)
    start, end = cal.day_bounds(date(2026, 10, 4))
    assert start == after
    assert end - start == timedelta(hours=23)


def test_fall_back_day_boundary(cal: LogicalCalendar) -> None:
    # 2026-04-05: clocks fall 03:00 AEDT -> 02:00 AEST, so 02:00-03:00 happens twice.
    first_two = datetime(2026, 4, 4, 15, 0, 0, tzinfo=UTC)  # 02:00 AEDT (first occurrence)
    assert cal.logical_day(first_two - timedelta(seconds=1)) == date(2026, 4, 4)
    assert cal.logical_day(first_two) == date(2026, 4, 5)
    # The repeated 02:xx hour stays inside the same logical day.
    assert cal.logical_day(first_two + timedelta(hours=1, minutes=30)) == date(2026, 4, 5)
    start, end = cal.day_bounds(date(2026, 4, 5))
    assert start == first_two
    assert end - start == timedelta(hours=25)


def test_bounds_are_consistent_with_logical_day_everywhere(cal: LogicalCalendar) -> None:
    for month_day in [date(2026, 4, 5), date(2026, 10, 4), date(2026, 9, 21)]:
        start, end = cal.day_bounds(month_day)
        assert cal.logical_day(start) == month_day
        assert cal.logical_day(end - timedelta(seconds=1)) == month_day
        assert cal.logical_day(end) == month_day + timedelta(days=1)


def test_weekend_detection(cal: LogicalCalendar) -> None:
    assert not cal.is_weekend(date(2026, 9, 25))  # Friday
    assert cal.is_weekend(date(2026, 9, 26))
    assert cal.is_weekend(date(2026, 9, 27))
    assert not cal.is_weekend(date(2026, 9, 28))


def test_friday_night_after_midnight_is_still_a_weekday(cal: LogicalCalendar) -> None:
    saturday_0030 = at(0, 30, day=date(2026, 9, 26))
    assert cal.logical_day(saturday_0030) == date(2026, 9, 25)
    assert not cal.is_weekend(cal.logical_day(saturday_0030))


def test_instant_on_day_places_early_times_on_next_calendar_date(cal: LogicalCalendar) -> None:
    day = date(2026, 9, 21)
    assert cal.instant_on_day(day, time(18, 30)) == at(18, 30, day=day)
    assert cal.instant_on_day(day, time(1, 0)) == at(1, 0, day=date(2026, 9, 22))


def test_fake_clock_rejects_naive_datetimes() -> None:
    with pytest.raises(ValueError):
        FakeClock(datetime(2026, 1, 1))
