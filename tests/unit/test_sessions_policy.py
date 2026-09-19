"""Policy precedence, allowance accounting and session lifecycle (spec 24.1 / 24.3)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from app.models import (
    SESSION_ENFORCEMENT_FAILED,
    AllowanceAdjustment,
    DayLock,
    NotificationEvent,
    SessionRecord,
)
from app.policy import Reason
from app.state import allowance_summary, desired_active_ips
from tests.conftest import MONDAY, SATURDAY, Env, at, build_env


def summary(env: Env, child: str = "child8"):
    with env.db.session() as db:
        return allowance_summary(db, env.config, env.calendar, child, env.clock.now())


def start(env: Env, child: str, device: str, minutes: int = 30, **kw):
    return env.service.start_child_session(child, device, minutes, **kw)


# --- allowance -------------------------------------------------------------------------


def test_weekday_and_weekend_base_allowance(env: Env) -> None:
    env.set(10, 0, MONDAY)
    assert summary(env).base_seconds == 120 * 60
    env.set(10, 0, SATURDAY)
    assert summary(env).base_seconds == 180 * 60


def test_remaining_includes_adjustments_and_elapsed_active_time(env: Env) -> None:
    env.set(10, 0)
    assert start(env, "child8", "ipad", 30).ok
    env.set(10, 12)
    assert summary(env).remaining_seconds == (120 - 12) * 60
    assert env.service.parent_grant("child8", 15, "parents").ok
    assert summary(env).remaining_seconds == (120 + 15 - 12) * 60
    assert summary(env).remaining_minutes == 123


def test_active_charge_never_exceeds_reservation(env: Env) -> None:
    env.set(10, 0)
    start(env, "child8", "ipad", 15)
    env.set(11, 0)  # timer has not ticked yet; only 15 minutes may be charged
    assert summary(env).charged_seconds == 15 * 60


def test_early_stop_charges_only_elapsed_and_refunds_the_rest(env: Env) -> None:
    env.set(10, 0)
    start(env, "child8", "ipad", 30)
    env.set(10, 10)
    res = env.service.stop_session(1, actor="child8", role="child", child_id="child8")
    assert res.ok and res.ended_device_ids == {"ipad"}
    assert summary(env).charged_seconds == 10 * 60
    assert summary(env).remaining_minutes == 110


def test_stop_can_charge_full_reservation_when_configured(tmp_path: Path) -> None:
    env = build_env(tmp_path, sessions={"stop_returns_unused_reserved_time": False})
    env.set(10, 0)
    start(env, "child8", "ipad", 30)
    env.set(10, 5)
    env.service.stop_session(1, actor="child8", role="child", child_id="child8")
    assert summary(env).charged_seconds == 30 * 60


def test_session_spanning_reset_is_charged_to_each_logical_day(env: Env) -> None:
    # Saturday 01:30 belongs to Friday's logical day; 02:00 begins Saturday's.
    env.set(1, 30, SATURDAY)
    assert start(env, "child8", "ipad", 60).ok
    env.set(2, 30, SATURDAY)
    with env.db.session() as db:
        sess = db.get(SessionRecord, 1)
        assert sess is not None
        from app.state import session_charge_seconds

        friday = env.calendar.day_bounds(SATURDAY - timedelta(days=1))
        saturday = env.calendar.day_bounds(SATURDAY)
        assert session_charge_seconds(sess, *friday, env.clock.now()) == 30 * 60
        assert session_charge_seconds(sess, *saturday, env.clock.now()) == 30 * 60


# --- start-time and cutoff rules ---------------------------------------------------------


def test_weekday_earliest_start_is_enforced(env: Env) -> None:
    env.set(8, 30)
    res = start(env, "child8", "ipad")
    assert not res.ok and res.reason is Reason.BEFORE_EARLIEST_START
    env.set(9, 0)
    assert start(env, "child8", "ipad").ok


def test_no_earliest_start_on_weekends(env: Env) -> None:
    env.set(7, 30, SATURDAY)
    assert start(env, "child8", "ipad").ok


def test_kids_tv_cutoff_rejects_at_1830_without_override(env: Env) -> None:
    env.set(18, 30)
    res = start(env, "child8", "kids_tv")
    assert not res.ok and res.reason is Reason.DEVICE_CUTOFF


def test_cutoff_only_applies_on_weekdays_and_only_to_that_device(env: Env) -> None:
    env.set(19, 0)
    assert start(env, "child8", "lounge_tv").ok
    env.set(19, 0, SATURDAY)
    assert start(env, "child12", "kids_tv").ok


def test_session_is_capped_at_the_cutoff(env: Env) -> None:
    env.set(18, 10)
    res = start(env, "child8", "kids_tv", 30)
    assert res.ok
    assert res.sessions[0].planned_end_at == at(18, 30)
    assert res.sessions[0].reserved_seconds == 20 * 60


def test_cutoff_ends_running_session_after_downtime_charging_only_to_cutoff(env: Env) -> None:
    env.set(18, 0)
    start(env, "child8", "kids_tv", 60)  # capped to 18:30 by the cutoff rule
    env.set(20, 0)  # simulate the app being down until 20:00
    tick = env.service.tick()
    assert [s.end_reason for s in tick.ended] == ["expired"]
    assert summary(env).charged_seconds == 30 * 60


# --- parent overrides ------------------------------------------------------------------


def test_parent_grant_at_1830_permits_exactly_the_granted_window(env: Env) -> None:
    env.set(18, 30)
    assert not start(env, "child8", "kids_tv").ok
    assert env.service.parent_grant("child8", 30, "parents").ok
    res = start(env, "child8", "kids_tv", 60)
    # Allowance is plentiful (150 min), so the session is capped by the grant window: 19:00.
    assert res.ok, res.message
    assert res.sessions[0].planned_end_at == at(19, 0)
    assert res.sessions[0].reserved_seconds == 30 * 60
    env.set(18, 59, second=59)
    assert env.service.tick().ended == []
    env.set(19, 0)
    ended = env.service.tick().ended
    assert len(ended) == 1 and ended[0].end_reason == "expired"
    # After the window the cutoff applies again.
    res2 = start(env, "child8", "kids_tv", 15)
    assert not res2.ok and res2.reason is Reason.DEVICE_CUTOFF


def test_grant_overrides_early_start_rule(env: Env) -> None:
    env.set(8, 0)
    assert env.service.parent_grant("child8", 30, "parents").ok
    res = start(env, "child8", "ipad", 30)
    assert res.ok and res.sessions[0].planned_end_at == at(8, 30)


def test_grant_overrides_exhausted_allowance(env: Env) -> None:
    env.set(10, 0)
    for _ in range(4):
        assert start(env, "child8", "ipad", 30).ok
        env.clock.advance(minutes=30)
        env.service.tick()
    assert start(env, "child8", "ipad", 15).reason is Reason.NO_ALLOWANCE
    env.service.parent_grant("child8", 15, "parents")
    assert start(env, "child8", "ipad", 15).ok


def test_grant_window_includes_time_already_reserved(env: Env) -> None:
    from app.models import ParentOverride

    env.set(18, 0)
    start(env, "child8", "kids_tv", 60)  # capped at the 18:30 cutoff
    env.set(18, 25)  # five minutes of that reservation are still unelapsed
    env.service.parent_grant("child8", 30, "parents")
    with env.db.session() as db:
        override = db.scalars(select(ParentOverride)).one()
        assert override.starts_at == at(18, 25)
        assert override.ends_at == at(19, 0)  # 30 granted + 5 already reserved


def test_end_today_locks_ends_sessions_and_revokes_earlier_grant_windows(env: Env) -> None:
    env.set(10, 0)
    env.service.parent_grant("child8", 60, "parents")
    start(env, "child8", "ipad", 30)
    res = env.service.end_today("child8", "parents")
    assert res.ok and res.ended_device_ids == {"ipad"}
    denied = start(env, "child8", "ipad")
    assert not denied.ok and denied.reason is Reason.DAY_LOCKED
    with env.db.session() as db:
        assert db.scalars(select(DayLock)).one().cleared_at is None


def test_grant_after_end_today_bypasses_lock_and_keeps_both_records(env: Env) -> None:
    env.set(10, 0)
    env.service.end_today("child8", "parents")
    env.clock.advance(minutes=1)
    assert env.service.parent_grant("child8", 15, "parents").ok
    res = start(env, "child8", "ipad", 15)
    assert res.ok
    assert res.sessions[0].planned_end_at == env.clock.now() + timedelta(minutes=15)
    with env.db.session() as db:
        assert len(db.scalars(select(DayLock)).all()) == 1
        assert len(db.scalars(select(AllowanceAdjustment)).all()) == 1
    env.clock.advance(minutes=15)
    env.service.tick()
    assert start(env, "child8", "ipad", 15).reason is Reason.DAY_LOCKED


def test_clear_day_lock_reenables_starts(env: Env) -> None:
    env.set(10, 0)
    env.service.end_today("child8", "parents")
    env.service.clear_day_lock("child8", "parents")
    assert start(env, "child8", "ipad", 15).ok


def test_day_lock_lapses_at_the_logical_day_boundary(env: Env) -> None:
    env.set(20, 0, SATURDAY - timedelta(days=1))  # Friday evening
    env.service.end_today("child8", "parents")
    assert start(env, "child8", "lounge_tv", 15).reason is Reason.DAY_LOCKED
    env.set(0, 30, SATURDAY)  # still Friday's logical day
    assert start(env, "child8", "lounge_tv", 15).reason is Reason.DAY_LOCKED
    env.set(2, 0, SATURDAY)  # Saturday: weekend, no earliest start
    assert start(env, "child8", "lounge_tv", 15).ok


def test_day_lock_is_per_child(env: Env) -> None:
    env.set(10, 0)
    env.service.end_today("child8", "parents")
    assert start(env, "child12", "iphone_child12", 15).ok


# --- allowance, devices, entitlement ---------------------------------------------------


def test_request_within_allowance_starts_with_planned_end(env: Env) -> None:
    env.set(10, 0)
    res = start(env, "child8", "ipad", 30)
    assert res.ok
    assert res.sessions[0].planned_end_at == at(10, 30)


def test_request_larger_than_remaining_is_rejected(env: Env) -> None:
    env.set(10, 0)
    env.service.parent_grant("child8", 15, "parents")  # not relevant, keeps a grant record
    for _ in range(3):
        start(env, "child8", "ipad", 30)
        env.clock.advance(minutes=30)
        env.service.tick()
    # 135 - 90 = 45 minutes left, a 60 request must fail
    res = start(env, "child8", "ipad", 60)
    assert not res.ok and res.reason is Reason.INSUFFICIENT_ALLOWANCE


def test_last_minutes_option_offered_when_below_smallest_choice(env: Env) -> None:
    from app.state import load_facts

    env.set(10, 0)
    for minutes in (30, 30, 30, 15):
        start(env, "child8", "ipad", minutes)
        env.clock.advance(minutes=minutes)
        env.service.tick()
    # 120 - 105 = 15 left; take 5 back by stopping a fresh session early
    s = start(env, "child8", "ipad", 15).sessions[0]
    env.clock.advance(minutes=5)
    env.service.stop_session(s.id, actor="child8", role="child", child_id="child8")
    assert summary(env).remaining_minutes == 10
    with env.db.session() as db:
        facts = load_facts(db, env.config, env.calendar, "child8", "ipad", env.clock.now())
    assert env.service.policy.allowed_durations(facts) == [10]
    assert start(env, "child8", "ipad", 15).reason is Reason.INSUFFICIENT_ALLOWANCE
    assert start(env, "child8", "ipad", 10).ok


def test_already_using_another_device_is_rejected(env: Env) -> None:
    env.set(10, 0)
    assert start(env, "child8", "ipad").ok
    res = start(env, "child8", "kids_tv")
    assert not res.ok and res.reason is Reason.ALREADY_ACTIVE
    assert "iPad" in res.message


def test_personal_device_only_by_owner(env: Env) -> None:
    env.set(10, 0)
    res = start(env, "child12", "ipad")
    assert not res.ok and res.reason is Reason.NOT_OWNER


def test_unknown_device_and_invalid_duration_rejected(env: Env) -> None:
    env.set(10, 0)
    assert start(env, "child8", "nope").reason is Reason.UNKNOWN_DEVICE
    assert start(env, "child8", "ipad", 45).reason is Reason.INVALID_DURATION


def test_rejections_are_audited(env: Env) -> None:
    from app.models import AuditEvent

    env.set(8, 0)
    start(env, "child8", "ipad")
    with env.db.session() as db:
        event = db.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "session_rejected")
        ).one()
        assert event.result == "denied" and "BEFORE_EARLIEST_START" in event.details_json


def test_idempotent_start_returns_same_session(env: Env) -> None:
    env.set(10, 0)
    first = start(env, "child8", "ipad", idempotency_key="abcdefgh-1")
    second = start(env, "child8", "ipad", idempotency_key="abcdefgh-1")
    assert first.ok and second.ok and second.duplicate
    assert second.sessions[0].id == first.sessions[0].id
    with env.db.session() as db:
        assert len(db.scalars(select(SessionRecord)).all()) == 1


# --- shared TV -------------------------------------------------------------------------


def test_shared_tv_two_participants_charged_independently(env: Env) -> None:
    env.set(10, 0)
    res = start(env, "child8", "kids_tv", 30, participants=("child12",))
    assert res.ok and len(res.sessions) == 2
    assert {s.child_id for s in res.sessions} == {"child8", "child12"}
    assert len({s.group_id for s in res.sessions}) == 1
    env.set(10, 10)
    env.service.stop_session(res.sessions[0].id, actor="child8", role="child", child_id="child8")
    assert summary(env, "child8").charged_seconds == 10 * 60
    assert summary(env, "child12").remaining_minutes == 110  # still running, charged as elapsed
    with env.db.session() as db:
        assert desired_active_ips(db, env.clock.now()) == {"192.168.12.40"}


def test_participant_rejection_names_the_sibling(env: Env) -> None:
    env.set(10, 0)
    env.service.end_today("child12", "parents")
    res = start(env, "child8", "kids_tv", 30, participants=("child12",))
    assert not res.ok and res.message.startswith("Child 12 can't join")


def test_participants_only_on_shared_devices(env: Env) -> None:
    env.set(10, 0)
    assert not start(env, "child8", "ipad", 30, participants=("child12",)).ok


def test_add_participant_joins_with_same_planned_end(env: Env) -> None:
    env.set(10, 0)
    base = start(env, "child8", "kids_tv", 30)
    env.set(10, 10)
    res = env.service.add_participant(base.sessions[0].id, "child8", "child12")
    assert res.ok
    joined = res.sessions[0]
    assert joined.planned_end_at == at(10, 30) and joined.group_id == base.sessions[0].group_id
    again = env.service.add_participant(base.sessions[0].id, "child8", "child12")
    assert not again.ok and again.reason is Reason.ALREADY_ACTIVE


def test_second_child_can_start_shared_tv_separately(env: Env) -> None:
    env.set(10, 0)
    assert start(env, "child8", "kids_tv", 30).ok
    assert start(env, "child12", "kids_tv", 15).ok


# --- extensions ------------------------------------------------------------------------


def test_extension_not_offered_before_warning_window(env: Env) -> None:
    env.set(10, 0)
    s = start(env, "child8", "ipad", 30).sessions[0]
    env.set(10, 20)
    res = env.service.extend_session(s.id, "child8")
    assert not res.ok and res.reason is Reason.EXTENSION_NOT_YET


def test_extension_adds_exactly_fifteen_minutes(env: Env) -> None:
    env.set(10, 0)
    s = start(env, "child8", "ipad", 30).sessions[0]
    env.set(10, 25)
    res = env.service.extend_session(s.id, "child8")
    assert res.ok
    assert res.sessions[0].planned_end_at == at(10, 45)
    assert res.sessions[0].reserved_seconds == 45 * 60


def test_extension_rejected_without_fifteen_uncommitted_minutes(env: Env) -> None:
    env.set(10, 0)
    for _ in range(3):
        start(env, "child8", "ipad", 30)
        env.clock.advance(minutes=30)
        env.service.tick()
    s = start(env, "child8", "ipad", 30).sessions[0]  # 90 + 30 = 120: nothing uncommitted
    env.clock.advance(minutes=26)
    res = env.service.extend_session(s.id, "child8")
    assert not res.ok and res.reason is Reason.EXTENSION_NO_ALLOWANCE


def test_extension_cannot_cross_the_cutoff(env: Env) -> None:
    env.set(18, 0)
    s = start(env, "child8", "kids_tv", 30).sessions[0]  # 18:00 - 18:30
    env.set(18, 26)
    res = env.service.extend_session(s.id, "child8")
    assert not res.ok and res.reason is Reason.DEVICE_CUTOFF


def test_extension_is_atomic_under_concurrent_requests(env: Env) -> None:
    """Two simultaneous presses with room for only one extension: exactly one wins."""
    import threading

    env.set(10, 0)
    for _ in range(3):
        start(env, "child8", "ipad", 30)
        env.clock.advance(minutes=30)
        env.service.tick()
    s = start(env, "child8", "ipad", 15).sessions[0]
    # 120 - 90 - 15 reserved = 15 uncommitted: room for exactly one extension.
    env.clock.advance(minutes=11)
    results: list[bool] = []
    barrier = threading.Barrier(2)

    def press() -> None:
        barrier.wait()
        results.append(env.service.extend_session(s.id, "child8").ok)

    threads = [threading.Thread(target=press) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [False, True]


def test_extension_all_mode_requires_every_participant(env: Env) -> None:
    env.set(10, 0)
    for _ in range(3):
        start(env, "child12", "iphone_child12", 30)
        env.clock.advance(minutes=30)
        env.service.tick()
    # child12 has 30 min left; child8 has 120
    res = start(env, "child8", "kids_tv", 30, participants=("child12",))
    assert res.ok
    env.clock.advance(minutes=26)
    strict = env.service.extend_session(res.sessions[0].id, "child8", mode="all")
    assert not strict.ok and strict.ineligible == ["Child 12"]
    lenient = env.service.extend_session(res.sessions[0].id, "child8", mode="eligible")
    assert lenient.ok and [s.child_id for s in lenient.sessions] == ["child8"]


# --- timers ----------------------------------------------------------------------------


def test_session_auto_ends_at_planned_end_and_charges_reservation(env: Env) -> None:
    env.set(10, 0)
    start(env, "child8", "ipad", 30)
    env.set(10, 29, second=59)
    assert env.service.tick().ended == []
    env.set(10, 30)
    result = env.service.tick()
    assert [s.end_reason for s in result.ended] == ["expired"]
    assert result.ended_device_ids == {"ipad"}
    assert summary(env).charged_seconds == 30 * 60


def test_warning_fires_exactly_once_and_rearms_after_extension(env: Env) -> None:
    env.set(10, 0)
    s = start(env, "child8", "ipad", 30).sessions[0]
    env.set(10, 24, second=59)
    assert env.service.tick().warned == []
    env.set(10, 25)
    assert env.service.tick().warned == [s.id]
    env.set(10, 26)
    assert env.service.tick().warned == []
    env.service.extend_session(s.id, "child8")
    env.set(10, 40)
    assert env.service.tick().warned == [s.id]
    with env.db.session() as db:
        kinds = [n.kind for n in db.scalars(select(NotificationEvent)).all()]
        assert kinds.count("session_warning") == 2


def test_session_end_creates_child_and_parent_notifications(env: Env) -> None:
    env.set(10, 0)
    start(env, "child8", "ipad", 15)
    env.set(10, 15)
    env.service.tick()
    with env.db.session() as db:
        audiences = {
            n.audience
            for n in db.scalars(select(NotificationEvent)).all()
            if n.kind == "session_ended"
        }
        assert audiences == {"child", "parent"}


def test_revoked_override_ends_a_session_that_depended_on_it(env: Env) -> None:
    env.set(8, 0)
    env.service.parent_grant("child8", 30, "parents")
    start(env, "child8", "ipad", 30)
    env.set(8, 10)
    with env.db.session() as db:
        from app.models import ParentOverride

        override_id = db.scalars(select(ParentOverride)).one().id
    env.service.revoke_override(override_id, "parents")
    result = env.service.tick()
    assert [s.end_reason for s in result.ended] == ["before_start_time"]
    assert summary(env).charged_seconds == 10 * 60


def test_parent_tv_session_does_not_charge_children(env: Env) -> None:
    env.set(18, 45)
    res = env.service.start_tv("kids_tv", 30, "parents")
    assert res.ok
    env.set(19, 15)
    env.service.tick()
    assert summary(env, "child8").charged_seconds == 0
    assert summary(env, "child12").charged_seconds == 0


def test_until_stopped_ends_at_next_logical_day_reset(env: Env) -> None:
    env.set(20, 0)
    res = env.service.start_tv("lounge_tv", None, "parents")
    assert res.sessions[0].planned_end_at == at(2, 0, MONDAY + timedelta(days=1))
    env.set(1, 59, MONDAY + timedelta(days=1))
    assert env.service.tick().ended == []
    env.set(2, 0, MONDAY + timedelta(days=1))
    assert len(env.service.tick().ended) == 1


def test_until_stopped_without_reset_has_no_end(tmp_path: Path) -> None:
    env = build_env(tmp_path, parents={"until_stopped_end_at_logical_day_reset": False})
    env.set(20, 0)
    res = env.service.start_tv("lounge_tv", None, "parents")
    assert res.sessions[0].planned_end_at is None
    env.set(20, 0, MONDAY + timedelta(days=3))
    assert env.service.tick().ended == []
    assert desired_active_ips_now(env) == {"192.168.12.41"}


def desired_active_ips_now(env: Env) -> set[str]:
    with env.db.session() as db:
        return desired_active_ips(db, env.clock.now())


def test_parent_tv_rejects_personal_devices_and_bad_durations(env: Env) -> None:
    assert env.service.start_tv("ipad", 30, "parents").reason is Reason.UNKNOWN_DEVICE
    assert env.service.start_tv("kids_tv", 45, "parents").reason is Reason.INVALID_DURATION


def test_children_cannot_stop_other_children_or_parent_sessions(env: Env) -> None:
    env.set(10, 0)
    a = start(env, "child8", "ipad").sessions[0]
    tv = env.service.start_tv("lounge_tv", 30, "parents").sessions[0]
    assert not env.service.stop_session(a.id, actor="child12", role="child", child_id="child12").ok
    assert not env.service.stop_session(tv.id, actor="child8", role="child", child_id="child8").ok
    assert env.service.stop_session(a.id, actor="parents", role="parent").ok
    assert env.service.stop_session(tv.id, actor="parents", role="parent").ok


def test_parent_stopping_child_session_charges_elapsed(env: Env) -> None:
    env.set(10, 0)
    a = start(env, "child8", "ipad").sessions[0]
    env.set(10, 7)
    env.service.stop_session(a.id, actor="parents", role="parent")
    assert summary(env).charged_seconds == 7 * 60


# --- desired device state & failure handling -------------------------------------------


def test_desired_ips_exclude_expired_sessions_even_before_tick(env: Env) -> None:
    env.set(10, 0)
    start(env, "child8", "ipad", 15)
    assert desired_active_ips_now(env) == {"192.168.12.30"}
    env.set(10, 20)
    assert desired_active_ips_now(env) == set()


def test_tv_stays_enabled_while_any_participant_or_parent_grant_remains(env: Env) -> None:
    env.set(10, 0)
    kid = start(env, "child8", "kids_tv", 15).sessions[0]
    env.service.start_tv("kids_tv", 60, "parents")
    env.set(10, 20)
    env.service.tick()
    assert desired_active_ips_now(env) == {"192.168.12.40"}
    env.service.stop_session(
        kid.id, actor="child8", role="child", child_id="child8"
    )  # no-op, ended
    env.set(11, 0)
    env.service.tick()
    assert desired_active_ips_now(env) == set()


def test_enforcement_failed_sessions_are_refunded(env: Env) -> None:
    env.set(10, 0)
    s = start(env, "child8", "ipad", 30).sessions[0]
    env.set(10, 1)
    env.service.mark_enforcement_failed([s.id], "ssh down")
    assert summary(env).charged_seconds == 0
    assert desired_active_ips_now(env) == set()
    with env.db.session() as db:
        assert db.get(SessionRecord, s.id).status == SESSION_ENFORCEMENT_FAILED  # type: ignore[union-attr]


def test_device_enable_override_forces_device_on_until_it_expires(env: Env) -> None:
    env.set(10, 0)
    assert env.service.enable_device("lounge_tv", 10, "admin").ok
    assert desired_active_ips_now(env) == {"192.168.12.41"}
    env.set(10, 11)
    assert desired_active_ips_now(env) == set()


def test_a_session_past_its_planned_end_does_not_block_the_next_start(env: Env) -> None:
    """Between the planned end and the next timer tick the old session is still 'active' in the
    database; it must not make the child wait (or be told they are already using a device)."""
    env.set(10, 0)
    assert start(env, "child8", "ipad", 15).ok
    env.set(10, 15, second=2)  # timer has not ticked yet
    res = start(env, "child8", "kids_tv", 15)
    assert res.ok, res.message
    assert summary(env).charged_seconds == 15 * 60  # the expired session is charged only to its end
    env.service.tick()
    assert summary(env).charged_seconds == 15 * 60  # no double-charging once the timer catches up
