"""End-to-end API flows against the dry-run firewall (spec 24.2 / 24.3)."""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import select

from app.models import (
    SESSION_ENFORCEMENT_FAILED,
    AuditEvent,
    FirewallEvent,
    NotificationEvent,
    SessionRecord,
)
from tests.integration.conftest import (
    IPAD,
    IPHONE,
    KIDS_TV,
    LOUNGE_TV,
    PASSWORDS,
    AppEnv,
    Session,
)


def start(session: Session, device: str, minutes: int = 30, **extra):  # type: ignore[no-untyped-def]
    return session.post(
        "/api/child/session/start", {"device_id": device, "minutes": minutes, **extra}
    )


def sessions(env: AppEnv) -> list[SessionRecord]:
    with env.ctx.db.session() as db:
        return list(db.scalars(select(SessionRecord).order_by(SessionRecord.id)))


# --- acceptance scenarios ----------------------------------------------------------------


def test_child_requests_30_min_with_plenty_left(app_env: AppEnv, child8: Session) -> None:
    resp = start(child8, "ipad", 30)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] and body["sessions"][0]["reserved_minutes"] == 30
    assert app_env.firewall.active == {IPAD}
    assert app_env.firewall.ops() == [("add_active_ip", IPAD)]
    assert "30:00" in child8.get("/child").text or "29:5" in child8.get("/child").text


def test_child_stops_after_ten_minutes(app_env: AppEnv, child8: Session) -> None:
    sid = start(child8, "ipad", 30).json()["sessions"][0]["id"]
    app_env.firewall.clear_calls()
    app_env.clock.advance(minutes=10)
    resp = child8.post(f"/api/child/session/{sid}/stop")
    assert resp.status_code == 200 and resp.json()["ok"]
    assert app_env.firewall.active == set()
    # Revocation removes the address and then kills existing states.
    assert app_env.firewall.ops() == [("remove_active_ip", IPAD), ("kill_states", IPAD)]
    page = child8.get("/child").text
    assert "1h 50m" in page


def test_child_ignores_expiry_and_is_switched_off(app_env: AppEnv, child8: Session) -> None:
    start(child8, "ipad", 15)
    app_env.firewall.clear_calls()
    app_env.clock.advance(minutes=16)
    app_env.tick()
    assert app_env.firewall.active == set()
    assert ("kill_states", IPAD) in app_env.firewall.ops()
    assert sessions(app_env)[0].end_reason == "expired"


def test_second_device_is_rejected_with_already_using_message(
    app_env: AppEnv, child8: Session
) -> None:
    start(child8, "ipad")
    resp = start(child8, "kids_tv")
    assert resp.status_code == 409
    assert (
        resp.json()["reason"] == "ALREADY_ACTIVE"
        and "You are already using iPad" in resp.json()["message"]
    )
    assert app_env.firewall.active == {IPAD}


def test_two_children_share_the_tv_until_the_last_one_leaves(
    app_env: AppEnv, child8: Session, child12: Session
) -> None:
    a = start(child8, "kids_tv", 30).json()["sessions"][0]["id"]
    b = start(child12, "kids_tv", 15).json()["sessions"][0]["id"]
    assert app_env.firewall.active == {KIDS_TV}
    app_env.firewall.clear_calls()
    child12.post(f"/api/child/session/{b}/stop")
    assert app_env.firewall.active == {KIDS_TV}  # child8 is still watching
    assert not [c for c in app_env.firewall.ops() if c[0] in {"remove_active_ip", "kill_states"}]
    child8.post(f"/api/child/session/{a}/stop")
    assert app_env.firewall.active == set()


def test_cutoff_at_1830_ends_child_access(env_factory) -> None:  # type: ignore[no-untyped-def]
    env = env_factory(start_hour=18, start_minute=0)
    from tests.integration.conftest import Session as S

    child = S(env.new_client(), "child8")
    assert start(child, "kids_tv", 60).json()["sessions"][0]["reserved_minutes"] == 30
    env.clock.set(env.clock.now().replace(hour=8, minute=30))  # 18:30 local (UTC+10)
    env.tick()
    assert env.firewall.active == set()
    again = start(child, "kids_tv", 15)
    assert again.status_code == 409 and again.json()["reason"] == "DEVICE_CUTOFF"


def test_parent_grant_at_1830_permits_until_1900(env_factory) -> None:  # type: ignore[no-untyped-def]
    env = env_factory(start_hour=18, start_minute=30)
    from tests.integration.conftest import Session as S

    child, mum = S(env.new_client(), "child8"), S(env.new_client(), "parents")
    assert start(child, "kids_tv", 30).status_code == 409
    assert mum.post("/api/parent/child/child8/grant", {"minutes": 30}).json()["ok"]
    resp = start(child, "kids_tv", 60)
    assert resp.status_code == 200 and resp.json()["sessions"][0]["reserved_minutes"] == 30
    assert env.firewall.active == {KIDS_TV}
    env.clock.advance(minutes=30)
    env.tick()
    assert env.firewall.active == set()


def test_end_today_revokes_access_then_grant_permits_only_the_window(
    app_env: AppEnv, child8: Session, parent: Session
) -> None:
    start(child8, "ipad", 30)
    app_env.firewall.clear_calls()
    resp = parent.post("/api/parent/child/child8/end-today")
    assert resp.status_code == 200
    assert app_env.firewall.active == set()
    assert ("kill_states", IPAD) in app_env.firewall.ops()
    denied = start(child8, "ipad", 15)
    assert denied.status_code == 409 and denied.json()["reason"] == "DAY_LOCKED"
    assert "finished for today" in child8.get("/child").text
    # The other child is unaffected.
    # A grant is an explicit decision: it permits exactly the granted window despite the lock.
    parent.post("/api/parent/child/child8/grant", {"minutes": 15})
    ok = start(child8, "ipad", 15)
    assert ok.status_code == 200
    app_env.clock.advance(minutes=15)
    app_env.tick()
    assert app_env.firewall.active == set()
    assert start(child8, "ipad", 15).json()["reason"] == "DAY_LOCKED"
    parent.post("/api/parent/child/child8/clear-day-lock")
    assert start(child8, "ipad", 15).status_code == 200


def test_education_traffic_does_not_need_a_session(app_env: AppEnv) -> None:
    from app.firewall.resolver import DnsAnswer

    app_env.dns.answers["www.duolingo.com"] = DnsAnswer(
        frozenset({"104.18.1.1", "2606:4700::1"}), ("cdn.example",), 300
    )
    app_env.dns.answers["d35aaqx5ub95lt.cloudfront.net"] = DnsAnswer(
        frozenset({"13.32.1.1"}), (), 60
    )
    app_env.dns.answers["www.khanacademy.org"] = DnsAnswer(frozenset({"151.101.1.1"}), (), 300)
    app_env.call(app_env.ctx.resolver.refresh)
    assert app_env.firewall.education == {"104.18.1.1", "2606:4700::1", "13.32.1.1", "151.101.1.1"}
    assert app_env.firewall.active == set()  # entertainment stays blocked


# --- fail closed ---------------------------------------------------------------------------


def test_firewall_failure_means_no_grant_and_no_charge(app_env: AppEnv, child8: Session) -> None:
    app_env.firewall.fail_ops = {"add_active_ip"}
    resp = start(child8, "ipad", 30)
    assert resp.status_code == 503 and resp.json()["reason"] == "ENFORCEMENT_FAILED"
    assert app_env.firewall.active == set()
    rec = sessions(app_env)[0]
    assert rec.status == SESSION_ENFORCEMENT_FAILED and rec.charged_seconds == 0
    app_env.firewall.fail_ops = set()
    assert "2h" in child8.get("/child").text  # full allowance intact
    with app_env.ctx.db.session() as db:
        assert db.scalars(select(FirewallEvent).where(FirewallEvent.success.is_(False))).first()


def test_new_starts_are_rejected_while_enforcement_is_degraded_then_recover(
    app_env: AppEnv, child8: Session, parent: Session
) -> None:
    app_env.firewall.fail_all = True
    assert start(child8, "ipad").status_code == 503
    assert app_env.ctx.enforcement.degraded
    still = start(child8, "ipad")
    assert still.status_code == 503 and still.json()["reason"] == "ENFORCEMENT_DEGRADED"
    assert "Enforcement degraded" in parent.get("/parent/live").text
    assert (
        "unavailable" in child8.get("/child/live").text
        or "can't start" in child8.get("/child/live").text
    )
    app_env.firewall.fail_all = False
    assert start(child8, "ipad").status_code == 200  # gate retries once and recovers
    assert not app_env.ctx.enforcement.degraded
    with app_env.ctx.db.session() as db:
        kinds = {n.kind for n in db.scalars(select(NotificationEvent))}
        assert {"enforcement_failure", "enforcement_recovered"} <= kinds


def test_revocation_failure_keeps_accounting_and_retries(app_env: AppEnv, child8: Session) -> None:
    sid = start(child8, "ipad", 30).json()["sessions"][0]["id"]
    app_env.clock.advance(minutes=5)
    app_env.firewall.fail_ops = {"remove_active_ip"}
    assert child8.post(f"/api/child/session/{sid}/stop").status_code == 200  # DB is authoritative
    assert sessions(app_env)[0].status == "completed"
    assert app_env.firewall.active == {IPAD}  # pf still open; will be corrected
    app_env.firewall.fail_ops = set()
    app_env.reconcile()
    assert app_env.firewall.active == set()
    assert ("kill_states", IPAD) in app_env.firewall.ops()


# --- reconciliation ------------------------------------------------------------------------


def test_reconcile_heals_a_pf_filter_reload(app_env: AppEnv, child8: Session) -> None:
    start(child8, "ipad")
    app_env.firewall.wipe()
    result = app_env.reconcile()
    assert result.added == {IPAD} and app_env.firewall.active == {IPAD}


def test_reconcile_removes_unknown_entries(app_env: AppEnv) -> None:
    app_env.firewall.active = {"192.168.12.99"}
    app_env.reconcile()
    assert app_env.firewall.active == set()
    assert ("kill_states", "192.168.12.99") in app_env.firewall.ops()


def test_reconcile_is_idempotent(app_env: AppEnv, child8: Session) -> None:
    start(child8, "ipad")
    app_env.firewall.clear_calls()
    app_env.reconcile()
    app_env.reconcile()
    assert app_env.firewall.ops() == []


def test_startup_reconciliation_expires_stale_sessions_and_derives_active_set(
    env_factory,
    tmp_path: Path,
    user_hashes: dict[str, str],  # type: ignore[no-untyped-def]
) -> None:
    first = env_factory()
    from tests.integration.conftest import Session as S

    a, b = S(first.new_client(), "child8"), S(first.new_client(), "child12")
    start(a, "ipad", 15)  # will be stale after the outage
    start(b, "iphone_child12", 60)  # still running after the outage
    db_path = first.ctx.config.storage.db_file
    assert db_path.exists()
    first.client.close()

    # "Pi restart": a fresh process 30 minutes later with an empty pf table.
    from fastapi.testclient import TestClient

    from app.clock import FakeClock
    from app.config import UserCfg
    from app.context import build_context
    from app.firewall.dry_run import DryRunFirewallAdapter
    from app.main import create_app
    from tests.conftest import make_config

    config = make_config(tmp_path)
    users = {
        "child8": UserCfg(role="child", child_id="child8", password_hash=user_hashes["child8"]),
        "child12": UserCfg(role="child", child_id="child12", password_hash=user_hashes["child12"]),
        "parents": UserCfg(role="parent", password_hash=user_hashes["parents"]),
    }
    later = FakeClock(first.clock.now())
    later.advance(minutes=30)
    fw = DryRunFirewallAdapter()
    fw.active = {IPAD, "192.168.12.77"}  # leftovers from before the restart
    ctx = build_context(config, users, adapter=fw, clock=later)  # type: ignore[arg-type]
    with TestClient(create_app(ctx, run_background=False), client=("127.0.0.1", 1)):
        assert fw.active == {IPHONE}
        with ctx.db.session() as db:
            recs = {s.device_id: s for s in db.scalars(select(SessionRecord))}
        assert recs["ipad"].status == "completed" and recs["ipad"].end_reason == "expired"
        assert recs["ipad"].charged_seconds == 15 * 60
        assert recs["iphone_child12"].status == "active"
        assert ("kill_states", IPAD) in fw.ops()


# --- participants & extensions -------------------------------------------------------------


def test_sibling_can_be_added_only_with_their_password(app_env: AppEnv, child8: Session) -> None:
    sid = start(child8, "kids_tv", 30).json()["sessions"][0]["id"]
    bad = child8.post(
        f"/api/child/shared/{sid}/add-participant", {"child_id": "child12", "password": "wrong-pw"}
    )
    assert bad.status_code == 403 and bad.json()["reason"] == "SIBLING_AUTH_FAILED"
    good = child8.post(
        f"/api/child/shared/{sid}/add-participant",
        {"child_id": "child12", "password": PASSWORDS["child12"]},
    )
    assert good.status_code == 200 and good.json()["sessions"][0]["child_id"] == "child12"
    assert {s.child_id for s in sessions(app_env)} == {"child8", "child12"}


def test_start_with_sibling_requires_password_and_charges_both(
    app_env: AppEnv, child8: Session
) -> None:
    denied = start(
        child8, "kids_tv", 30, participants=[{"child_id": "child12", "password": "nope-nope"}]
    )
    assert denied.status_code == 403 and sessions(app_env) == []
    ok = start(
        child8,
        "kids_tv",
        30,
        participants=[{"child_id": "child12", "password": PASSWORDS["child12"]}],
    )
    assert ok.status_code == 200 and len(ok.json()["sessions"]) == 2


def test_wrong_sibling_passwords_count_toward_the_siblings_lockout(
    app_env: AppEnv, child8: Session
) -> None:
    for _ in range(5):
        start(
            child8, "kids_tv", 30, participants=[{"child_id": "child12", "password": "nope-nope"}]
        )
    good = start(
        child8,
        "kids_tv",
        30,
        participants=[{"child_id": "child12", "password": PASSWORDS["child12"]}],
    )
    assert good.status_code == 403  # locked, even with the right password


def test_extension_flow_over_http(app_env: AppEnv, child8: Session) -> None:
    sid = start(child8, "ipad", 30).json()["sessions"][0]["id"]
    early = child8.post(f"/api/child/session/{sid}/extend")
    assert early.status_code == 409 and early.json()["reason"] == "EXTENSION_NOT_YET"
    app_env.clock.advance(minutes=25)
    app_env.tick()
    with app_env.ctx.db.session() as db:
        assert db.scalars(
            select(NotificationEvent).where(NotificationEvent.kind == "session_warning")
        ).one()
    assert "+15 minutes" in child8.get("/child").text
    ok = child8.post(f"/api/child/session/{sid}/extend")
    assert ok.status_code == 200 and ok.json()["sessions"][0]["reserved_minutes"] == 45


def test_children_cannot_touch_each_others_sessions(
    app_env: AppEnv, child8: Session, child12: Session
) -> None:
    sid = start(child8, "ipad").json()["sessions"][0]["id"]
    assert child12.post(f"/api/child/session/{sid}/stop").status_code == 404
    assert child12.post(f"/api/child/session/{sid}/extend").status_code == 404
    assert app_env.firewall.active == {IPAD}


def test_personal_device_of_a_sibling_is_refused(app_env: AppEnv, child12: Session) -> None:
    resp = start(child12, "ipad")
    assert resp.status_code == 409 and resp.json()["reason"] == "NOT_OWNER"


# --- parent TV -----------------------------------------------------------------------------


def test_parent_tv_grants_do_not_charge_and_keep_tv_on_for_children(
    app_env: AppEnv, parent: Session, child8: Session
) -> None:
    resp = parent.post("/api/parent/tv/lounge_tv/start", {"minutes": 60})
    assert resp.status_code == 200 and app_env.firewall.active == {LOUNGE_TV}
    kid = start(child8, "lounge_tv", 15).json()["sessions"][0]["id"]
    app_env.clock.advance(minutes=5)
    child8.post(f"/api/child/session/{kid}/stop")
    assert app_env.firewall.active == {LOUNGE_TV}  # the parent is still watching
    assert "1h 55m" in child8.get("/child").text
    app_env.clock.advance(minutes=56)
    app_env.tick()
    assert app_env.firewall.active == set()


def test_until_stopped_and_manual_stop(app_env: AppEnv, parent: Session) -> None:
    resp = parent.post("/api/parent/tv/kids_tv/start", {"until_stopped": True})
    assert resp.status_code == 200 and resp.json()["sessions"][0]["until_stopped"]
    sid = resp.json()["sessions"][0]["id"]
    assert parent.post(f"/api/parent/session/{sid}/stop").status_code == 200
    assert app_env.firewall.active == set()


def test_parent_tv_start_validates_input(parent: Session) -> None:
    assert parent.post("/api/parent/tv/ipad/start", {"minutes": 30}).status_code == 404
    assert parent.post("/api/parent/tv/kids_tv/start", {"minutes": 45}).status_code == 422
    assert parent.post("/api/parent/tv/kids_tv/start", {}).status_code == 422
    assert (
        parent.post(
            "/api/parent/tv/kids_tv/start", {"minutes": 30, "until_stopped": True}
        ).status_code
        == 422
    )
    assert parent.post("/api/parent/tv/KIDS;rm/start", {"minutes": 30}).status_code == 404


def test_tv_start_failure_is_reported_and_refunded(app_env: AppEnv, parent: Session) -> None:
    app_env.firewall.fail_ops = {"add_active_ip"}
    resp = parent.post("/api/parent/tv/kids_tv/start", {"minutes": 30})
    assert resp.status_code == 503
    assert sessions(app_env)[0].status == SESSION_ENFORCEMENT_FAILED


# --- validation, idempotency, rate limits, audit -------------------------------------------


def test_input_validation_rejects_bad_ids_and_durations(child8: Session, parent: Session) -> None:
    assert start(child8, "ipad; reboot").status_code == 422
    assert start(child8, "ipad", -5).status_code == 422
    assert start(child8, "ipad", 45).status_code == 422
    assert (
        child8.post(
            "/api/child/session/start", {"device_id": "ipad", "minutes": 30, "extra": 1}
        ).status_code
        == 422
    )
    assert parent.post("/api/parent/child/nobody/grant", {"minutes": 15}).status_code == 404
    assert parent.post("/api/parent/child/child8/grant", {"minutes": 45}).status_code == 422


def test_grant_is_idempotent_per_request_id(
    app_env: AppEnv, parent: Session, child8: Session
) -> None:
    body = {"minutes": 15, "request_id": "req-abcdef-1"}
    assert parent.post("/api/parent/child/child8/grant", body).json()["duplicate"] is False
    assert parent.post("/api/parent/child/child8/grant", body).json()["duplicate"] is True
    assert "2h 15m" in child8.get("/child").text


def test_double_click_start_is_deduplicated(app_env: AppEnv, child8: Session) -> None:
    payload = {"request_id": "req-start-0001"}
    a, b = start(child8, "ipad", **payload), start(child8, "ipad", **payload)
    assert a.status_code == b.status_code == 200 and b.json()["duplicate"] is True
    assert len(sessions(app_env)) == 1


def test_parent_actions_are_rate_limited(env_factory) -> None:  # type: ignore[no-untyped-def]
    env = env_factory(
        security={
            "grant_actions_per_minute": 3,
            "enforce_file_modes": False,
            "secure_cookies": False,
        }
    )
    from tests.integration.conftest import Session as S

    mum = S(env.new_client(), "parents")
    codes = [mum.post("/api/parent/child/child8/clear-day-lock").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_every_lifecycle_step_is_audited_with_actor_and_result(
    app_env: AppEnv, child8: Session, parent: Session
) -> None:
    sid = start(child8, "ipad", 30).json()["sessions"][0]["id"]
    parent.post("/api/parent/child/child8/grant", {"minutes": 15})
    parent.post("/api/parent/child/child8/end-today")
    start(child8, "ipad", 15)  # rejected
    with app_env.ctx.db.session() as db:
        events = db.scalars(select(AuditEvent)).all()
    seen = {(e.actor, e.event_type, e.result) for e in events}
    assert ("child8", "session_start", "ok") in seen
    assert ("parents", "parent_grant", "ok") in seen
    assert ("parents", "end_today", "ok") in seen
    assert ("child8", "session_rejected", "denied") in seen
    assert ("parents", "session_end", "ok") in seen
    assert ("child8", "login", "ok") in seen
    assert sid


def test_audit_and_logs_never_contain_passwords(app_env: AppEnv, child8: Session) -> None:
    start(child8, "kids_tv", participants=[{"child_id": "child12", "password": "wrong-secret-pw"}])
    with app_env.ctx.db.session() as db:
        blob = " ".join(e.details_json + e.subject for e in db.scalars(select(AuditEvent)))
    assert "wrong-secret-pw" not in blob and PASSWORDS["child12"] not in blob


def test_live_fragment_returns_204_when_nothing_changed(child8: Session) -> None:
    key = __import__("re").search(r"live\?k=([0-9a-f]+)", child8.get("/child").text)
    assert key
    assert child8.get(f"/child/live?k={key.group(1)}").status_code == 204
    assert child8.get("/child/live?k=stale").status_code == 200
    assert child8.get("/child/live").status_code == 200


def test_diagnostics_page_shows_required_fields(
    app_env: AppEnv, parent: Session, child8: Session
) -> None:
    start(child8, "ipad")
    page = parent.get("/parent/diagnostics").text
    for needle in (
        "App version",
        "1.0.0",
        "Logical day",
        "2026-09-21",
        "Database",
        "Last pfSense contact",
        "Desired",
        IPAD,
        "Actual",
        "Last refresh",
        "Unresolved hostnames",
        "www.duolingo.com",
        "Runtime libraries",
        "argon2-cffi",
    ):
        assert needle in page, needle


def test_dashboards_poll_fast_only_near_the_end_of_a_session(
    app_env: AppEnv, child8: Session, parent: Session
) -> None:
    def interval(page: str) -> str:
        match = re.search(r'hx-trigger="every (\d+)s"', page)
        assert match, page
        return match.group(1)

    def key(page: str) -> str:
        match = re.search(r"live\?k=([0-9a-f]+)", page)
        assert match
        return match.group(1)

    assert interval(child8.get("/child").text) == "15"
    assert interval(parent.get("/parent").text) == "15"
    assert start(child8, "ipad", 30).json()["ok"]  # 10:00 to 10:30
    app_env.set(10, 23)  # 7 minutes left: outside warning (5) + 1 minutes
    page = child8.get("/child").text
    assert interval(page) == "15" and interval(parent.get("/parent").text) == "15"
    app_env.set(10, 24, second=30)
    # The interval changed, so the live fragment is re-sent (not a 204) and htmx re-arms.
    assert child8.get(f"/child/live?k={key(page)}").status_code == 200
    assert interval(child8.get("/child").text) == "5"
    assert interval(parent.get("/parent").text) == "5"


def test_poll_intervals_are_configurable(env_factory) -> None:  # type: ignore[no-untyped-def]
    env = env_factory(ui={"poll_fast_seconds": 3, "poll_idle_seconds": 30})
    child = Session(env.new_client(), "child8")
    assert 'hx-trigger="every 30s"' in child.get("/child").text
