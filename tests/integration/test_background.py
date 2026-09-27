"""Enforcement edge cases, push notifications, the scheduler and database resilience."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select, text

from app.db import Database, UTCDateTime, current_revision, upgrade_to_head
from app.firewall.dry_run import DryRunFirewallAdapter
from app.models import NotificationEvent, PushSubscription
from app.push import PushError, PushGone
from app.secrets_store import derive_key, load_or_create_secret
from app.timers import Scheduler
from tests.integration.conftest import IPAD, AppEnv, Session

SUB = {
    "endpoint": "https://fcm.googleapis.com/fcm/send/abc",
    "keys": {"p256dh": "BPubKey1234567890", "auth": "AuthSecret12345"},
}


def subscribe(session: Session, **override) -> None:  # type: ignore[no-untyped-def]
    body = {**SUB, **override}
    resp = session.post("/api/push/subscribe", body)
    assert resp.status_code == 200, resp.text


# --- enforcement ---------------------------------------------------------------------------


def test_failed_state_kill_is_retried_until_it_succeeds(app_env: AppEnv, child8: Session) -> None:
    sid = child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 30}).json()[
        "sessions"
    ][0]["id"]
    app_env.firewall.fail_ops = {"kill_states"}
    child8.post(f"/api/child/session/{sid}/stop")
    assert app_env.firewall.active == set()  # address removed...
    assert app_env.ctx.enforcement.degraded  # ...but the kill failed, so we are degraded
    app_env.firewall.fail_ops = set()
    app_env.firewall.clear_calls()
    app_env.reconcile()
    assert ("kill_states", IPAD) in app_env.firewall.ops()  # ...and retried on the next pass
    assert not app_env.ctx.enforcement.degraded
    app_env.firewall.clear_calls()
    app_env.reconcile()
    assert ("kill_states", IPAD) not in app_env.firewall.ops()  # only once


def test_revocations_run_before_grants(app_env: AppEnv, child8: Session) -> None:
    app_env.firewall.active = {"192.168.12.99"}
    child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 15})
    ops = [c[0] for c in app_env.firewall.ops()]
    assert ops.index("remove_active_ip") < ops.index("add_active_ip")


def test_parents_are_told_once_per_outage(app_env: AppEnv) -> None:
    app_env.firewall.fail_all = True
    for _ in range(3):
        with pytest.raises(Exception):  # noqa: B017
            app_env.reconcile()
    with app_env.ctx.db.session() as db:
        events = db.scalars(
            select(NotificationEvent).where(NotificationEvent.kind == "enforcement_failure")
        ).all()
        assert len(events) == 1 and events[0].audience == "parent"
    status = app_env.ctx.enforcement
    assert status.degraded and status.last_error and status.degraded_since is not None
    app_env.firewall.fail_all = False
    app_env.reconcile()
    assert not status.degraded and status.last_success_at is not None


def test_desired_and_actual_sets_are_exposed_for_diagnostics(
    app_env: AppEnv, child8: Session
) -> None:
    child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 15})
    assert app_env.ctx.enforcement.desired == {IPAD} and app_env.ctx.enforcement.actual == {IPAD}


# --- notifications -------------------------------------------------------------------------


def test_subscription_keys_are_encrypted_at_rest(app_env: AppEnv, child8: Session) -> None:
    subscribe(child8)
    with app_env.ctx.db.session() as db:
        row = db.scalars(select(PushSubscription)).one()
        assert row.username == "child8" and row.role == "child"
        assert (
            SUB["keys"]["auth"] not in row.keys_encrypted
            and SUB["keys"]["p256dh"] not in row.keys_encrypted
        )
        raw = db.execute(text("SELECT keys_encrypted FROM push_subscriptions")).scalar_one()
        assert "AuthSecret" not in raw


def test_subscription_validation(child8: Session) -> None:
    assert (
        child8.post(
            "/api/push/subscribe", {**SUB, "endpoint": "http://insecure.example/x"}
        ).status_code
        == 422
    )
    assert (
        child8.post(
            "/api/push/subscribe", {**SUB, "keys": {"p256dh": "x y", "auth": "!"}}
        ).status_code
        == 422
    )
    assert child8.post("/api/push/subscribe", {**SUB, "keys": {}}).status_code == 422
    for lan in ("https://192.168.12.1/", "https://pfsense.home.arpa/x", "https://x.example/1"):
        res = child8.post("/api/push/subscribe", {**SUB, "endpoint": lan})
        assert res.status_code == 422 and res.json()["reason"] == "INVALID_SUBSCRIPTION", lan
    assert (
        child8.post("/api/push/subscribe", {"endpoint": "https://x.example/1"}).status_code == 422
    )


def test_subscribing_twice_updates_rather_than_duplicates(app_env: AppEnv, child8: Session) -> None:
    subscribe(child8)
    subscribe(child8)
    with app_env.ctx.db.session() as db:
        assert len(db.scalars(select(PushSubscription)).all()) == 1
    assert child8.post("/api/push/unsubscribe", {"endpoint": SUB["endpoint"]}).json()["ok"]
    with app_env.ctx.db.session() as db:
        assert db.scalars(select(PushSubscription)).all() == []


def test_warning_push_goes_only_to_that_child_and_only_once(
    app_env: AppEnv, child8: Session, child12: Session, parent: Session
) -> None:
    subscribe(child8)
    subscribe(child12, endpoint="https://web.push.apple.com/other")
    subscribe(parent, endpoint="https://web.push.apple.com/parent")
    child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 30})
    app_env.clock.advance(minutes=25)
    app_env.tick()
    app_env.tick()
    sent = app_env.push.sent
    assert [(s[0]["endpoint"], s[1]["kind"]) for s in sent] == [
        (SUB["endpoint"], "session_warning")
    ]
    assert sent[0][1]["title"] == "5 minutes left" and sent[0][1]["url"] == "/child"
    assert sent[0][0]["keys"]["auth"] == SUB["keys"]["auth"]  # decrypted for delivery


def test_session_end_notifies_the_child_and_the_parents(
    app_env: AppEnv, child8: Session, parent: Session
) -> None:
    subscribe(child8)
    subscribe(parent, endpoint="https://web.push.apple.com/parent")
    child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 15})
    app_env.clock.advance(minutes=16)
    app_env.tick()
    ended = {s[0]["endpoint"]: s[1] for s in app_env.push.sent if s[1]["kind"] == "session_ended"}
    assert set(ended) == {SUB["endpoint"], "https://web.push.apple.com/parent"}
    assert ended["https://web.push.apple.com/parent"]["url"] == "/parent"


def test_enforcement_failure_alerts_parents(app_env: AppEnv, parent: Session) -> None:
    subscribe(parent)
    app_env.firewall.fail_all = True
    with pytest.raises(Exception):  # noqa: B017
        app_env.reconcile()
    app_env.firewall.fail_all = False
    assert app_env.reconcile() is not None
    app_env.tick()
    assert [s[1]["kind"] for s in app_env.push.sent] == [
        "enforcement_failure",
        "enforcement_recovered",
    ]
    assert all(s[1]["url"] == "/parent" for s in app_env.push.sent)


def test_gone_subscriptions_are_removed_and_flaky_ones_kept(
    app_env: AppEnv, child8: Session
) -> None:
    subscribe(child8)
    app_env.push.raise_with = PushError("boom")
    child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 15})
    app_env.clock.advance(minutes=16)
    app_env.tick()
    with app_env.ctx.db.session() as db:
        assert db.scalars(select(PushSubscription)).one().failure_count >= 1
    app_env.push.raise_with = PushGone("410")
    child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 15})
    app_env.clock.advance(minutes=16)
    app_env.tick()
    with app_env.ctx.db.session() as db:
        assert db.scalars(select(PushSubscription)).all() == []


def test_push_failure_never_affects_enforcement(app_env: AppEnv, child8: Session) -> None:
    subscribe(child8)
    app_env.push.raise_with = RuntimeError("push service exploded")
    child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 15})
    app_env.clock.advance(minutes=16)
    app_env.tick()
    assert app_env.firewall.active == set()  # the session still ended on time


def test_events_are_marked_dispatched_even_without_subscribers(
    app_env: AppEnv, child8: Session
) -> None:
    child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 15})
    app_env.clock.advance(minutes=16)
    app_env.tick()
    with app_env.ctx.db.session() as db:
        assert all(n.dispatched_at is not None for n in db.scalars(select(NotificationEvent)))


def test_push_can_be_disabled(env_factory, user_hashes) -> None:  # type: ignore[no-untyped-def]
    env = env_factory(notifications={"browser_push_enabled": False, "warning_minutes": 5})
    from tests.integration.conftest import Session as S

    child = S(env.new_client(), "child8")
    assert child.post("/api/push/subscribe", SUB).status_code == 409
    assert child.get("/api/push/public-key").json()["enabled"] is False


# --- scheduler -----------------------------------------------------------------------------


def test_scheduler_runs_ticks_and_survives_failures(app_env: AppEnv) -> None:
    calls = {"tick": 0, "reconcile": 0, "refresh": 0, "housekeeping": 0}

    class Enforcement:
        async def reconcile(self) -> None:
            calls["reconcile"] += 1
            raise RuntimeError("pfSense unreachable")

    class Orch:
        enforcement = Enforcement()

        async def tick(self) -> None:
            calls["tick"] += 1
            if calls["tick"] == 1:
                raise RuntimeError("first iteration blows up")

    class Resolver:
        async def refresh(self) -> None:
            calls["refresh"] += 1

        def next_interval_seconds(self) -> float:
            return 0.01

    def maintenance() -> None:
        calls["housekeeping"] += 1

    async def scenario() -> None:
        sched = Scheduler(
            Orch(),  # type: ignore[arg-type]
            Resolver(),  # type: ignore[arg-type]
            app_env.ctx.config,
            maintenance,
            tick_seconds=0.01,
            reconcile_seconds=0.01,
        )
        sched.start()
        sched.start()  # idempotent
        await asyncio.sleep(0.2)
        await sched.stop()
        stopped = dict(calls)
        await asyncio.sleep(0.05)
        assert calls == stopped  # nothing runs after stop()

    asyncio.run(scenario())
    assert calls["tick"] >= 3 and calls["reconcile"] >= 3 and calls["refresh"] >= 3
    assert calls["housekeeping"] == 1


def test_background_scheduler_drives_the_real_app(env_factory) -> None:  # type: ignore[no-untyped-def]
    """With the scheduler on, a session ends on its own without anyone calling tick()."""
    import time

    from fastapi.testclient import TestClient

    from app.clock import FakeClock
    from app.config import UserCfg
    from app.context import build_context
    from app.main import create_app
    from app.timers import Scheduler as Sched
    from tests.conftest import at, make_config

    env = env_factory()
    assert env  # keeps the shared fixtures exercised
    config = make_config(env.tmp_path / "bg")
    users = {
        "child8": UserCfg(
            role="child", child_id="child8", password_hash=env.ctx.users["child8"].password_hash
        ),
        "child12": UserCfg(
            role="child", child_id="child12", password_hash=env.ctx.users["child12"].password_hash
        ),
        "parents": UserCfg(role="parent", password_hash=env.ctx.users["parents"].password_hash),
    }
    clock = FakeClock(at(10))
    fw = DryRunFirewallAdapter()
    ctx = build_context(config, users, adapter=fw, clock=clock, dns=env.dns, push_sender=env.push)  # type: ignore[arg-type]
    ctx.scheduler = Sched(
        ctx.orchestrator,
        ctx.resolver,
        config,
        ctx.maintenance,
        tick_seconds=0.05,
        reconcile_seconds=0.05,
    )
    with TestClient(create_app(ctx, run_background=True), client=("127.0.0.1", 1)) as client:
        res = client.portal.call(  # type: ignore[union-attr]
            lambda: ctx.orchestrator.start_child_session("child8", "ipad", 15)
        )
        assert res.ok and fw.active == {IPAD}
        clock.advance(minutes=16)
        deadline = time.monotonic() + 5
        while fw.active and time.monotonic() < deadline:
            time.sleep(0.05)
        assert fw.active == set()


# --- database & secrets --------------------------------------------------------------------


def test_utc_datetime_rejects_naive_and_returns_aware() -> None:
    col = UTCDateTime()
    with pytest.raises(ValueError, match="naive"):
        col.process_bind_param(datetime(2026, 1, 1), None)
    stored = col.process_bind_param(datetime(2026, 1, 1, 12, tzinfo=UTC), None)
    assert stored is not None and stored.tzinfo is None
    assert col.process_result_value(stored, None) == datetime(2026, 1, 1, 12, tzinfo=UTC)
    assert (
        col.process_bind_param(None, None) is None and col.process_result_value(None, None) is None
    )


def test_database_runs_in_wal_mode_with_foreign_keys(app_env: AppEnv) -> None:
    with app_env.ctx.db.session() as db:
        assert db.execute(text("PRAGMA journal_mode")).scalar_one() == "wal"
        assert db.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
    assert app_env.ctx.db.check()


def test_migrations_tolerate_a_restored_database_from_a_previous_release(tmp_path: Path) -> None:
    db = Database(tmp_path / "old.db")
    db.upgrade()
    with db.session(write=True) as s:
        s.execute(
            text(
                "INSERT INTO audit_events (timestamp, actor, event_type, subject, result, details_json) "
                "VALUES ('2026-01-01 00:00:00', 'parents', 'grant', 'child8', 'ok', '{}')"
            )
        )
    db.dispose()
    # A restore brings back the file as it was; startup must upgrade in place and keep the data.
    restored = Database(tmp_path / "old.db")
    upgrade_to_head(restored.url)
    upgrade_to_head(restored.url)  # idempotent
    assert current_revision(restored) == "0001"
    with restored.session() as s:
        assert s.execute(text("SELECT count(*) FROM audit_events")).scalar_one() == 1


def test_current_revision_of_an_uninitialised_database_is_none(tmp_path: Path) -> None:
    assert current_revision(Database(tmp_path / "blank.db")) is None


def test_secret_is_created_once_with_private_permissions(tmp_path: Path) -> None:
    path = tmp_path / "s" / "secret.key"
    first = load_or_create_secret(path)
    assert len(first) == 32 and load_or_create_secret(path) == first
    assert path.stat().st_mode & 0o077 == 0
    assert derive_key(first, "a") != derive_key(first, "b")


def test_vapid_keys_are_generated_once_and_private(tmp_path: Path) -> None:
    from app.push import VapidKeys

    path = tmp_path / "k" / "vapid.pem"
    keys = VapidKeys(path)
    again = VapidKeys(path)
    assert keys.public_key == again.public_key and len(keys.public_key) == 87  # 65 bytes, base64url
    assert path.stat().st_mode & 0o077 == 0
    assert json.dumps(keys.public_key)
