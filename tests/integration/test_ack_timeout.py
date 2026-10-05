"""Start immediately, refund if the firewall never confirms (plan 5.1, D2)."""

from __future__ import annotations

from sqlalchemy import select

from app.models import SESSION_ACTIVE, SESSION_ENFORCEMENT_FAILED, NotificationEvent, SessionRecord
from tests.integration.conftest import IPAD, AppEnv, Session


def start(s: Session, device: str = "ipad", minutes: int = 30):  # type: ignore[no-untyped-def]
    return s.post("/api/child/session/start", {"device_id": device, "minutes": minutes})


def only_session(env: AppEnv) -> SessionRecord:
    with env.ctx.db.session() as db:
        [rec] = db.scalars(select(SessionRecord)).all()
        return rec


def test_an_acknowledged_start_is_confirmed_and_charged_from_start(
    app_env: AppEnv, child8: Session
) -> None:
    assert start(child8).status_code == 200
    rec = only_session(app_env)
    assert rec.enforced_at == rec.start_at  # the dry-run firewall acknowledges at once
    app_env.clock.advance(minutes=10)
    app_env.tick()
    assert only_session(app_env).status == SESSION_ACTIVE
    assert "1h 50m" in child8.get("/child").text  # charged from Start


def test_a_start_the_firewall_never_applies_is_ended_and_refunded(
    app_env: AppEnv, child8: Session, parent: Session
) -> None:
    app_env.firewall.acknowledge = False  # pfSense has stopped applying
    resp = start(child8)
    assert resp.status_code == 200 and resp.json()["ok"]  # started at once (D2)
    page = child8.get("/child").text
    assert "The Internet turns on within a minute" in page
    assert "switching on (within a minute)" in parent.get("/parent").text
    app_env.clock.advance(seconds=149)
    app_env.tick()
    assert only_session(app_env).status == SESSION_ACTIVE  # still inside ack_timeout_seconds
    app_env.clock.advance(seconds=2)
    app_env.tick()
    rec = only_session(app_env)
    assert rec.status == SESSION_ENFORCEMENT_FAILED and rec.charged_seconds == 0
    page = child8.get("/child").text
    assert "The Internet did not turn on. Your time has been given back." in page
    assert "2h" in page  # the full allowance is back
    with app_env.ctx.db.session() as db:
        kinds = {(n.kind, n.audience) for n in db.scalars(select(NotificationEvent))}
    assert {("enforcement_failed", "child"), ("enforcement_failed", "parent")} <= kinds
    app_env.clock.advance(minutes=11)
    assert "did not turn on" not in child8.get("/child").text  # the note fades out


def test_a_late_acknowledgement_still_confirms(app_env: AppEnv, child8: Session) -> None:
    app_env.firewall.acknowledge = False
    start(child8)
    app_env.clock.advance(seconds=60)
    app_env.firewall.acknowledge = True  # the next poll applies it
    app_env.publish()
    app_env.tick()
    app_env.clock.advance(seconds=120)
    app_env.tick()
    rec = only_session(app_env)
    assert rec.status == SESSION_ACTIVE and rec.enforced_at is not None
    assert app_env.firewall.active == {IPAD}


def test_an_acknowledgement_from_before_the_start_does_not_count(
    app_env: AppEnv, child8: Session
) -> None:
    from app.firewall.base import AppliedState

    start(child8)
    rec = only_session(app_env)
    with app_env.ctx.db.session(write=True) as db:
        db.get(SessionRecord, rec.id).enforced_at = None  # type: ignore[union-attr]
    stale = AppliedState(1, "normal", frozenset({"ipad"}), rec.start_at.replace(year=2025))
    app_env.ctx.enforcement.applied_state = stale
    app_env.firewall.acknowledge = False
    app_env.clock.advance(seconds=151)
    app_env.tick()
    assert only_session(app_env).status == SESSION_ENFORCEMENT_FAILED


def test_ack_timeout_is_configurable(env_factory) -> None:  # type: ignore[no-untyped-def]
    env = env_factory(firewall={"mode": "dry_run", "ack_timeout_seconds": 60})
    assert env.ctx.config.firewall.ack_timeout_seconds == 60
