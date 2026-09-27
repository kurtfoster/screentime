"""No RTC on the Pi: nothing is granted and children cannot start until the clock is synchronised."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from sqlalchemy import select

from app.clock import TimesyncdMarker
from app.models import AuditEvent
from tests.integration.conftest import IPAD, IPHONE, AppEnv, Session


class ManualSync:
    def __init__(self, synced: bool) -> None:
        self.synced = synced

    def synchronised(self) -> bool:
        return self.synced


def start(session: Session, device: str) -> object:
    return session.post("/api/child/session/start", {"device_id": device, "minutes": 30})


def test_unsynchronised_clock_fails_closed_then_recovers(
    env_factory: Callable[..., AppEnv],
) -> None:
    sync = ManualSync(True)
    env = env_factory(clock_sync=sync)
    child8, child12 = Session(env.new_client(), "child8"), Session(env.new_client(), "child12")
    parent = Session(env.new_client(), "parents")
    assert start(child8, "ipad").json()["ok"]  # type: ignore[attr-defined]
    assert env.firewall.active == {IPAD}

    sync.synced = False  # e.g. the Pi rebooted after a power cut and NTP is not reachable
    env.reconcile()
    assert env.firewall.active == set()  # every grant withdrawn, including running sessions
    refused = start(child12, "iphone_child12")
    assert refused.status_code == 503  # type: ignore[attr-defined]
    assert refused.json()["reason"] == "CLOCK_NOT_SYNCED"  # type: ignore[attr-defined]
    assert env.firewall.active == set()
    with env.ctx.db.session() as db:
        reasons = [e.details_json for e in db.scalars(select(AuditEvent)) if e.result == "denied"]
    assert any("CLOCK_NOT_SYNCED" in r for r in reasons)
    ready = env.new_client().get("/health/ready")
    assert ready.status_code == 503 and ready.json()["clock"] == "not synchronised"
    assert "clock is not synchronised yet" in parent.get("/parent").text

    sync.synced = True
    env.reconcile()
    assert env.firewall.active == {IPAD}  # the session that was still running is restored
    assert start(child12, "iphone_child12").json()["ok"]  # type: ignore[attr-defined]
    assert env.firewall.active == {IPAD, IPHONE}
    ready = env.new_client().get("/health/ready")
    assert ready.status_code == 200 and ready.json()["clock"] == "synchronised"
    assert "clock is not synchronised yet" not in parent.get("/parent").text


def test_startup_with_an_unsynchronised_clock_grants_nothing(
    env_factory: Callable[..., AppEnv],
) -> None:
    env = env_factory(clock_sync=ManualSync(False))
    env.firewall.active.add(IPAD)  # left in pf by the previous run
    env.reconcile()
    assert env.firewall.active == set()


def test_timesyncd_marker_is_latched(tmp_path: Path) -> None:
    marker = tmp_path / "synchronized"
    check = TimesyncdMarker(marker)
    assert not check.synchronised()
    marker.touch()
    assert check.synchronised()
    marker.unlink()
    assert check.synchronised()  # timesyncd never withdraws it within a boot; neither do we
