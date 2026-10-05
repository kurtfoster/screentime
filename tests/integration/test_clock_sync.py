"""No RTC on the Pi: until the clock is synchronised, children cannot start and nothing is
published (plan 5.5). The firewall keeps the leases it has and times them itself."""

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


def test_unsynchronised_clock_pauses_publication_then_recovers(
    env_factory: Callable[..., AppEnv],
) -> None:
    sync = ManualSync(True)
    env = env_factory(clock_sync=sync)
    child8, child12 = Session(env.new_client(), "child8"), Session(env.new_client(), "child12")
    parent = Session(env.new_client(), "parents")
    assert start(child8, "ipad").json()["ok"]  # type: ignore[attr-defined]
    assert env.firewall.active == {IPAD}

    sync.synced = False  # e.g. the Pi rebooted after a power cut and NTP is not reachable
    env.firewall.clear_calls()
    assert env.publish().paused
    assert env.firewall.calls == []  # nothing is published: the firewall keeps its leases
    refused = start(child12, "iphone_child12")
    assert refused.status_code == 503  # type: ignore[attr-defined]
    assert refused.json()["reason"] == "CLOCK_NOT_SYNCED"  # type: ignore[attr-defined]
    assert env.firewall.active == {IPAD}
    assert "paused: the clock is not synchronised" in parent.get("/parent/diagnostics").text
    with env.ctx.db.session() as db:
        reasons = [e.details_json for e in db.scalars(select(AuditEvent)) if e.result == "denied"]
    assert any("CLOCK_NOT_SYNCED" in r for r in reasons)
    ready = env.new_client().get("/health/ready")
    assert ready.status_code == 503 and ready.json()["clock"] == "not synchronised"
    assert "clock is not synchronised yet" in parent.get("/parent").text

    sync.synced = True
    assert not env.publish().paused
    assert env.firewall.active == {IPAD}  # the running session carries on
    assert start(child12, "iphone_child12").json()["ok"]  # type: ignore[attr-defined]
    assert env.firewall.active == {IPAD, IPHONE}
    ready = env.new_client().get("/health/ready")
    assert ready.status_code == 200 and ready.json()["clock"] == "synchronised"
    assert "clock is not synchronised yet" not in parent.get("/parent").text


def test_startup_with_an_unsynchronised_clock_publishes_nothing(
    env_factory: Callable[..., AppEnv],
) -> None:
    env = env_factory(clock_sync=ManualSync(False))
    env.firewall.clear_calls()
    env.publish()
    assert env.firewall.calls == [] and env.ctx.enforcement.publishing_paused


def test_timesyncd_marker_is_latched(tmp_path: Path) -> None:
    marker = tmp_path / "synchronized"
    check = TimesyncdMarker(marker)
    assert not check.synchronised()
    marker.touch()
    assert check.synchronised()
    marker.unlink()
    assert check.synchronised()  # timesyncd never withdraws it within a boot; neither do we
