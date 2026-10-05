"""Parent alerts for pfSense not checking in and failing open (plan 6.5, D13; Gate A)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.admin import main
from app.firewall.alerts import HEARTBEAT_KEY
from app.models import AuditEvent, FailopenEpisode, Meta, NotificationEvent
from tests.integration.conftest import AppEnv, Session
from tests.integration.test_firewall_routes import acknowledge, fetch, rotate

KNOWN = (
    "known iphone_child12 192.168.12.31 personal\n"
    "known ipad 192.168.12.30 personal\n"
    "known kids_tv 192.168.12.40 tv\n"
    "known lounge_tv 192.168.12.41 tv\n"
)


def ack(generation: int = 1, extra: str = "", known: str = KNOWN, mode: str = "normal") -> str:
    return f"screentime-applied v1\ngeneration {generation}\nmode {mode}\n{extra}{known}end\n"


@pytest.fixture
def pull_env(env_factory: Callable[..., AppEnv]) -> AppEnv:
    return env_factory(firewall={"mode": "pfsense_pull"})


@pytest.fixture
def token(pull_env: AppEnv) -> str:
    return rotate(pull_env)


def events(env: AppEnv, kind: str) -> list[AuditEvent]:
    with env.ctx.db.session() as db:
        return list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == kind)))


def notifications(env: AppEnv) -> list[str]:
    with env.ctx.db.session() as db:
        return [
            n.kind for n in db.scalars(select(NotificationEvent).order_by(NotificationEvent.id))
        ]


def alerts_tick(env: AppEnv) -> None:
    env.ctx.firewall_alerts_tick()


def test_live_states_at_three_and_ten_minutes_for_parents_only(
    pull_env: AppEnv, token: str
) -> None:
    parent, child = (
        Session(pull_env.new_client(), "parents"),
        Session(pull_env.new_client(), "child8"),
    )
    assert fetch(pull_env, token).status_code == 200  # 10:00
    alerts_tick(pull_env)
    assert "fw-banner" not in parent.get("/parent").text  # no alert while pfSense fetches

    pull_env.clock.advance(seconds=179)
    assert "not checked in" not in parent.get("/parent").text
    pull_env.clock.advance(seconds=1)
    page = parent.get("/parent").text
    assert (
        "pfSense has not checked in for 3 min. If this reaches 10 min, every device is allowed and the curfew is off."
        in page
    )
    alerts_tick(pull_env)

    pull_env.clock.advance(seconds=420)  # 10:10
    page = parent.get("/parent").text
    assert "Since 10:10 every device is probably allowed and the curfew is off." in page
    assert "pfSense cannot reach the screen-time controller." in page
    alerts_tick(pull_env)
    for text in (child.get("/child").text, child.get("/child/live").text):
        assert "pfSense" not in text and "every device" not in text  # never shown to children

    assert fetch(pull_env, token).status_code == 200  # pfSense is back
    alerts_tick(pull_env)
    assert "every device is probably" not in parent.get("/parent").text
    live = ("firewall_not_checking_in", "firewall_failopen_probable", "firewall_ok")
    with pull_env.ctx.db.session() as db:
        states = list(
            db.scalars(
                select(AuditEvent.event_type)
                .where(AuditEvent.event_type.in_(live))
                .order_by(AuditEvent.id)
            )
        )
    assert states == ["firewall_not_checking_in", "firewall_failopen_probable", "firewall_ok"]
    assert notifications(pull_env) == [
        "firewall_not_checking_in",
        "firewall_failopen_probable",
        "firewall_ok",
    ]
    alerts_tick(pull_env)
    assert len(notifications(pull_env)) == 3  # each change once


def test_wording_follows_pfsense_reporting_fail_closed(pull_env: AppEnv, token: str) -> None:
    parent = Session(pull_env.new_client(), "parents")
    fetch(pull_env, token)
    assert acknowledge(pull_env, token, ack(extra="stale 900 closed\n")).status_code == 204
    pull_env.clock.advance(minutes=4)
    assert "If this reaches 15 min, every device is switched off." in parent.get("/parent").text
    pull_env.clock.advance(minutes=12)
    assert "every device is probably switched off" in parent.get("/parent").text


def test_a_reported_episode_is_stored_once_shown_and_dismissed(
    pull_env: AppEnv, token: str
) -> None:
    mum, dad = Session(pull_env.new_client(), "parents"), None
    pull_env.ctx.accounts.add_parent("sam", "Sam", "sam-parent-pw", "test")
    dad = Session(pull_env.new_client(), "sam", "sam-parent-pw")
    fetch(pull_env, token)  # 10:00
    # Every device was allowed from 08:30 for 21 minutes; pfSense reports it in each ack.
    assert acknowledge(pull_env, token, ack(extra="last-failopen 5400 1260\n")).status_code == 204
    pull_env.clock.advance(seconds=61)
    assert acknowledge(pull_env, token, ack(extra="last-failopen 5461 1260\n")).status_code == 204
    with pull_env.ctx.db.session() as db:
        [episode] = db.scalars(select(FailopenEpisode)).all()
    page = mum.get("/parent").text
    assert "Every device was allowed from 08:30 to 08:51 (21 min), including during curfew." in page
    assert f"/api/parent/failopen/{episode.id}/dismiss" in page
    assert notifications(pull_env).count("firewall_failopen_episode") == 1

    child = Session(pull_env.new_client(), "child8")
    assert child.post(f"/api/parent/failopen/{episode.id}/dismiss").status_code == 403
    assert dad.post(f"/api/parent/failopen/{episode.id}/dismiss").json()["ok"]
    assert "Every device was allowed" not in mum.get("/parent").text  # dismissed for everyone
    assert mum.post(f"/api/parent/failopen/{episode.id}/dismiss").status_code == 404
    [dismissal] = events(pull_env, "failopen_dismissed")
    assert dismissal.actor == "sam"
    # pfSense keeps reporting it for 7 days: still stored once, still dismissed.
    acknowledge(pull_env, token, ack(extra="last-failopen 5521 1260\n"))
    assert "Every device was allowed" not in mum.get("/parent").text


def test_a_live_fail_open_reported_by_pfsense_is_shown(pull_env: AppEnv, token: str) -> None:
    parent = Session(pull_env.new_client(), "parents")
    fetch(pull_env, token)
    acknowledge(pull_env, token, ack(mode="fail-open"))
    assert "every device is allowed right now (fail-open)" in parent.get("/parent").text


def test_an_outage_of_the_controller_is_shown_until_pfsense_acknowledges(
    env_factory: Callable[..., AppEnv],
) -> None:
    first = env_factory(firewall={"mode": "pfsense_pull"})
    with first.ctx.db.session(write=True) as db:
        heartbeat = first.clock.now() - timedelta(minutes=25)  # unplugged at 09:35
        db.merge(Meta(key=HEARTBEAT_KEY, value=heartbeat.isoformat()))
    restarted = env_factory(firewall={"mode": "pfsense_pull"})  # same database, 10:00
    token = rotate(restarted)
    parent = Session(restarted.new_client(), "parents")
    text = "The controller was off from 09:35 to 10:00; pfSense will confirm whether devices were opened."
    assert text in parent.get("/parent").text
    assert events(restarted, "controller_outage")
    fetch(restarted, token)
    restarted.clock.advance(seconds=5)
    acknowledge(restarted, token, ack())
    assert "The controller was off" not in parent.get("/parent").text


def test_a_short_restart_is_not_an_outage(env_factory: Callable[..., AppEnv]) -> None:
    first = env_factory(firewall={"mode": "pfsense_pull"})
    first.ctx.firewall_alerts_tick()  # heartbeat now
    restarted = env_factory(firewall={"mode": "pfsense_pull"})
    assert restarted.ctx.alerts is not None and restarted.ctx.alerts.outage is None


# --- C9 drift check ----------------------------------------------------------------------


def run(env: AppEnv, *argv: str) -> tuple[int, str]:
    lines: list[str] = []
    return main(list(argv), ctx=env.ctx, out=lines.append), "\n".join(lines)


def test_firewall_check_passes_when_config_matches_pfsense(pull_env: AppEnv, token: str) -> None:
    assert run(pull_env, "firewall-check")[0] == 1  # nothing acknowledged yet
    fetch(pull_env, token)
    acknowledge(pull_env, token, ack(extra="stale 600 open\n"))
    code, text = run(pull_env, "firewall-check")
    assert code == 0 and "matches pfSense" in text


@pytest.mark.parametrize(
    ("extra", "known", "needle"),
    [
        ("stale 900 open\n", KNOWN, "STALE_GRACE is 900 on pfSense"),
        (
            "stale 600 open\n",
            KNOWN.replace("192.168.12.40", "192.168.12.42"),
            "kids_tv is 192.168.12.40 (tv) here but 192.168.12.42 (tv) on pfSense",
        ),
        (
            "stale 600 open\n",
            KNOWN.replace("known lounge_tv 192.168.12.41 tv\n", ""),
            "lounge_tv is not in pfSense's device map",
        ),
        (
            "stale 600 open\n",
            KNOWN + "known garage 192.168.12.50 tv\n",
            "garage is in pfSense's device map but not in config.yaml",
        ),
        ("", KNOWN, "does not report its grace period"),
        ("stale 600 open\n", "", "does not report its device map"),
    ],
)
def test_firewall_check_reports_each_mismatch(
    pull_env: AppEnv, token: str, extra: str, known: str, needle: str
) -> None:
    fetch(pull_env, token)
    acknowledge(pull_env, token, ack(extra=extra, known=known))
    code, text = run(pull_env, "firewall-check")
    assert code == 1 and needle in text
    parent = Session(pull_env.new_client(), "parents")
    assert needle.replace("'", "&#39;") in parent.get("/parent/diagnostics").text


def test_firewall_check_needs_pull_mode(app_env: AppEnv) -> None:
    assert run(app_env, "firewall-check")[0] == 2


def test_diagnostics_show_fetch_and_acknowledgement(pull_env: AppEnv, token: str) -> None:
    fetch(pull_env, token)
    acknowledge(pull_env, token, ack(extra="stale 600 open\n"))
    page = Session(pull_env.new_client(), "parents").get("/parent/diagnostics").text
    for needle in (
        "pfSense (pull)",
        "Last fetch",
        "10:00:00",
        "Acknowledged generation",
        "600 s, open",
        "config.yaml matches pfSense",
        "SCR_EDU_ALLOW",
    ):
        assert needle in page, needle
    assert "Unresolved hostnames" not in page  # the education resolver is not used in pull mode


def test_old_acknowledgements_are_pruned_but_the_latest_is_kept(
    pull_env: AppEnv, token: str
) -> None:
    from app.models import FirewallAck

    fetch(pull_env, token)
    acknowledge(pull_env, token, ack(generation=1))
    acknowledge(pull_env, token, ack(generation=2))
    pull_env.clock.advance(days=31)
    pull_env.ctx.maintenance()
    with pull_env.ctx.db.session() as db:
        assert [a.generation for a in db.scalars(select(FirewallAck))] == [2]
