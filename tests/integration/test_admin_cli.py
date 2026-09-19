"""The admin CLI drives the same services as the web UI (spec section 25)."""

from __future__ import annotations

import pytest

from app.admin import main
from tests.integration.conftest import IPAD, KIDS_TV, AppEnv, Session


def run(env: AppEnv, *argv: str) -> tuple[int, str]:
    lines: list[str] = []
    code = main(list(argv), ctx=env.ctx, out=lines.append)
    return code, "\n".join(lines)


def test_status_lists_policy_state(app_env: AppEnv, child8: Session, parent: Session) -> None:
    child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 30})
    parent.post("/api/parent/child/child12/end-today")
    parent.post("/api/parent/tv/lounge_tv/start", {"minutes": 15})
    code, text = run(app_env, "status")
    assert code == 0
    for needle in (
        "Child 8",
        "active:    #1 ipad",
        "Child 12",
        "day lock:  ACTIVE",
        "lounge_tv",
        "= 2h remaining",
        "logical day 2026-09-21",
    ):
        assert needle in text, (needle, text)


def test_devices_and_sessions_and_audit(app_env: AppEnv, child8: Session) -> None:
    child8.post("/api/child/session/start", {"device_id": "kids_tv", "minutes": 15})
    assert (
        IPAD in run(app_env, "devices")[1] and "weekday_cutoff=18:30" in run(app_env, "devices")[1]
    )
    assert "kids_tv" in run(app_env, "sessions")[1]
    assert "no sessions" in run(app_env, "sessions", "--all", "--limit", "0")[1]
    assert "session_start" in run(app_env, "audit")[1]


def test_reset_commands_change_state_and_firewall(app_env: AppEnv, child8: Session) -> None:
    child8.post("/api/child/session/start", {"device_id": "kids_tv", "minutes": 30})
    assert app_env.firewall.active == {KIDS_TV}
    code, text = run(app_env, "end-all")
    assert code == 0 and "ended" in text
    assert app_env.firewall.active == set() and ("kill_states", KIDS_TV) in app_env.firewall.ops()
    assert "no sessions" in run(app_env, "sessions")[1]


def test_grant_end_today_and_clear_lock(app_env: AppEnv) -> None:
    assert run(app_env, "grant", "child8", "30")[0] == 0
    assert "2h 30m" in run(app_env, "status")[1]
    assert run(app_env, "end-today", "child8")[0] == 0
    assert "ACTIVE" in run(app_env, "status")[1]
    assert run(app_env, "clear-lock", "child8")[0] == 0
    assert run(app_env, "grant", "nobody", "30")[0] == 2
    code, text = run(app_env, "grant", "child8", "45")
    assert code == 1 and "INVALID_DURATION" in text


def test_tv_and_enable_device_and_end_session(app_env: AppEnv) -> None:
    assert run(app_env, "tv", "kids_tv", "until-stopped")[0] == 0
    assert app_env.firewall.active == {KIDS_TV}
    assert run(app_env, "end-session", "1")[0] == 0 and app_env.firewall.active == set()
    assert run(app_env, "enable-device", "lounge_tv", "10")[0] == 0
    assert "192.168.12.41" in app_env.firewall.active
    assert run(app_env, "end-session", "999")[0] == 1


def test_unlock_and_reconcile(app_env: AppEnv) -> None:
    client = app_env.new_client()
    import re

    for _ in range(5):
        token = re.search(r'name="login_token" value="([^"]+)"', client.get("/login").text)
        assert token
        client.post(
            "/login",
            data={"username": "child8", "password": "bad-bad", "login_token": token.group(1)},
        )
    assert "unlocked child8" in run(app_env, "unlock", "child8")[1]
    assert "was not locked" in run(app_env, "unlock", "child8")[1]
    app_env.firewall.active = {"192.168.12.98"}
    code, text = run(app_env, "reconcile", "--education")
    assert code == 0 and "removed=['192.168.12.98']" in text
    app_env.firewall.fail_all = True
    assert run(app_env, "reconcile")[0] == 1


def test_bad_arguments_exit_nonzero() -> None:
    with pytest.raises(SystemExit):
        main(["grant"])
