"""pfSense's fetch and acknowledgement routes (plan 6.3, 6.5; Gate A firewall route tests)."""

from __future__ import annotations

import importlib
import logging
import pkgutil
import re
import stat
from collections.abc import Callable

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.admin import main
from app.clock import ClockSync
from app.firewall.token import TOKEN_FILE
from app.models import FirewallAck, SessionRecord
from app.routes.firewall import SESSIONLESS_PATHS
from tests.integration.conftest import AppEnv, Session

PFSENSE = "192.168.12.1"
ACK = "screentime-applied v1\ngeneration {g}\nmode normal\n{devices}end\n"


@pytest.fixture
def pull_env(env_factory: Callable[..., AppEnv]) -> AppEnv:
    return env_factory(firewall={"mode": "pfsense_pull"})


def rotate(env: AppEnv) -> str:
    lines: list[str] = []
    assert main(["firewall-token", "rotate"], ctx=env.ctx, out=lines.append) == 0
    [token] = [ln.strip() for ln in lines if re.fullmatch(r"\s+[A-Za-z0-9_-]{40,}", ln)]
    return token


def fetch(env: AppEnv, token: str | None, source: str = PFSENSE):  # type: ignore[no-untyped-def]
    headers = {"X-Real-IP": source}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return env.client.get("/firewall/v1/desired", headers=headers)


def acknowledge(env: AppEnv, token: str, body: str | bytes, source: str = PFSENSE):  # type: ignore[no-untyped-def]
    return env.client.post(
        "/firewall/v1/applied",
        content=body,
        headers={"X-Real-IP": source, "Authorization": f"Bearer {token}"},
    )


def test_token_rotation_stores_only_a_hash_and_revokes_the_old_token(pull_env: AppEnv) -> None:
    first = rotate(pull_env)
    stored = pull_env.ctx.config.storage.data_dir / TOKEN_FILE
    assert stat.S_IMODE(stored.stat().st_mode) == 0o600
    assert first not in stored.read_text()  # a SHA-256, not the token
    assert fetch(pull_env, first).status_code == 200
    second = rotate(pull_env)
    assert fetch(pull_env, first).status_code == 401
    assert fetch(pull_env, second).status_code == 200


def test_the_desired_document_follows_the_grammar(pull_env: AppEnv) -> None:
    token = rotate(pull_env)
    empty = fetch(pull_env, token)
    assert empty.status_code == 200
    assert empty.headers["content-type"] == "text/plain; charset=us-ascii"
    assert empty.headers["cache-control"] == "no-store"
    assert re.fullmatch(r"screentime-desired v1\ngeneration \d+\nend\n", empty.text)
    pull_env.call(pull_env.ctx.orchestrator.start_child_session, "child8", "ipad", 30)
    body = fetch(pull_env, token).text
    assert re.fullmatch(r"screentime-desired v1\ngeneration \d+\ndevice ipad 900\nend\n", body)


@pytest.mark.parametrize(
    ("token", "source", "status"),
    [
        (None, PFSENSE, 401),
        ("wrong-token-wrong-token-wrong-token-wrong-token", PFSENSE, 401),
        ("VALID", "192.168.12.30", 403),  # a child's iPad, even with the right token
    ],
)
def test_wrong_token_or_source_is_refused(
    pull_env: AppEnv, token: str | None, source: str, status: int, caplog: pytest.LogCaptureFixture
) -> None:
    valid = rotate(pull_env)
    presented = valid if token == "VALID" else token
    with caplog.at_level(logging.DEBUG):
        assert fetch(pull_env, presented, source).status_code == status
        ack = acknowledge(pull_env, presented or "x", ACK.format(g=1, devices=""), source)
        assert ack.status_code == status
    assert "firewall request rejected" in caplog.text
    assert valid not in caplog.text  # the token is never logged
    if presented:
        assert presented not in caplog.text


def test_x_real_ip_is_trusted_only_from_the_local_proxy(pull_env: AppEnv) -> None:
    token = rotate(pull_env)
    direct = TestClient(pull_env.client.app, client=("192.168.12.30", 5000))  # type: ignore[arg-type]
    resp = direct.get(
        "/firewall/v1/desired",
        headers={"X-Real-IP": PFSENSE, "Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_routes_are_absent_outside_pull_mode(app_env: AppEnv) -> None:
    assert fetch(app_env, "anything").status_code == 404


class Unsynchronised(ClockSync):
    def synchronised(self) -> bool:
        return False


def test_an_unsynchronised_clock_answers_503(env_factory: Callable[..., AppEnv]) -> None:
    env = env_factory(firewall={"mode": "pfsense_pull"}, clock_sync=Unsynchronised())
    token = rotate(env)
    assert fetch(env, token).status_code == 503


def test_acknowledgement_confirms_sessions_and_is_stored_when_it_changes(
    pull_env: AppEnv,
) -> None:
    token = rotate(pull_env)
    child = Session(pull_env.new_client(), "child8")
    assert child.post("/api/child/session/start", {"device_id": "ipad", "minutes": 30}).json()["ok"]
    generation = int(re.search(r"generation (\d+)", fetch(pull_env, token).text).group(1))  # type: ignore[union-attr]
    pull_env.clock.advance(seconds=20)
    ack = ACK.format(g=generation, devices="device ipad\n")
    assert acknowledge(pull_env, token, ack).status_code == 204
    assert acknowledge(pull_env, token, ack).status_code == 204  # the same again a minute later
    pull_env.tick()
    with pull_env.ctx.db.session() as db:
        [rec] = db.scalars(select(SessionRecord)).all()
        rows = db.scalars(select(FirewallAck)).all()
    assert rec.enforced_at is not None
    assert len(rows) == 1 and rows[0].device_ids == "ipad" and rows[0].generation == generation
    applied = pull_env.ctx.enforcement.applied_state
    assert applied is not None and applied.device_ids == {"ipad"}


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ("screentime-applied v1\ngeneration 1\nmode normal\n", 400),  # truncated
        ("screentime-applied v1\ngeneration 1\nmode sideways\nend\n", 400),
        ("x" * 5000, 413),
    ],
)
def test_malformed_acknowledgements_are_rejected(pull_env: AppEnv, body: str, status: int) -> None:
    token = rotate(pull_env)
    assert acknowledge(pull_env, token, body).status_code == status
    assert pull_env.ctx.enforcement.applied_state is None


def test_starts_are_refused_when_pfsense_stops_fetching(pull_env: AppEnv) -> None:
    token = rotate(pull_env)
    child = Session(pull_env.new_client(), "child8")
    assert fetch(pull_env, token).status_code == 200
    pull_env.clock.advance(seconds=181)  # past firewall.degraded_after_seconds
    resp = child.post("/api/child/session/start", {"device_id": "ipad", "minutes": 30})
    assert resp.status_code == 503 and resp.json()["reason"] == "ENFORCEMENT_DEGRADED"
    assert fetch(pull_env, token).status_code == 200  # pfSense is back
    resp = child.post("/api/child/session/start", {"device_id": "ipad", "minutes": 30})
    assert resp.status_code == 200


def test_firewall_polls_are_logged_only_at_debug(
    pull_env: AppEnv, caplog: pytest.LogCaptureFixture
) -> None:
    token = rotate(pull_env)
    with caplog.at_level(logging.INFO, logger="screentime.app"):
        fetch(pull_env, token)
    assert not [r for r in caplog.records if "/firewall/" in r.getMessage()]


# --- the session/CSRF exemption is an explicit, guarded allowlist ----------------------------


FORM_POSTS = {"/login", "/logout", "/account/password"}  # each checks its own token


def all_routes() -> list[APIRoute]:
    """Every route in app/routes, found by module so a new router cannot be missed."""
    import app.routes

    found: list[APIRoute] = []
    for info in pkgutil.iter_modules(app.routes.__path__):
        module = importlib.import_module(f"app.routes.{info.name}")
        found += [r for r in module.router.routes if isinstance(r, APIRoute)]
    return found


def test_only_the_firewall_routes_are_sessionless(app_env: AppEnv, parent: Session) -> None:
    """Every other POST refuses a signed-in request that lacks the CSRF token."""
    routes = all_routes()
    assert {r.path for r in routes if r.path.startswith("/firewall/")} == SESSIONLESS_PATHS
    posts = sorted({r.path for r in routes if "POST" in r.methods})
    assert len(posts) > 15  # the enumeration really found the application's routes
    for path in posts:
        if path in SESSIONLESS_PATHS or path in FORM_POSTS:
            continue
        url = re.sub(r"\{[^}]+\}", "1", path)
        resp = parent.post(url, {}, csrf=False)
        assert resp.status_code in (401, 403), (path, resp.status_code)
    for path in FORM_POSTS - {"/login"}:
        resp = parent.client.post(path, data={"csrf_token": "forged"}, follow_redirects=False)
        assert resp.status_code in (303, 403, 422), path
