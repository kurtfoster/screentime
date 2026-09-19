"""Login, role enforcement, CSRF, lockouts and response hardening (spec 10.1, 19)."""

from __future__ import annotations

import contextlib
import re

from tests.integration.conftest import PASSWORDS, AppEnv, Session


def login_token(client) -> str:  # type: ignore[no-untyped-def]
    match = re.search(r'name="login_token" value="([^"]+)"', client.get("/login").text)
    assert match
    return match.group(1)


def attempt(client, username: str, password: str):  # type: ignore[no-untyped-def]
    return client.post(
        "/login",
        data={"username": username, "password": password, "login_token": login_token(client)},
        follow_redirects=False,
    )


def test_anonymous_requests_are_redirected_or_rejected(app_env: AppEnv) -> None:
    client = app_env.new_client()
    for path in ("/child", "/parent", "/parent/diagnostics", "/child/live"):
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code == 303 and resp.headers["location"] == "/login"
    api = client.post("/api/child/session/start", json={"device_id": "ipad", "minutes": 30})
    assert api.status_code == 401 and api.json()["reason"] == "UNAUTHENTICATED"


def test_child_login_lands_on_child_dashboard_only(app_env: AppEnv, child8: Session) -> None:
    page = child8.get("/child")
    assert (
        page.status_code == 200 and "START SCREEN TIME" in page.text and "Hi Child 8" in page.text
    )
    assert "END TODAY" not in page.text
    root = child8.client.get("/", follow_redirects=False)
    assert root.status_code == 303 and root.headers["location"] == "/child"


def test_parent_login_lands_on_parent_dashboard(parent: Session) -> None:
    page = parent.get("/parent")
    assert page.status_code == 200 and "END TODAY" in page.text and "TV access" in page.text


def test_children_cannot_reach_parent_pages_or_apis_even_by_guessing_urls(
    app_env: AppEnv, child8: Session
) -> None:
    assert child8.get("/parent").status_code == 403
    assert child8.get("/parent/diagnostics").status_code == 403
    assert child8.get("/parent/live").status_code == 403
    for url, body in [
        ("/api/parent/child/child8/grant", {"minutes": 60}),
        ("/api/parent/child/child12/end-today", {}),
        ("/api/parent/child/child8/clear-day-lock", {}),
        ("/api/parent/tv/kids_tv/start", {"minutes": 30}),
        ("/api/parent/session/1/stop", {}),
        ("/api/parent/lockouts/child8/reset", {}),
    ]:
        resp = child8.post(url, body)
        assert resp.status_code == 403, url
        assert resp.json()["reason"] == "FORBIDDEN"


def test_parent_cannot_use_child_only_endpoints(parent: Session) -> None:
    resp = parent.post("/api/child/session/start", {"device_id": "kids_tv", "minutes": 30})
    assert resp.status_code == 403
    assert parent.get("/child").status_code == 403


def test_wrong_password_and_unknown_user_give_the_same_message(app_env: AppEnv) -> None:
    client = app_env.new_client()
    a = attempt(client, "child8", "nope-nope")
    b = attempt(client, "nobody", "nope-nope")
    assert a.status_code == b.status_code == 401
    assert "not right" in a.text and "not right" in b.text


def test_login_form_requires_a_valid_token(app_env: AppEnv) -> None:
    client = app_env.new_client()
    resp = client.post(
        "/login",
        data={"username": "child8", "password": PASSWORDS["child8"], "login_token": "forged"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


def test_cookie_flags_and_rotation(app_env: AppEnv) -> None:
    client = app_env.new_client()
    resp = attempt(client, "child8", PASSWORDS["child8"])
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie
    first = client.cookies.get("st_session")
    client2 = app_env.new_client()
    attempt(client2, "child8", PASSWORDS["child8"])
    assert client2.cookies.get("st_session") != first  # a fresh session id on every login


def test_secure_cookie_flag_follows_config(env_factory) -> None:  # type: ignore[no-untyped-def]
    env = env_factory(security={"secure_cookies": True, "enforce_file_modes": False})
    resp = attempt(env.client, "child8", PASSWORDS["child8"])
    assert "secure" in resp.headers["set-cookie"].lower()


def test_api_requires_csrf_token(child8: Session) -> None:
    resp = child8.post("/api/child/session/start", {"device_id": "ipad", "minutes": 30}, csrf=False)
    assert resp.status_code == 403 and resp.json()["reason"] == "CSRF"
    wrong = child8.client.post(
        "/api/child/session/start",
        json={"device_id": "ipad", "minutes": 30},
        headers={"X-CSRF-Token": "not-the-token"},
    )
    assert wrong.status_code == 403


def test_logout_invalidates_the_session_server_side(app_env: AppEnv, child8: Session) -> None:
    cookie = child8.client.cookies.get("st_session")
    assert cookie
    resp = child8.client.post("/logout", data={"csrf_token": child8.csrf}, follow_redirects=False)
    assert resp.status_code == 303
    replay = app_env.new_client()
    replay.cookies.set("st_session", cookie)
    assert replay.get("/child", follow_redirects=False).status_code == 303  # token no longer valid


def test_forged_logout_does_not_end_the_server_side_session(
    app_env: AppEnv, child8: Session
) -> None:
    cookie = child8.client.cookies.get("st_session")
    assert cookie
    child8.client.post("/logout", data={"csrf_token": "forged"}, follow_redirects=False)
    other = app_env.new_client()
    other.cookies.set("st_session", cookie)
    assert other.get("/child").status_code == 200  # a cross-site logout cannot kill the session


def test_failed_logins_lock_a_child_until_a_parent_resets(app_env: AppEnv, parent: Session) -> None:
    client = app_env.new_client()
    for _ in range(4):
        assert attempt(client, "child8", "wrong-pw").status_code == 401
    locked = attempt(client, "child8", "wrong-pw")
    assert locked.status_code == 429
    # Even the correct password is refused while locked.
    assert attempt(client, "child8", PASSWORDS["child8"]).status_code == 429
    dash = parent.get("/parent/live")
    assert "Locked logins" in dash.text and "child8" in dash.text
    assert parent.post("/api/parent/lockouts/child8/reset").json()["ok"] is True
    assert attempt(client, "child8", PASSWORDS["child8"]).status_code == 303


def test_lockout_expires_with_time(app_env: AppEnv) -> None:
    client = app_env.new_client()
    for _ in range(5):
        attempt(client, "child12", "wrong-pw")
    assert attempt(client, "child12", PASSWORDS["child12"]).status_code == 429
    app_env.clock.advance(minutes=16)
    assert attempt(client, "child12", PASSWORDS["child12"]).status_code == 303


def test_children_cannot_lock_the_parent_account_from_another_address(app_env: AppEnv) -> None:
    child_device = app_env.new_client()
    for _ in range(6):
        attempt(child_device, "parents", "guess-guess")
    assert attempt(child_device, "parents", "guess-guess").status_code == 429
    # A parent signing in from a different source address is unaffected.
    from fastapi.testclient import TestClient

    parent_phone = TestClient(app_env.client.app, client=("192.168.12.99", 40000))  # type: ignore[arg-type]
    assert attempt(parent_phone, "parents", PASSWORDS["parents"]).status_code == 303


def test_security_headers_and_no_store(child8: Session) -> None:
    resp = child8.get("/child")
    assert "default-src 'self'" in resp.headers["content-security-policy"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-frame-options"] == "DENY"
    static = child8.get("/static/css/app.css")
    assert static.status_code == 200 and "no-store" not in static.headers.get("cache-control", "")
    assert "<script>" not in resp.text  # no inline scripts (CSP)


def test_health_endpoints_are_local_only(app_env: AppEnv) -> None:
    assert app_env.client.get("/health/live").json()["status"] == "ok"
    ready = app_env.client.get("/health/ready")
    assert ready.status_code == 200 and ready.json()["database"] == "ok"
    from fastapi.testclient import TestClient

    remote = TestClient(app_env.client.app, client=("8.8.8.8", 1234))  # type: ignore[arg-type]
    assert remote.get("/health/live").status_code == 404
    assert remote.get("/health/ready").status_code == 404


def test_ready_reports_degraded_firewall(app_env: AppEnv) -> None:
    app_env.firewall.fail_all = True
    with contextlib.suppress(Exception):
        app_env.reconcile()
    resp = app_env.client.get("/health/ready")
    assert resp.status_code == 503 and resp.json()["firewall"] == "degraded"


def test_pwa_assets_are_served(app_env: AppEnv) -> None:
    client = app_env.new_client()
    assert client.get("/static/manifest.webmanifest").json()["display"] == "standalone"
    sw = client.get("/service-worker.js")
    assert sw.status_code == 200 and sw.headers["service-worker-allowed"] == "/"
    assert "javascript" in sw.headers["content-type"]
    assert "Screen Time controller unavailable" in client.get("/offline").text
    for icon in ("icon-192.png", "icon-512.png", "apple-touch-icon.png"):
        assert client.get(f"/static/icons/{icon}").status_code == 200
