"""Password changes in the app (plan 7.1, D7, D8; Gate A account tests)."""

from __future__ import annotations

import logging
import re

import pytest
from sqlalchemy import select

from app.models import AuditEvent, User
from tests.integration.conftest import PASSWORDS, AppEnv, Session
from tests.integration.test_web_auth import attempt


def form_csrf(session: Session, url: str = "/account/password") -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', session.get(url).text)
    assert match
    return match.group(1)


def change_own(session: Session, current: str, new: str, confirm: str | None = None):  # type: ignore[no-untyped-def]
    return session.client.post(
        "/account/password",
        data={
            "current_password": current,
            "new_password": new,
            "confirm_password": new if confirm is None else confirm,
            "csrf_token": form_csrf(session),
        },
        follow_redirects=False,
    )


def set_for(
    parent: Session, username: str, new: str, own: str | None = None, confirm: str | None = None
):  # type: ignore[no-untyped-def]
    return parent.post(
        f"/api/parent/user/{username}/password",
        {
            "new_password": new,
            "confirm_password": new if confirm is None else confirm,
            "parent_password": PASSWORDS["parents"] if own is None else own,
        },
    )


def events(env: AppEnv, kind: str) -> list[AuditEvent]:
    with env.ctx.db.session() as db:
        return list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == kind)))


def add_second_parent(env: AppEnv) -> None:
    env.ctx.accounts.add_parent("sam", "Sam", "sam-parent-pw", "test")


# --- your own password ----------------------------------------------------------------------


def test_change_own_password_rotates_this_session_and_revokes_the_others(
    app_env: AppEnv, child8: Session, caplog: pytest.LogCaptureFixture
) -> None:
    other_device = Session(app_env.new_client(), "child8")
    old_cookie = child8.client.cookies.get("st_session")
    with caplog.at_level(logging.DEBUG):
        resp = change_own(child8, PASSWORDS["child8"], "tui-bird-7")
    assert resp.status_code == 303 and resp.headers["location"] == "/account/password?done=1"
    assert child8.client.cookies.get("st_session") != old_cookie  # rotated
    page = child8.client.get("/account/password?done=1", follow_redirects=False)
    assert page.status_code == 200 and "Password changed" in page.text
    assert child8.client.get("/child", follow_redirects=False).status_code == 200
    assert other_device.client.get("/child", follow_redirects=False).status_code == 303
    assert attempt(app_env.new_client(), "child8", "tui-bird-7").status_code == 303
    [event] = events(app_env, "password_changed")
    assert (event.actor, event.subject) == ("child8", "child8")
    assert "tui-bird-7" not in caplog.text and "tui-bird-7" not in event.details_json


def test_wrong_current_password_counts_toward_the_lockout(app_env: AppEnv, child8: Session) -> None:
    for _ in range(4):
        resp = change_own(child8, "not-my-password", "tui-bird-7")
        assert resp.status_code == 403 and "current password is not right" in resp.text
    locked = change_own(child8, "not-my-password", "tui-bird-7")
    assert locked.status_code == 429 and "Too many wrong passwords" in locked.text
    # The login is now locked too, even with the right password.
    assert attempt(app_env.new_client(), "child8", PASSWORDS["child8"]).status_code == 429
    assert len(events(app_env, "password_change")) == 5  # every denial is audited


@pytest.mark.parametrize(
    ("new", "confirm", "needle"),
    [
        ("abc", None, "at least 4"),
        ("1234", None, "straight sequence"),
        ("child8", None, "same as the username"),
        ("2015", None, "too common"),
        ("tui-bird-7", "tui-bird-8", "do not match"),
    ],
)
def test_new_password_rules_are_enforced(
    app_env: AppEnv, child8: Session, new: str, confirm: str | None, needle: str
) -> None:
    resp = change_own(child8, PASSWORDS["child8"], new, confirm)
    assert resp.status_code == 422 and needle in resp.text
    assert attempt(app_env.new_client(), "child8", PASSWORDS["child8"]).status_code == 303


def test_nfc_equivalent_passwords_match(app_env: AppEnv, child12: Session) -> None:
    assert change_own(child12, PASSWORDS["child12"], "café au lait").status_code == 303
    assert attempt(app_env.new_client(), "child12", "café au lait").status_code == 303


def test_change_password_needs_csrf_and_a_session(app_env: AppEnv, child8: Session) -> None:
    resp = child8.client.post(
        "/account/password",
        data={
            "current_password": PASSWORDS["child8"],
            "new_password": "tui-bird-7",
            "confirm_password": "tui-bird-7",
            "csrf_token": "forged",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 403
    anonymous = app_env.new_client().get("/account/password", follow_redirects=False)
    assert anonymous.status_code == 303 and anonymous.headers["location"] == "/login"


def test_password_fields_suit_phones(child8: Session) -> None:
    page = child8.get("/account/password").text
    assert 'autocomplete="current-password"' in page and 'autocomplete="new-password"' in page
    assert page.count('autocapitalize="none"') == 3 and page.count("data-toggle-password") == 3


# --- parents setting other passwords ----------------------------------------------------------


def test_parent_sets_a_childs_password_and_clears_the_lockout(
    app_env: AppEnv, parent: Session
) -> None:
    child = Session(app_env.new_client(), "child8")
    client = app_env.new_client()
    for _ in range(5):
        attempt(client, "child8", "wrong-pw")
    assert attempt(client, "child8", PASSWORDS["child8"]).status_code == 429
    page = parent.get("/parent/user/child8/password")
    assert page.status_code == 200 and "Child 8" in page.text and "Your own password" in page.text
    resp = set_for(parent, "child8", "kea-nest-3")
    assert resp.status_code == 200 and resp.json()["ok"] is True
    assert attempt(client, "child8", "kea-nest-3").status_code == 303  # lockout cleared
    assert child.client.get("/child", follow_redirects=False).status_code == 303  # signed out
    [event] = events(app_env, "password_reset")
    assert (event.actor, event.subject) == ("parents", "child8")
    with app_env.ctx.db.session() as db:
        row = db.scalars(select(User).where(User.username == "child8")).one()
    assert row.password_changed_by == "parents"


def test_setting_a_password_requires_the_parents_own_password(
    app_env: AppEnv, parent: Session
) -> None:
    resp = set_for(parent, "child8", "kea-nest-3", own="not-mine")
    assert resp.status_code == 403 and resp.json()["reason"] == "REAUTH_FAILED"
    assert attempt(app_env.new_client(), "child8", PASSWORDS["child8"]).status_code == 303
    mismatch = set_for(parent, "child8", "kea-nest-3", confirm="kea-nest-4")
    assert mismatch.status_code == 422 and mismatch.json()["reason"] == "PASSWORD_MISMATCH"
    weak = set_for(parent, "child8", "0000")
    assert weak.status_code == 422 and weak.json()["reason"] == "PASSWORD_REJECTED"


def test_failed_reauthentication_locks_the_parent_on_that_device(
    app_env: AppEnv, parent: Session
) -> None:
    codes = [set_for(parent, "child8", "kea-nest-3", own="guess").status_code for _ in range(6)]
    assert codes[:4] == [403] * 4 and codes[-1] == 429


def test_children_cannot_set_passwords(app_env: AppEnv, child8: Session) -> None:
    resp = child8.post(
        "/api/parent/user/child12/password",
        {"new_password": "kea-nest-3", "confirm_password": "kea-nest-3", "parent_password": "x"},
    )
    assert resp.status_code == 403 and resp.json()["reason"] == "FORBIDDEN"
    assert child8.get("/parent/user/child12/password").status_code == 403
    assert child8.get("/account/parents").status_code == 403


def test_a_parent_resets_the_other_parents_password(app_env: AppEnv, parent: Session) -> None:
    add_second_parent(app_env)
    sam = Session(app_env.new_client(), "sam", "sam-parent-pw")
    listing = parent.get("/account/parents").text
    assert "Sam" in listing and "/parent/user/sam/password" in listing
    assert "/parent/user/parents/password" not in listing  # your own goes via Change password
    assert set_for(parent, "sam", "pohutukawa").status_code == 200
    assert sam.client.get("/parent", follow_redirects=False).status_code == 303
    assert attempt(app_env.new_client(), "sam", "pohutukawa").status_code == 303


def test_own_and_unknown_accounts_are_refused_on_the_reset_endpoint(parent: Session) -> None:
    own = set_for(parent, "parents", "pohutukawa")
    assert own.status_code == 422 and own.json()["reason"] == "USE_CHANGE_PASSWORD"
    assert set_for(parent, "nobody", "pohutukawa").status_code == 404


# --- what parents see -------------------------------------------------------------------------


def test_missing_child_login_shows_a_set_password_button(app_env: AppEnv, parent: Session) -> None:
    with app_env.ctx.db.session(write=True) as db:
        db.scalars(select(User).where(User.username == "child12")).one().password_hash = ""
    page = parent.get("/parent").text
    assert "No password set for Child 12" in page and "/parent/user/child12/password" in page
    ready = app_env.client.get("/health/ready").json()
    assert ready["accounts"] == {"parents": 1, "children_without_password": ["child12"]}
    assert set_for(parent, "child12", "kea-nest-3").status_code == 200
    assert "No password set" not in parent.get("/parent").text


def test_last_parent_sign_in_and_recent_changes_are_shown(app_env: AppEnv) -> None:
    from fastapi.testclient import TestClient

    phone = TestClient(app_env.client.app, client=("192.168.12.30", 40000))  # type: ignore[arg-type]
    mum = Session(phone, "parents")
    page = mum.get("/parent").text
    assert "Last parent sign-in: Parents, Mon 10:00, iPad (192.168.12.30)" in page
    child = Session(app_env.new_client(), "child8")
    change_own(child, PASSWORDS["child8"], "tui-bird-7")
    assert "Child 8 changed their password, Mon 10:00" in mum.get("/parent").text
    set_for(mum, "child12", "kea-nest-3")
    assert "Parents set Child 12&#39;s password, Mon 10:00" in mum.get("/parent").text


def test_readiness_fails_without_any_parent(app_env: AppEnv) -> None:
    with app_env.ctx.db.session(write=True) as db:
        db.scalars(select(User).where(User.username == "parents")).one().enabled = False
    ready = app_env.client.get("/health/ready")
    assert ready.status_code == 503 and ready.json()["accounts"]["parents"] == 0
