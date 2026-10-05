"""Accounts in the database (plan 7, D7 to D9): admin CLI, sign-in, rehash, missing logins."""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest
from sqlalchemy import select

from app.accounts import AccountError
from app.admin import main
from app.config import PasswordHashCfg
from app.models import AuditEvent, User, WebSession
from app.passwords import PasswordHashing
from tests.integration.conftest import PASSWORDS, AppEnv, Session
from tests.integration.test_web_auth import attempt


def run(env: AppEnv, *argv: str) -> tuple[int, str]:
    lines: list[str] = []
    code = main(list(argv), ctx=env.ctx, out=lines.append)
    return code, "\n".join(lines)


@pytest.fixture
def typed(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """What the operator types at the getpass prompts, in order."""
    answers: list[str] = []
    monkeypatch.setattr("app.admin.getpass.getpass", lambda prompt="": answers.pop(0))
    yield answers
    assert answers == [], "not every prompt was answered"


def audit_rows(env: AppEnv) -> list[AuditEvent]:
    with env.ctx.db.session() as db:
        return list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))


# --- admin CLI ------------------------------------------------------------------------------


def test_each_parent_gets_their_own_login(app_env: AppEnv, typed: list[str]) -> None:
    typed += ["kurt-pw-1", "kurt-pw-1"]
    code, text = run(app_env, "user", "add-parent", "kurt", "--name", "Kurt")
    assert code == 0 and "created parent account kurt (Kurt)" in text
    assert attempt(app_env.new_client(), "kurt", "kurt-pw-1").status_code == 303
    code, listing = run(app_env, "user", "list")
    assert "kurt" in listing and "Kurt" in listing and "by admin-cli" in listing
    assert "parents" in listing  # the fixture's parent is still there


def test_add_parent_refuses_bad_input(app_env: AppEnv, typed: list[str]) -> None:
    typed += ["one-pw", "another-pw"]
    code, text = run(app_env, "user", "add-parent", "kurt", "--name", "Kurt")
    assert code == 1 and "do not match" in text
    typed += ["1234", "1234"]
    code, text = run(app_env, "user", "add-parent", "kurt", "--name", "Kurt")
    assert code == 1 and "straight sequence" in text
    typed += ["fine-pw", "fine-pw"]
    code, text = run(app_env, "user", "add-parent", "child8", "--name", "Clash")
    assert code == 1 and "already exists" in text
    typed += ["fine-pw", "fine-pw"]
    code, text = run(app_env, "user", "add-parent", "Bad Name!", "--name", "X")
    assert code == 1 and "lowercase" in text
    with pytest.raises(AccountError, match="display name"):
        app_env.ctx.accounts.add_parent("sam", "", "fine-pw", "test")


def test_set_password_signs_the_user_out_everywhere_and_is_audited(
    app_env: AppEnv, child8: Session, typed: list[str], caplog: pytest.LogCaptureFixture
) -> None:
    other_device = Session(app_env.new_client(), "child8")
    typed += ["new-child8-pw", "new-child8-pw"]
    with caplog.at_level(logging.INFO):
        code, text = run(app_env, "user", "set-password", "child8")
    assert code == 0 and "signed out" in text
    for s in (child8, other_device):
        assert s.client.get("/child", follow_redirects=False).status_code == 303
    assert attempt(app_env.new_client(), "child8", PASSWORDS["child8"]).status_code == 401
    assert attempt(app_env.new_client(), "child8", "new-child8-pw").status_code == 303
    event = [e for e in audit_rows(app_env) if e.event_type == "password_reset"][-1]
    assert (event.actor, event.subject, event.result) == ("admin-cli", "child8", "ok")
    everything = caplog.text + "".join(e.details_json for e in audit_rows(app_env))
    assert "new-child8-pw" not in everything  # never logged or audited
    with app_env.ctx.db.session() as db:
        row = db.scalars(select(User).where(User.username == "child8")).one()
        assert row.password_changed_by == "admin-cli" and row.password_changed_at is not None


def test_set_password_clears_a_lockout(app_env: AppEnv, typed: list[str]) -> None:
    client = app_env.new_client()
    for _ in range(5):
        attempt(client, "child12", "wrong-pw")
    assert attempt(client, "child12", PASSWORDS["child12"]).status_code == 429
    typed += ["fresh-pw-12", "fresh-pw-12"]
    assert run(app_env, "user", "set-password", "child12")[0] == 0
    assert attempt(client, "child12", "fresh-pw-12").status_code == 303


def test_set_password_for_an_unknown_account_fails_before_prompting(app_env: AppEnv) -> None:
    code, text = run(app_env, "user", "set-password", "nobody")
    assert code == 1 and "no enabled account" in text


def test_disable_and_enable_a_parent(app_env: AppEnv, parent: Session, typed: list[str]) -> None:
    code, text = run(app_env, "user", "disable", "parents")
    assert code == 1 and "only enabled parent" in text
    typed += ["kurt-pw-1", "kurt-pw-1"]
    run(app_env, "user", "add-parent", "kurt", "--name", "Kurt")
    assert run(app_env, "user", "disable", "parents") == (0, "disabled parents")
    assert parent.client.get("/parent", follow_redirects=False).status_code == 303  # signed out
    assert attempt(app_env.new_client(), "parents", PASSWORDS["parents"]).status_code == 401
    assert "DISABLED" in run(app_env, "user", "list")[1]
    assert run(app_env, "user", "enable", "parents")[0] == 0
    assert attempt(app_env.new_client(), "parents", PASSWORDS["parents"]).status_code == 303
    code, text = run(app_env, "user", "disable", "child8")
    assert code == 1 and "config.yaml" in text
    assert run(app_env, "user", "disable", "ghost")[0] == 1


# --- sign-in --------------------------------------------------------------------------------


def test_login_rehashes_with_the_configured_parameters(app_env: AppEnv) -> None:
    legacy = PasswordHashing(PasswordHashCfg(memory_kib=65536, time_cost=3, parallelism=4))
    with app_env.ctx.db.session(write=True) as db:
        row = db.scalars(select(User).where(User.username == "parents")).one()
        row.password_hash = legacy.hash("old-parent-pw")
    assert attempt(app_env.new_client(), "parents", "old-parent-pw").status_code == 303
    with app_env.ctx.db.session() as db:
        stored = db.scalars(select(User.password_hash).where(User.username == "parents")).one()
    assert "$m=19456,t=2,p=1$" in stored  # upgraded to security.password_hash
    assert attempt(app_env.new_client(), "parents", "old-parent-pw").status_code == 303
    assert any(e.event_type == "password_rehashed" for e in audit_rows(app_env))


def test_a_child_without_a_password_is_reported_not_a_startup_failure(app_env: AppEnv) -> None:
    with app_env.ctx.db.session(write=True) as db:
        db.scalars(select(User).where(User.username == "child12")).one().password_hash = ""
    missing = app_env.ctx.accounts.missing_child_logins()
    assert [(a.username, a.display_name) for a in missing] == [("child12", "Child 12")]
    for guess in ("anything", "child12"):
        assert attempt(app_env.new_client(), "child12", guess).status_code == 401


def test_overlong_passwords_are_refused_without_hashing(app_env: AppEnv) -> None:
    result = app_env.ctx.auth.login("parents", "x" * 129, "192.168.12.50")
    assert not result.ok and "not right" in result.message


# --- children follow config.yaml ------------------------------------------------------------


def test_child_accounts_follow_the_configuration(env_factory, tmp_path) -> None:  # type: ignore[no-untyped-def]
    first = env_factory()
    assert attempt(first.new_client(), "child8", PASSWORDS["child8"]).status_code == 303
    # The household renames child8's login in config.yaml and restarts.
    renamed = env_factory(
        children={
            "child8": {
                "display_name": "Child 8",
                "username": "eight",
                "weekday_allowance_minutes": 120,
                "weekend_allowance_minutes": 180,
                "owned_devices": ["ipad"],
                "permitted_shared_devices": ["kids_tv", "lounge_tv"],
            }
        }
    )
    accounts = {a.username: a for a in renamed.ctx.accounts.all()}
    assert not accounts["child8"].enabled  # the old name can no longer sign in
    assert accounts["eight"].enabled and not accounts["eight"].has_password
    assert attempt(renamed.new_client(), "child8", PASSWORDS["child8"]).status_code == 401
    with renamed.ctx.db.session() as db:
        assert not db.scalars(select(WebSession).where(WebSession.username == "eight")).all()


def test_a_parent_name_used_as_a_child_username_is_logged_not_fatal(
    app_env: AppEnv, caplog: pytest.LogCaptureFixture
) -> None:
    from app.bootstrap import sync_reference_data
    from tests.conftest import make_config

    config = make_config(
        app_env.tmp_path,
        children={
            "child12": {
                "display_name": "Child 12",
                "username": "parents",
                "weekday_allowance_minutes": 120,
                "weekend_allowance_minutes": 180,
                "owned_devices": ["iphone_child12"],
                "permitted_shared_devices": ["kids_tv", "lounge_tv"],
            }
        },
    )
    with caplog.at_level(logging.ERROR), app_env.ctx.db.session(write=True) as db:
        sync_reference_data(db, config)
    assert "already a parent account" in caplog.text
    with app_env.ctx.db.session() as db:
        row = db.scalars(select(User).where(User.username == "parents")).one()
    assert row.role == "parent" and row.enabled
