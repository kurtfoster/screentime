"""Login accounts in the database (plan section 7): lookup, creation, password changes.

Children's accounts follow ``config.yaml``: every configured child has exactly one enabled
``child`` row (created at start-up without a password, so a parent can set it from a phone).
Parent accounts are created and removed with the admin CLI only.

Every password change stores the new hash with who set it and when, revokes all of that
user's web sessions, clears their lockouts and writes an audit event. Passwords are never
logged or audited.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.clock import Clock
from app.config import USERNAME_PATTERN, AppConfig
from app.db import Database
from app.models import TYPE_CHILD, TYPE_PARENT, User
from app.password_policy import password_problem

if TYPE_CHECKING:
    from app.auth import AuthService

log = logging.getLogger("screentime.accounts")


class AccountError(Exception):
    """A request about an account that cannot be carried out; the message is for people."""


@dataclass(frozen=True)
class Account:
    username: str
    role: str
    child_id: str | None
    enabled: bool
    display_name: str
    password_hash: str
    password_changed_at: datetime | None
    password_changed_by: str | None

    @property
    def has_password(self) -> bool:
        return bool(self.password_hash)

    @property
    def is_parent(self) -> bool:
        return self.role == TYPE_PARENT


def _to_account(row: User, config: AppConfig) -> Account:
    if row.role == TYPE_CHILD and row.child_id in config.children:
        name = config.children[row.child_id].display_name
    else:
        name = row.display_name or row.username
    return Account(
        username=row.username,
        role=row.role,
        child_id=row.child_id,
        enabled=row.enabled,
        display_name=name,
        password_hash=row.password_hash,
        password_changed_at=row.password_changed_at,
        password_changed_by=row.password_changed_by,
    )


def load_account(session: Session, config: AppConfig, username: str) -> Account | None:
    row = session.scalars(select(User).where(User.username == username)).first()
    return None if row is None else _to_account(row, config)


def sync_child_accounts(session: Session, config: AppConfig) -> None:
    """One enabled child row per configured child; rows for removed children are disabled."""
    rows = {u.username: u for u in session.scalars(select(User))}
    wanted: dict[str, str] = {c.username: cid for cid, c in config.children.items()}
    for username, child_id in wanted.items():
        row = rows.get(username)
        if row is None:
            session.add(
                User(
                    username=username,
                    role=TYPE_CHILD,
                    child_id=child_id,
                    enabled=True,
                    password_hash="",
                )
            )
        elif row.role != TYPE_CHILD:
            log.error(
                "children.%s.username %r is already a %s account; that child cannot sign in "
                "until one of them is renamed",
                child_id,
                username,
                row.role,
            )
        else:
            row.child_id, row.enabled = child_id, True
    for row in rows.values():
        if row.role == TYPE_CHILD and wanted.get(row.username) != row.child_id:
            row.enabled = False


class AccountService:
    def __init__(self, db: Database, config: AppConfig, clock: Clock, auth: AuthService) -> None:
        self._db = db
        self._cfg = config
        self._clock = clock
        self._auth = auth

    # -- reads ------------------------------------------------------------------------

    def get(self, username: str) -> Account | None:
        with self._db.session() as session:
            return load_account(session, self._cfg, username)

    def all(self) -> list[Account]:
        with self._db.session() as session:
            rows = session.scalars(select(User).order_by(User.role.desc(), User.username)).all()
            return [_to_account(r, self._cfg) for r in rows]

    def parents(self) -> list[Account]:
        return [a for a in self.all() if a.is_parent and a.enabled]

    def missing_child_logins(self) -> list[Account]:
        """Configured children who cannot sign in yet because no password has been set."""
        return [a for a in self.all() if a.role == TYPE_CHILD and a.enabled and not a.has_password]

    # -- changes ----------------------------------------------------------------------

    def check_new_password(self, username: str, password: str) -> None:
        problem = password_problem(password, username, self._cfg.security.password_min_length)
        if problem:
            raise AccountError(problem)

    def add_parent(self, username: str, display_name: str, password: str, actor: str) -> Account:
        username = username.strip().lower()
        if not re.fullmatch(USERNAME_PATTERN, username):
            raise AccountError(
                "Usernames are 1 to 32 lowercase letters, digits, '.', '_' or '-', "
                "starting with a letter."
            )
        display_name = display_name.strip()
        if not 1 <= len(display_name) <= 64:
            raise AccountError("The display name must be 1 to 64 characters.")
        if self.get(username) is not None:
            raise AccountError(f"An account called {username!r} already exists.")
        self.check_new_password(username, password)
        password_hash = self._auth.passwords.hash(password)  # slow: outside the transaction
        now = self._clock.now()
        with self._db.session(write=True) as session:
            session.add(
                User(
                    username=username,
                    role=TYPE_PARENT,
                    child_id=None,
                    enabled=True,
                    display_name=display_name,
                    password_hash=password_hash,
                    password_changed_at=now,
                    password_changed_by=actor[:32],
                )
            )
            record_audit(session, now, actor, "account_created", username, role=TYPE_PARENT)
            account = load_account(session, self._cfg, username)
        assert account is not None
        return account

    def set_password(self, username: str, password: str, actor: str) -> Account:
        """Store a new password, then sign that user out everywhere and clear their lockouts.

        The caller re-issues a session when users change their own password.
        """
        account = self.get(username)
        if account is None or not account.enabled:
            raise AccountError(f"There is no enabled account called {username!r}.")
        self.check_new_password(username, password)
        password_hash = self._auth.passwords.hash(password)
        now = self._clock.now()
        with self._db.session(write=True) as session:
            row = session.scalars(select(User).where(User.username == username)).one()
            row.password_hash = password_hash
            row.password_changed_at = now
            row.password_changed_by = actor[:32]
            self._auth.revoke_sessions(session, username)
            self._auth.clear_lockouts(session, username)
            record_audit(
                session,
                now,
                actor,
                "password_changed" if actor == username else "password_reset",
                username,
            )
            updated = _to_account(row, self._cfg)
        return updated

    def set_enabled(self, username: str, enabled: bool, actor: str) -> None:
        account = self.get(username)
        if account is None:
            raise AccountError(f"There is no account called {username!r}.")
        if not account.is_parent:
            raise AccountError("Child accounts follow config.yaml: remove the child there instead.")
        if not enabled and [p.username for p in self.parents()] == [username]:
            raise AccountError("This is the only enabled parent account; add another one first.")
        with self._db.session(write=True) as session:
            row = session.scalars(select(User).where(User.username == username)).one()
            row.enabled = enabled
            if not enabled:
                self._auth.revoke_sessions(session, username)
            record_audit(
                session,
                self._clock.now(),
                actor,
                "account_enabled" if enabled else "account_disabled",
                username,
            )
