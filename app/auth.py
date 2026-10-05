"""Authentication: Argon2id passwords, server-side sessions, CSRF and lockouts (spec 10.1, 19).

Cookies carry a random token plus an HMAC; only a SHA-256 of the token is stored, so a
database leak does not yield usable sessions. Each login rotates the session. Failed
logins lock a child account for a period, and a parent can reset it; the parent account
is throttled per source address instead so a child cannot lock a parent out.

Accounts and their Argon2id hashes live in the ``users`` table (app.accounts).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.accounts import Account, load_account
from app.audit import record_audit
from app.clock import Clock
from app.config import PASSWORD_MAX_LENGTH, AppConfig
from app.db import Database
from app.models import LoginFailure, User, WebSession
from app.passwords import PasswordHashing
from app.secrets_store import derive_key

COOKIE_NAME = "st_session"


@dataclass(frozen=True)
class Principal:
    username: str
    role: str  # child | parent
    child_id: str | None
    csrf_token: str

    @property
    def is_parent(self) -> bool:
        return self.role == "parent"


@dataclass(frozen=True)
class LoginResult:
    ok: bool
    cookie: str | None = None
    principal: Principal | None = None
    message: str = ""
    locked_until: datetime | None = None


class SlidingWindowLimiter:
    """Small in-memory limiter for grant/start endpoints (single process, so no shared store)."""

    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self._limit = limit
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self._window:
                hits.popleft()
            if len(hits) >= self._limit:
                return False
            hits.append(now)
            return True


class AuthService:
    def __init__(
        self,
        db: Database,
        config: AppConfig,
        clock: Clock,
        secret: bytes,
    ) -> None:
        self._db = db
        self._cfg = config
        self._clock = clock
        self._cookie_key = derive_key(secret, "session-cookie")
        self._login_key = derive_key(secret, "login-csrf")
        self.passwords = PasswordHashing(config.security.password_hash)

    # -- cookie handling --------------------------------------------------------------

    def _sign(self, token: str) -> str:
        mac = hmac.new(self._cookie_key, token.encode(), hashlib.sha256).hexdigest()[:32]
        return f"{token}.{mac}"

    def _unsign(self, cookie: str) -> str | None:
        token, _, mac = cookie.partition(".")
        expected = hmac.new(self._cookie_key, token.encode(), hashlib.sha256).hexdigest()[:32]
        if token and hmac.compare_digest(mac, expected):
            return token
        return None

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    # -- login CSRF (stateless, for the pre-login form) --------------------------------

    def new_login_token(self) -> str:
        nonce = secrets.token_hex(8)
        ts = str(int(self._clock.now().timestamp()))
        payload = f"{nonce}.{ts}"
        mac = hmac.new(self._login_key, payload.encode(), hashlib.sha256).hexdigest()[:32]
        return f"{payload}.{mac}"

    def check_login_token(self, token: str, max_age_seconds: int = 3600) -> bool:
        parts = token.split(".")
        if len(parts) != 3 or not parts[1].isdigit():
            return False
        payload = f"{parts[0]}.{parts[1]}"
        expected = hmac.new(self._login_key, payload.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(parts[2], expected):
            return False
        age = self._clock.now().timestamp() - int(parts[1])
        return 0 <= age <= max_age_seconds

    # -- accounts -------------------------------------------------------------------

    def _account(self, username: str) -> Account | None:
        """The enabled account called ``username``; disabled accounts cannot sign in."""
        with self._db.session() as session:
            account = load_account(session, self._cfg, username)
        return account if account is not None and account.enabled else None

    # -- lockouts ---------------------------------------------------------------------

    @staticmethod
    def _failure_key(username: str, client_ip: str, account: Account | None) -> str:
        if account is None:
            return f"unknown:{client_ip}"[:96]  # bounded: one row per address, never per guess
        if account.is_parent:
            return f"parent:{username}:{client_ip}"[:96]
        return f"user:{username}"[:96]

    def lockout_for(
        self, username: str, client_ip: str, account: Account | None = None
    ) -> datetime | None:
        now = self._clock.now()
        account = account or self._account(username)
        with self._db.session() as session:
            row = session.get(LoginFailure, self._failure_key(username, client_ip, account))
            if row is not None and row.locked_until is not None and row.locked_until > now:
                return row.locked_until
        return None

    def _register_failure(
        self, username: str, client_ip: str, account: Account | None
    ) -> datetime | None:
        sec = self._cfg.security
        now = self._clock.now()
        key = self._failure_key(username, client_ip, account)
        with self._db.session(write=True) as session:
            row = session.get(LoginFailure, key)
            if row is None:
                row = LoginFailure(
                    key=key, username=username[:32], failures=0, window_started_at=now
                )
                session.add(row)
            if now - row.window_started_at > timedelta(minutes=sec.login_window_minutes):
                row.failures, row.window_started_at = 0, now
            row.failures += 1
            if row.failures >= sec.login_max_failures:
                row.locked_until = now + timedelta(minutes=sec.login_lockout_minutes)
                row.failures = 0
                record_audit(
                    session,
                    now,
                    username[:32],
                    "login_locked",
                    username[:32],
                    "denied",
                    ip=client_ip,
                )
            return row.locked_until

    def _clear_failures(self, username: str, client_ip: str, account: Account | None) -> None:
        with self._db.session(write=True) as session:
            row = session.get(LoginFailure, self._failure_key(username, client_ip, account))
            if row is not None:
                session.delete(row)

    @staticmethod
    def clear_lockouts(session: Session, username: str) -> None:
        """Every lockout of ``username``: the child's own, or the parent's per-address ones."""
        session.execute(
            delete(LoginFailure).where(
                (LoginFailure.key == f"user:{username}"[:96])
                | LoginFailure.key.like(f"parent:{username}:%")
            )
        )

    def locked_children(self) -> list[tuple[str, datetime]]:
        """Child accounts currently locked out, for the parental reset control."""
        now = self._clock.now()
        with self._db.session() as session:
            rows = session.scalars(
                select(LoginFailure).where(
                    LoginFailure.key.like("user:%"), LoginFailure.locked_until > now
                )
            ).all()
            return [(r.username, r.locked_until) for r in rows if r.locked_until]

    def reset_lockout(self, username: str, actor: str) -> bool:
        with self._db.session(write=True) as session:
            row = session.get(LoginFailure, f"user:{username}"[:96])
            if row is None:
                return False
            session.delete(row)
            record_audit(session, self._clock.now(), actor, "lockout_reset", username)
            return True

    # -- verify credentials without creating a session (sibling check) -----------------

    def verify_child_credentials(self, child_id: str, password: str, client_ip: str) -> bool:
        """Check a child's password (e.g. sibling joining a TV). Failures count toward lockout."""
        username = self._cfg.children[child_id].username
        account = self._account(username)
        if account is not None and account.child_id != child_id:
            account = None
        return self.verify_password(username, password, client_ip, account)

    def verify_password(
        self, username: str, password: str, client_ip: str, account: Account | None = None
    ) -> bool:
        """Check a password for an account without signing in (sibling checks, re-authentication).

        A locked account fails without a verify. Failures count toward the lockout, exactly as
        a failed login does, so this cannot be used to guess around it.
        """
        if account is None:
            account = self._account(username)
        if self.lockout_for(username, client_ip, account) is not None:
            return False
        ok = self.passwords.verify(account.password_hash if account else None, password)
        if ok and account is not None:
            self._clear_failures(username, client_ip, account)
            self._rehash_if_needed(account, password)
        else:
            self._register_failure(username, client_ip, account)
        return ok

    def _rehash_if_needed(self, account: Account, password: str) -> None:
        """Bring a hash made with other Argon2 parameters up to ``security.password_hash``."""
        if not self.passwords.needs_rehash(account.password_hash):
            return
        new_hash = self.passwords.hash(password)
        with self._db.session(write=True) as session:
            session.execute(
                update(User)
                .where(
                    User.username == account.username,
                    User.password_hash == account.password_hash,  # not if it changed meanwhile
                )
                .values(password_hash=new_hash)
            )
            record_audit(
                session, self._clock.now(), "system", "password_rehashed", account.username
            )

    # -- login / sessions -------------------------------------------------------------

    def login(self, username: str, password: str, client_ip: str) -> LoginResult:
        username = username.strip().lower()[:32]
        account = self._account(username)
        locked = self.lockout_for(username, client_ip, account)
        if locked is not None:
            self._audit_login(username, "denied", client_ip, "locked")
            return LoginResult(
                False, message="Too many attempts. Ask a parent to unlock you.", locked_until=locked
            )
        valid = len(password) <= PASSWORD_MAX_LENGTH and self.passwords.verify(
            account.password_hash if account else None, password
        )
        if account is None or not valid:
            locked = self._register_failure(username, client_ip, account)
            self._audit_login(username, "denied", client_ip, "bad credentials")
            return LoginResult(
                False, message="That username or password is not right.", locked_until=locked
            )
        self._clear_failures(username, client_ip, account)
        self._rehash_if_needed(account, password)
        cookie, principal = self.issue_session(account, client_ip, event="login")
        return LoginResult(True, cookie=cookie, principal=principal)

    def issue_session(
        self, account: Account, client_ip: str, *, event: str
    ) -> tuple[str, Principal]:
        """A new server-side session (rotation: a fresh id every time). Returns the cookie.

        Older sessions for this user stay valid only until their own expiry (a child may use
        several devices), unless a password change revoked them.
        """
        now = self._clock.now()
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        expires = now + timedelta(minutes=self._cfg.security.session_ttl_minutes)
        with self._db.session(write=True) as session:
            session.execute(delete(WebSession).where(WebSession.expires_at < now))
            session.add(
                WebSession(
                    token_hash=self._hash_token(token),
                    username=account.username,
                    role=account.role,
                    child_id=account.child_id,
                    csrf_token=csrf,
                    created_at=now,
                    expires_at=expires,
                )
            )
            record_audit(session, now, account.username, event, account.username, ip=client_ip)
        principal = Principal(account.username, account.role, account.child_id, csrf)
        return self._sign(token), principal

    def _audit_login(self, username: str, result: str, ip: str, why: str) -> None:
        with self._db.session(write=True) as session:
            record_audit(
                session,
                self._clock.now(),
                username or "unknown",
                "login",
                username,
                result,
                ip=ip,
                why=why,
            )

    def resolve(self, cookie: str | None) -> Principal | None:
        if not cookie:
            return None
        token = self._unsign(cookie)
        if token is None:
            return None
        now = self._clock.now()
        with self._db.session() as session:
            row = session.get(WebSession, self._hash_token(token))
            if row is None or row.expires_at <= now:
                return None
            user = session.scalars(select(User).where(User.username == row.username)).first()
            if user is None or not user.enabled or user.role != row.role:
                return None
            return Principal(row.username, row.role, row.child_id, row.csrf_token)

    def logout(self, cookie: str | None) -> None:
        if not cookie:
            return
        token = self._unsign(cookie)
        if token is None:
            return
        with self._db.session(write=True) as session:
            session.execute(
                delete(WebSession).where(WebSession.token_hash == self._hash_token(token))
            )

    @staticmethod
    def revoke_sessions(session: Session, username: str) -> None:
        session.execute(delete(WebSession).where(WebSession.username == username))
