"""Argon2id password hashing sized for a single-core Raspberry Pi (spec section 19).

Parameters are always explicit: argon2-cffi's defaults differ between releases (64 MiB with
p=4 in 25.x, 100 MiB with p=8 in 21.1). They come from ``security.password_hash`` and cannot
go below the OWASP minimum. Verification runs one at a time across the process, because on
one core parallel verifies only multiply memory and none finishes sooner.

This module imports argon2 but not the web or database stack, so the command-line tools can
use it cheaply.
"""

from __future__ import annotations

import secrets
import threading
import time

from argon2 import PasswordHasher, Type

# InvalidHash exists in argon2-cffi 21.1 (Raspberry Pi OS) and is an alias of InvalidHashError in 23+.
from argon2.exceptions import InvalidHash, VerificationError

from app.config import PasswordHashCfg

_VERIFY_SLOT = threading.BoundedSemaphore(1)


class PasswordHashing:
    def __init__(self, cfg: PasswordHashCfg | None = None) -> None:
        self.cfg = cfg or PasswordHashCfg()
        self._hasher = PasswordHasher(
            time_cost=self.cfg.time_cost,
            memory_cost=self.cfg.memory_kib,
            parallelism=self.cfg.parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._dummy: str | None = None
        self.last_verify_seconds: float | None = None

    def hash(self, password: str) -> str:
        return str(self._hasher.hash(password))  # argon2-cffi 21.1 is untyped

    def verify(self, stored_hash: str | None, password: str) -> bool:
        """Check a password. ``None`` (unknown user) still costs one verify, so timing is equal.

        The dummy hash is created on first use rather than at import, so neither the
        ``--check-config`` pre-start nor the service start pays for a hash.
        """
        with _VERIFY_SLOT:
            if stored_hash is None and self._dummy is None:
                self._dummy = self.hash(secrets.token_urlsafe(16))
            target = stored_hash if stored_hash is not None else self._dummy
            assert target is not None
            started = time.perf_counter()
            try:
                ok = bool(self._hasher.verify(target, password))
            except (VerificationError, InvalidHash):
                ok = False
            self.last_verify_seconds = time.perf_counter() - started
        return ok and stored_hash is not None


_default = PasswordHashing()


def hash_password(password: str) -> str:
    """Hash with the default (OWASP minimum) parameters. Tools that load config use PasswordHashing."""
    return _default.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    return _default.verify(stored_hash, password)
