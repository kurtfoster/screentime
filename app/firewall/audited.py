"""Decorator that records every firewall operation (spec section 21) and tracks contact health."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import TypeVar

from app.clock import Clock
from app.db import Database
from app.firewall.base import FirewallAdapter, FirewallError, FirewallHealth
from app.models import FirewallEvent
from app.runtime import run_sync

log = logging.getLogger("screentime.firewall")
T = TypeVar("T")


class AuditedFirewall:
    """Wraps any adapter. Mutating calls are always stored; reads are stored only on failure."""

    def __init__(self, inner: FirewallAdapter, db: Database, clock: Clock, mode: str) -> None:
        self.inner = inner
        self.mode = mode
        self._db = db
        self._clock = clock
        self.last_success_at: datetime | None = None
        self.last_error: str | None = None
        self.last_error_at: datetime | None = None

    def _store(self, action: str, target: str, ok: bool, started: float, error: str) -> None:
        elapsed = int((time.monotonic() - started) * 1000)
        try:
            with self._db.session(write=True) as session:
                session.add(
                    FirewallEvent(
                        timestamp=self._clock.now(),
                        action=action,
                        target=target[:200],
                        success=ok,
                        command_summary=f"{self.mode}:{action}",
                        duration_ms=elapsed,
                        error_text=error[:1000],
                    )
                )
        except Exception:
            log.exception("could not persist firewall event action=%s", action)

    async def _call(
        self,
        action: str,
        target: str,
        fn: Callable[[], Awaitable[T]],
        *,
        store_success: bool = True,
    ) -> T:
        started = time.monotonic()
        try:
            result = await fn()
        except Exception as exc:
            message = str(exc) or exc.__class__.__name__
            self.last_error, self.last_error_at = message, self._clock.now()
            log.error("firewall action=%s target=%s ok=false error=%s", action, target, message)
            await run_sync(self._store, action, target, False, started, message)
            if isinstance(exc, FirewallError):
                raise
            raise FirewallError(message) from exc
        self.last_success_at = self._clock.now()
        self.last_error = None
        elapsed = int((time.monotonic() - started) * 1000)
        log.info("firewall action=%s target=%s ok=true duration_ms=%d", action, target, elapsed)
        if store_success:
            await run_sync(self._store, action, target, True, started, "")
        return result

    async def health(self) -> FirewallHealth:
        started = time.monotonic()
        result = await self.inner.health()
        if result.ok:
            self.last_success_at = self._clock.now()
            self.last_error = None
        else:
            self.last_error, self.last_error_at = result.detail, self._clock.now()
            await run_sync(self._store, "health", "", False, started, result.detail)
        return result

    async def get_active_ips(self) -> set[str]:
        return await self._call(
            "get_active_ips", "", self.inner.get_active_ips, store_success=False
        )

    async def replace_active_ips(self, ips: set[str]) -> None:
        await self._call(
            "replace_active_ips", ",".join(sorted(ips)), lambda: self.inner.replace_active_ips(ips)
        )

    async def add_active_ip(self, ip: str) -> None:
        await self._call("add_active_ip", ip, lambda: self.inner.add_active_ip(ip))

    async def remove_active_ip(self, ip: str) -> None:
        await self._call("remove_active_ip", ip, lambda: self.inner.remove_active_ip(ip))

    async def kill_states(self, ip: str) -> None:
        await self._call("kill_states", ip, lambda: self.inner.kill_states(ip))

    async def replace_education_ips(self, ips: set[str]) -> None:
        await self._call(
            "replace_education_ips",
            f"{len(ips)} addresses",
            lambda: self.inner.replace_education_ips(ips),
        )
