"""Decorator that records every firewall operation (spec section 21) and tracks contact health."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Protocol, TypeVar, runtime_checkable

from app.clock import Clock
from app.db import Database
from app.firewall.base import (
    AppliedState,
    DesiredState,
    FirewallAdapter,
    FirewallError,
    FirewallHealth,
)
from app.models import FirewallEvent
from app.runtime import run_sync

log = logging.getLogger("screentime.firewall")
T = TypeVar("T")


@runtime_checkable
class EducationTable(Protocol):
    async def replace_education_ips(self, ips: set[str]) -> None: ...


class AuditedFirewall:
    """Wraps any adapter: failures and each new generation are stored as firewall events."""

    def __init__(self, inner: FirewallAdapter, db: Database, clock: Clock, mode: str) -> None:
        self.inner = inner
        self.mode = mode
        self._db = db
        self._clock = clock
        self.last_success_at: datetime | None = None
        self.last_error: str | None = None
        self.last_error_at: datetime | None = None
        self.last_generation: int | None = None
        self._health_ok = True

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

    async def publish(self, desired: DesiredState) -> int:
        """Publish; stored as a firewall event only when the generation changes (or it fails)."""
        started = time.monotonic()
        target = ",".join(sorted(desired.device_ids)) or "(none)"
        try:
            generation = await self.inner.publish(desired)
        except Exception as exc:
            message = str(exc) or exc.__class__.__name__
            self.last_error, self.last_error_at = message, self._clock.now()
            log.error("firewall action=publish target=%s ok=false error=%s", target, message)
            await run_sync(self._store, "publish", target, False, started, message)
            if isinstance(exc, FirewallError):
                raise
            raise FirewallError(message) from exc
        self.last_success_at = self._clock.now()
        self.last_error = None
        if generation != self.last_generation:
            self.last_generation = generation
            log.info("firewall action=publish generation=%d devices=%s", generation, target)
            await run_sync(
                self._store, "publish", f"generation {generation}: {target}", True, started, ""
            )
        return generation

    async def applied(self) -> AppliedState | None:
        return await self.inner.applied()

    async def health(self) -> FirewallHealth:
        started = time.monotonic()
        result = await self.inner.health()
        if result.ok:
            self.last_success_at = self._clock.now()
            self.last_error = None
        else:
            # Stored once per outage: health is checked on every publication.
            if self._health_ok:
                await run_sync(self._store, "health", "", False, started, result.detail)
            self.last_error, self.last_error_at = result.detail, self._clock.now()
        self._health_ok = result.ok
        return result

    async def replace_education_ips(self, ips: set[str]) -> None:
        """Transitional: the SSH and dry-run adapters still push the education table."""
        inner = self.inner
        if not isinstance(inner, EducationTable):
            return
        await self._call(
            "replace_education_ips",
            f"{len(ips)} addresses",
            lambda: inner.replace_education_ips(ips),
        )
