"""In-process asyncio scheduler (spec section 17). No Redis, no Celery.

Three independent loops: the timer tick (expiry, warnings, cutoffs), the firewall
reconcile loop (also heals a pf filter reload that wiped table edits), and the
education DNS refresh. A failure in one iteration is logged and never stops the loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable

from app.config import AppConfig
from app.firewall.resolver import EducationResolver
from app.orchestrator import Orchestrator
from app.runtime import run_sync

log = logging.getLogger("screentime.app")

TICK_SECONDS = 5.0  # spec: at least every 10 seconds
MAINTENANCE_SECONDS = 3600.0


class Scheduler:
    def __init__(
        self,
        orchestrator: Orchestrator,
        resolver: EducationResolver,
        config: AppConfig,
        maintenance: Callable[[], None] | None = None,
    ) -> None:
        self._orch = orchestrator
        self._resolver = resolver
        self._cfg = config
        self._maintenance = maintenance
        self._tasks: list[asyncio.Task[None]] = []

    async def _loop(
        self, name: str, work: Callable[[], Awaitable[object]], interval: Callable[[], float]
    ) -> None:
        while True:
            try:
                await work()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("scheduler loop %s iteration failed", name)
            await asyncio.sleep(interval())

    async def _reconcile(self) -> None:
        try:
            await self._orch.enforcement.reconcile()
        except Exception as exc:  # already logged loudly by the enforcement service
            log.debug("periodic reconcile failed: %s", exc)

    async def _housekeeping(self) -> None:
        if self._maintenance is not None:
            await run_sync(self._maintenance)

    def start(self) -> None:
        if self._tasks:
            return
        fw = self._cfg.firewall
        loops = [
            ("tick", lambda: self._orch.tick(), lambda: TICK_SECONDS),
            ("reconcile", self._reconcile, lambda: float(fw.reconcile_seconds)),
            ("education", self._resolver.refresh, self._resolver.next_interval_seconds),
            ("housekeeping", self._housekeeping, lambda: MAINTENANCE_SECONDS),
        ]
        for name, work, interval in loops:
            self._tasks.append(asyncio.create_task(self._loop(name, work, interval), name=name))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()
