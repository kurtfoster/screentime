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
from app.resources import TICK_LAG_WARN_SECONDS, LagTracker
from app.runtime import run_sync

log = logging.getLogger("screentime.app")

TICK_SECONDS = 5.0  # spec: at least every 10 seconds
MAINTENANCE_SECONDS = 3600.0
RESOURCE_SAMPLE_SECONDS = 60.0


class Scheduler:
    def __init__(
        self,
        orchestrator: Orchestrator,
        resolver: EducationResolver,
        config: AppConfig,
        maintenance: Callable[[], None] | None = None,
        *,
        tick_seconds: float = TICK_SECONDS,
        reconcile_seconds: float | None = None,
        tick_lag: LagTracker | None = None,
        sample_resources: Callable[[], object] | None = None,
    ) -> None:
        self.tick_lag = tick_lag or LagTracker()
        self._sample_resources = sample_resources
        self._last_lag_warning = float("-inf")
        self._tick_seconds = tick_seconds
        self._reconcile_seconds = reconcile_seconds
        self._orch = orchestrator
        self._resolver = resolver
        self._cfg = config
        self._maintenance = maintenance
        self._tasks: list[asyncio.Task[None]] = []

    def _record_tick_lag(self, started: float, intended: float) -> None:
        lag = started - intended
        self.tick_lag.record(started, lag)
        if lag > TICK_LAG_WARN_SECONDS and started - self._last_lag_warning >= 60:
            self._last_lag_warning = started  # at most one warning a minute
            log.warning(
                "timer tick ran %.1f s late (threshold %.0f s): the CPU is overloaded",
                lag,
                TICK_LAG_WARN_SECONDS,
            )

    async def _loop(
        self, name: str, work: Callable[[], Awaitable[object]], interval: Callable[[], float]
    ) -> None:
        clock = asyncio.get_running_loop().time
        intended: float | None = None
        while True:
            started = clock()
            if name == "tick" and intended is not None:
                self._record_tick_lag(started, intended)
            try:
                await work()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("scheduler loop %s iteration failed", name)
            delay = interval()
            intended = started + delay  # tick start to tick start, so slow work counts as lag
            await asyncio.sleep(delay)

    async def _reconcile(self) -> None:
        try:
            await self._orch.enforcement.reconcile()
        except Exception as exc:  # already logged loudly by the enforcement service
            log.debug("periodic reconcile failed: %s", exc)

    async def _housekeeping(self) -> None:
        if self._maintenance is not None:
            await run_sync(self._maintenance)

    async def _resources(self) -> None:
        if self._sample_resources is not None:
            await run_sync(self._sample_resources)

    def start(self) -> None:
        if self._tasks:
            return
        fw = self._cfg.firewall
        loops = [
            ("tick", lambda: self._orch.tick(), lambda: self._tick_seconds),
            (
                "reconcile",
                self._reconcile,
                lambda: self._reconcile_seconds or float(fw.reconcile_seconds),
            ),
            ("education", self._resolver.refresh, self._resolver.next_interval_seconds),
            ("housekeeping", self._housekeeping, lambda: MAINTENANCE_SECONDS),
            ("resources", self._resources, lambda: RESOURCE_SAMPLE_SECONDS),
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
