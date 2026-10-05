"""Publication of the desired firewall state (spec sections 12-13, v1.2 plan 6).

The database decides which devices should be on; this service turns that into a
:class:`DesiredState` (devices with leases) and publishes it. The firewall applies the whole
state at once, revokes devices that left it and kills their connections, then acknowledges.
A publication failure flips the enforcement-degraded flag, which blocks new child starts.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select

from app.clock import AssumeSynchronised, Clock, ClockSync, LogicalCalendar
from app.config import AppConfig
from app.db import Database
from app.firewall.audited import AuditedFirewall
from app.firewall.base import AppliedState, DesiredState, FirewallError
from app.models import NotificationEvent
from app.runtime import run_sync
from app.state import desired_leases

log = logging.getLogger("screentime.firewall")


@dataclass(frozen=True)
class PublishResult:
    generation: int
    desired: DesiredState


class EnforcementService:
    def __init__(
        self,
        db: Database,
        config: AppConfig,
        clock: Clock,
        calendar: LogicalCalendar,
        firewall: AuditedFirewall,
        clock_sync: ClockSync | None = None,
    ) -> None:
        self._db = db
        self._clock_sync = clock_sync or AssumeSynchronised()
        self._last_sync_state: bool | None = None
        self._cfg = config
        self._clock = clock
        self._cal = calendar
        self.firewall = firewall
        self._lock = asyncio.Lock()
        self.degraded = False
        self.degraded_since: datetime | None = None
        self.last_publish_at: datetime | None = None
        self.last_success_at: datetime | None = None
        self.last_error: str | None = None
        self.desired_state = DesiredState()
        self.applied_state: AppliedState | None = None

    @property
    def desired(self) -> set[str]:
        """Addresses that should be on (diagnostics)."""
        return set(self.desired_state.ips)

    @property
    def actual(self) -> set[str] | None:
        """Addresses the firewall last acknowledged, or None before any acknowledgement."""
        if self.applied_state is None:
            return None
        return self.ips_for_devices(self.applied_state.device_ids)

    def clock_synchronised(self) -> bool:
        """Whether the system clock can be trusted; logs each change of state once."""
        synced = self._clock_sync.synchronised()
        if synced != self._last_sync_state:
            if synced:
                log.info("system clock synchronised: grants and child starts are enabled")
            else:
                log.warning(
                    "system clock not yet synchronised: no device will be granted and child "
                    "starts are refused until NTP succeeds"
                )
            self._last_sync_state = synced
        return synced

    def ips_for_devices(self, device_ids: Iterable[str]) -> set[str]:
        return {self._cfg.devices[d].ip for d in device_ids if d in self._cfg.devices}

    async def publish(self) -> PublishResult:
        """Publish the desired state now. Raises :class:`FirewallError` if that cannot be done."""
        async with self._lock:
            now = self._clock.now()
            self.last_publish_at = now
            # With an untrusted clock, sessions that really ended can look current, so grant
            # nothing at all (fail closed) until the clock is synchronised.
            desired = (
                await run_sync(self._read_desired, now)
                if self.clock_synchronised()
                else DesiredState()
            )
            self.desired_state = desired
            try:
                generation = await self.firewall.publish(desired)
            except FirewallError as exc:
                await self._mark_degraded(str(exc), now)
                raise
            self.applied_state = await self.firewall.applied()
            await self._mark_healthy(now)
            return PublishResult(generation, desired)

    def _read_desired(self, now: datetime) -> DesiredState:
        next_reset = self._cal.day_start(self._cal.logical_day(now) + timedelta(days=1))
        with self._db.session() as session:
            return desired_leases(session, now, next_reset, self._cfg.firewall.max_lease_seconds)

    async def _mark_degraded(self, error: str, now: datetime) -> None:
        self.last_error = error
        if not self.degraded:
            self.degraded = True
            self.degraded_since = now
            log.critical("enforcement degraded: cannot reach pfSense (%s)", error)
            await run_sync(
                self._notify_parents,
                f"enforcement-failed:{now.isoformat()}",
                "Screen-time enforcement is degraded",
                "The controller cannot reach pfSense. New child sessions are blocked until it recovers.",
                "enforcement_failure",
                now,
            )
        else:
            log.error("enforcement still degraded: %s", error)

    async def _mark_healthy(self, now: datetime) -> None:
        self.last_success_at = now
        if self.degraded:
            since = self.degraded_since
            self.degraded = False
            self.degraded_since = None
            self.last_error = None
            log.warning("enforcement recovered after outage starting %s", since)
            await run_sync(
                self._notify_parents,
                f"enforcement-recovered:{now.isoformat()}",
                "Screen-time enforcement recovered",
                "pfSense is reachable again and the firewall has been reconciled.",
                "enforcement_recovered",
                now,
            )

    def _notify_parents(self, dedupe: str, title: str, body: str, kind: str, now: datetime) -> None:
        if not self._cfg.notifications.parent_notifications_enabled:
            return
        with self._db.session(write=True) as session:
            if session.scalar(
                select(NotificationEvent.id).where(NotificationEvent.dedupe_key == dedupe)
            ):
                return
            session.add(
                NotificationEvent(
                    kind=kind,
                    audience="parent",
                    dedupe_key=dedupe,
                    title=title,
                    body=body,
                    created_at=now,
                )
            )
