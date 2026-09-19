"""Idempotent reconciliation of pf's active table with the database (spec sections 12-13).

The database decides what *should* be enabled; this service makes the firewall match.
Revocations run first (the safety-critical direction), then state kills, then grants.
Any firewall failure flips the enforcement-degraded flag, which blocks new child starts.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select

from app.clock import Clock
from app.config import AppConfig
from app.db import Database
from app.firewall.audited import AuditedFirewall
from app.firewall.base import FirewallError
from app.models import NotificationEvent
from app.runtime import run_sync
from app.state import desired_active_ips

log = logging.getLogger("screentime.firewall")


@dataclass
class ReconcileResult:
    desired: set[str]
    added: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)
    killed: set[str] = field(default_factory=set)


class EnforcementService:
    def __init__(
        self, db: Database, config: AppConfig, clock: Clock, firewall: AuditedFirewall
    ) -> None:
        self._db = db
        self._cfg = config
        self._clock = clock
        self.firewall = firewall
        self._lock = asyncio.Lock()
        self._pending_kills: set[str] = set()
        self.degraded = False
        self.degraded_since: datetime | None = None
        self.last_reconcile_at: datetime | None = None
        self.last_success_at: datetime | None = None
        self.last_error: str | None = None
        self.desired: set[str] = set()
        self.actual: set[str] | None = None

    def ips_for_devices(self, device_ids: Iterable[str]) -> set[str]:
        return {self._cfg.devices[d].ip for d in device_ids if d in self._cfg.devices}

    async def reconcile(self, kill_ips: Iterable[str] = ()) -> ReconcileResult:
        """Converge pf on the desired set. Raises :class:`FirewallError` if that cannot be done."""
        async with self._lock:
            now = self._clock.now()
            self.last_reconcile_at = now
            desired = await run_sync(self._read_desired, now)
            self.desired = desired
            self._pending_kills |= set(kill_ips)
            result = ReconcileResult(desired=desired)
            try:
                current = await self.firewall.get_active_ips()
                for ip in sorted(current - desired):
                    await self.firewall.remove_active_ip(ip)
                    result.removed.add(ip)
                    self._pending_kills.add(ip)
                self._pending_kills -= desired
                for ip in sorted(self._pending_kills):
                    await self.firewall.kill_states(ip)
                    result.killed.add(ip)
                    self._pending_kills.discard(ip)
                for ip in sorted(desired - current):
                    await self.firewall.add_active_ip(ip)
                    result.added.add(ip)
            except FirewallError as exc:
                await self._mark_degraded(str(exc), now)
                raise
            self.actual = set(desired)
            await self._mark_healthy(now)
            return result

    def _read_desired(self, now: datetime) -> set[str]:
        with self._db.session() as session:
            return desired_active_ips(session, now)

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
