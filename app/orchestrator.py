"""Async façade tying session commands to firewall reconciliation.

Rules enforced here (spec sections 3, 13, 18):

* Fail closed: a child start only succeeds once the firewall has actually granted
  access. If it cannot, the session is marked ``enforcement_failed`` and refunded.
* Commit first, then reconcile. The database is authoritative; pf follows.
* Revocations (stop, expiry, End-for-Today) reconcile *and* kill states, but a failure
  there never undoes the accounting; the reconcile loop keeps retrying.
"""

from __future__ import annotations

import logging
from datetime import datetime

from app.audit import record_audit
from app.clock import Clock
from app.config import AppConfig
from app.db import Database
from app.enforcement import EnforcementService
from app.firewall.base import FirewallError
from app.notifications import Notifier
from app.policy import Reason
from app.runtime import run_sync
from app.sessions import CommandResult, SessionService, TickResult

log = logging.getLogger("screentime.app")


class Orchestrator:
    def __init__(
        self,
        db: Database,
        config: AppConfig,
        clock: Clock,
        sessions: SessionService,
        enforcement: EnforcementService,
        notifier: Notifier,
    ) -> None:
        self.db = db
        self.cfg = config
        self.clock = clock
        self.sessions = sessions
        self.enforcement = enforcement
        self.notifier = notifier

    # -- helpers ----------------------------------------------------------------------

    async def _reconcile_quietly(self, ended_device_ids: set[str] | None = None) -> bool:
        kills = self.enforcement.ips_for_devices(ended_device_ids or ())
        try:
            await self.enforcement.reconcile(kill_ips=kills)
        except FirewallError:
            return False
        return True

    async def _grant_or_refund(self, res: CommandResult) -> CommandResult:
        """Reconcile after a start; on failure refund the new sessions and report honestly."""
        try:
            await self.enforcement.reconcile()
        except FirewallError as exc:
            ids = [s.id for s in res.sessions]
            await run_sync(self.sessions.mark_enforcement_failed, ids, str(exc))
            await self._reconcile_quietly()
            return CommandResult.fail(
                Reason.ENFORCEMENT_FAILED,
                "The Internet could not be switched on. You have not been charged. "
                "Ask a parent if this keeps happening.",
            )
        return res

    async def _degraded_gate(self, actor: str) -> CommandResult | None:
        if not self.enforcement.degraded:
            return None
        await self._reconcile_quietly()  # one quick attempt to recover before refusing
        if not self.enforcement.degraded:
            return None
        await run_sync(self._audit_denied, actor, "session_rejected", Reason.ENFORCEMENT_DEGRADED)
        return CommandResult.fail(
            Reason.ENFORCEMENT_DEGRADED,
            "Screen time can't start right now because the network controller is unavailable. "
            "Ask a parent for help.",
        )

    def _audit_denied(self, actor: str, event: str, reason: Reason) -> None:
        with self.db.session(write=True) as session:
            record_audit(session, self.clock.now(), actor, event, "", "denied", reason=reason)

    # -- child ------------------------------------------------------------------------

    async def start_child_session(
        self,
        child_id: str,
        device_id: str,
        minutes: int,
        *,
        participants: tuple[str, ...] = (),
        idempotency_key: str | None = None,
    ) -> CommandResult:
        gate = await self._degraded_gate(self.cfg.children[child_id].username)
        if gate is not None:
            return gate
        res = await run_sync(
            lambda: self.sessions.start_child_session(
                child_id,
                device_id,
                minutes,
                participants=participants,
                idempotency_key=idempotency_key,
            )
        )
        if not res.ok or res.duplicate:
            return res
        return await self._grant_or_refund(res)

    async def stop_session(
        self, session_id: int, *, actor: str, role: str, child_id: str | None = None
    ) -> CommandResult:
        res = await run_sync(
            lambda: self.sessions.stop_session(
                session_id, actor=actor, role=role, child_id=child_id
            )
        )
        if res.ok and not res.duplicate:
            await self._reconcile_quietly(res.ended_device_ids)
        return res

    async def extend_session(
        self, session_id: int, child_id: str, *, mode: str = "eligible"
    ) -> CommandResult:
        return await run_sync(lambda: self.sessions.extend_session(session_id, child_id, mode=mode))

    async def add_participant(
        self, session_id: int, requester_child_id: str, sibling_child_id: str
    ) -> CommandResult:
        return await run_sync(
            lambda: self.sessions.add_participant(session_id, requester_child_id, sibling_child_id)
        )

    # -- parent -----------------------------------------------------------------------

    async def parent_grant(
        self, child_id: str, minutes: int, actor: str, *, idempotency_key: str | None = None
    ) -> CommandResult:
        return await run_sync(
            lambda: self.sessions.parent_grant(
                child_id, minutes, actor, idempotency_key=idempotency_key
            )
        )

    async def end_today(self, child_id: str, actor: str) -> CommandResult:
        res = await run_sync(lambda: self.sessions.end_today(child_id, actor))
        if res.ok:
            await self._reconcile_quietly(res.ended_device_ids)
        return res

    async def clear_day_lock(self, child_id: str, actor: str) -> CommandResult:
        return await run_sync(lambda: self.sessions.clear_day_lock(child_id, actor))

    async def start_tv(
        self, device_id: str, minutes: int | None, actor: str, *, idempotency_key: str | None = None
    ) -> CommandResult:
        res = await run_sync(
            lambda: self.sessions.start_tv(
                device_id, minutes, actor, idempotency_key=idempotency_key
            )
        )
        if not res.ok or res.duplicate:
            return res
        return await self._grant_or_refund(res)

    async def revoke_override(self, override_id: int, actor: str) -> CommandResult:
        res = await run_sync(lambda: self.sessions.revoke_override(override_id, actor))
        if res.ok:
            await self._reconcile_quietly(res.ended_device_ids)
        return res

    # -- background -------------------------------------------------------------------

    async def tick(self, now: datetime | None = None) -> TickResult:
        """One timer pass: expire, warn, revoke, notify. Never raises on firewall trouble."""
        result = await run_sync(lambda: self.sessions.tick(now))
        if result.changed:
            await self._reconcile_quietly(result.ended_device_ids)
        try:
            await self.notifier.dispatch_pending()
        except Exception:
            log.exception("notification dispatch failed")
        return result

    async def startup(self) -> None:
        """Catch up everything that expired while down, then reconcile pf (spec 13.3)."""
        await self.tick()
        await self._reconcile_quietly()
