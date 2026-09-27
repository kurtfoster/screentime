"""Application wiring: builds every service from configuration in one place."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete

from app.auth import AuthService, SlidingWindowLimiter
from app.bootstrap import sync_reference_data
from app.clock import (
    AssumeSynchronised,
    Clock,
    ClockSync,
    LogicalCalendar,
    SystemClock,
    TimesyncdMarker,
)
from app.config import AppConfig, UserCfg
from app.db import Database
from app.enforcement import EnforcementService
from app.firewall.audited import AuditedFirewall
from app.firewall.base import FirewallAdapter
from app.firewall.dry_run import DryRunFirewallAdapter
from app.firewall.pfsense_ssh import PfSenseSshFirewallAdapter
from app.firewall.resolver import DnsClient, EducationResolver
from app.models import FirewallEvent, WebSession
from app.notifications import Notifier
from app.orchestrator import Orchestrator
from app.policy import PolicyEngine
from app.push import PushSender
from app.secrets_store import load_or_create_secret
from app.sessions import SessionService
from app.timers import Scheduler
from app.views import ViewBuilder

log = logging.getLogger("screentime.app")


@dataclass
class AppContext:
    config: AppConfig
    users: dict[str, UserCfg]
    db: Database
    clock: Clock
    calendar: LogicalCalendar
    policy: PolicyEngine
    sessions: SessionService
    views: ViewBuilder
    firewall: AuditedFirewall
    enforcement: EnforcementService
    resolver: EducationResolver
    notifier: Notifier
    orchestrator: Orchestrator
    auth: AuthService
    scheduler: Scheduler
    action_limiter: SlidingWindowLimiter

    def maintenance(self) -> None:
        """Hourly housekeeping: expired web sessions and old firewall events."""
        now = self.clock.now()
        with self.db.session(write=True) as session:
            session.execute(delete(WebSession).where(WebSession.expires_at < now))
            session.execute(
                delete(FirewallEvent).where(FirewallEvent.timestamp < now - timedelta(days=30))
            )


def build_context(
    config: AppConfig,
    users: dict[str, UserCfg],
    *,
    adapter: FirewallAdapter | None = None,
    clock: Clock | None = None,
    dns: DnsClient | None = None,
    push_sender: PushSender | None = None,
    migrate: bool = True,
    enable_push: bool = True,
    clock_sync: ClockSync | None = None,
) -> AppContext:
    clock = clock or SystemClock()
    if clock_sync is None:
        clock_sync = (
            TimesyncdMarker(config.clock.sync_marker)
            if config.clock.require_sync
            else AssumeSynchronised()
        )
    calendar = LogicalCalendar(config.zone, config.logical_day_reset)
    db = Database(config.storage.db_file)
    if migrate:
        db.upgrade()
    with db.session(write=True) as session:
        sync_reference_data(session, config, users)
    secret = load_or_create_secret(config.storage.data_dir / "secret.key")

    if adapter is None:
        adapter = (
            PfSenseSshFirewallAdapter(config.firewall)
            if config.firewall.mode == "pfsense_ssh"
            else DryRunFirewallAdapter()
        )
    firewall = AuditedFirewall(adapter, db, clock, config.firewall.mode)

    public_key: str | None = None
    if push_sender is None and enable_push and config.notifications.browser_push_enabled:
        try:
            from app.push import VapidKeys, WebPushSender

            keys = VapidKeys(
                config.push.vapid_key_file or config.storage.data_dir / "vapid_private.pem"
            )
            push_sender = WebPushSender(
                keys, config.push.vapid_subject, config.push.allowed_endpoint_hosts
            )
            public_key = keys.public_key
        except Exception:
            log.exception("web push disabled: could not initialise VAPID keys")

    policy = PolicyEngine(config, calendar)
    sessions = SessionService(db, config, calendar, clock)
    enforcement = EnforcementService(db, config, clock, firewall, clock_sync)
    if dns is None:
        from app.firewall.resolver import DnsPythonClient

        dns = DnsPythonClient()
    resolver = EducationResolver(config, dns, firewall, clock)
    notifier = Notifier(db, config, clock, secret, push_sender, public_key)
    orchestrator = Orchestrator(db, config, clock, sessions, enforcement, notifier)
    ctx = AppContext(
        config=config,
        users=users,
        db=db,
        clock=clock,
        calendar=calendar,
        policy=policy,
        sessions=sessions,
        views=ViewBuilder(config, calendar, policy),
        firewall=firewall,
        enforcement=enforcement,
        resolver=resolver,
        notifier=notifier,
        orchestrator=orchestrator,
        auth=AuthService(db, config, users, clock, secret),
        scheduler=None,  # type: ignore[arg-type]  # assigned below (needs ctx.maintenance)
        action_limiter=SlidingWindowLimiter(config.security.grant_actions_per_minute),
    )
    ctx.scheduler = Scheduler(orchestrator, resolver, config, ctx.maintenance)
    return ctx
