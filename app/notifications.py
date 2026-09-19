"""Notification abstraction (spec section 15).

Durable notification rows are created by the timer engine; this service delivers them.
In-app state is served by the pages themselves and never depends on push succeeding.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select

from app.clock import Clock
from app.config import AppConfig
from app.db import Database
from app.models import NotificationEvent, PushSubscription
from app.push import PushError, PushGone, PushSender
from app.runtime import run_sync
from app.secrets_store import fernet_key

log = logging.getLogger("screentime.push")

_B64_RE = re.compile(r"^[A-Za-z0-9_-]{8,256}={0,2}$")
MAX_FAILURES = 10


class SubscriptionError(ValueError):
    pass


class Notifier:
    def __init__(
        self,
        db: Database,
        config: AppConfig,
        clock: Clock,
        secret: bytes,
        sender: PushSender | None,
        public_key: str | None = None,
    ) -> None:
        self._db = db
        self._cfg = config
        self._clock = clock
        self._fernet = Fernet(fernet_key(secret, "push-subscriptions"))
        self._sender = sender
        self.public_key = public_key

    @property
    def enabled(self) -> bool:
        return self._cfg.notifications.browser_push_enabled and self._sender is not None

    # -- subscriptions ----------------------------------------------------------------

    def subscribe(self, username: str, role: str, endpoint: str, keys: dict[str, Any]) -> None:
        if not endpoint.startswith("https://") or len(endpoint) > 1024:
            raise SubscriptionError("endpoint must be an https URL")
        p256dh, auth = keys.get("p256dh"), keys.get("auth")
        if not (
            isinstance(p256dh, str)
            and isinstance(auth, str)
            and _B64_RE.match(p256dh)
            and _B64_RE.match(auth)
        ):
            raise SubscriptionError("invalid subscription keys")
        token = self._fernet.encrypt(json.dumps({"p256dh": p256dh, "auth": auth}).encode()).decode()
        with self._db.session(write=True) as session:
            row = session.scalar(
                select(PushSubscription).where(PushSubscription.endpoint == endpoint)
            )
            if row is None:
                row = PushSubscription(endpoint=endpoint, created_at=self._clock.now())
                session.add(row)
            row.username, row.role, row.keys_encrypted, row.failure_count = username, role, token, 0

    def unsubscribe(self, username: str, endpoint: str) -> None:
        with self._db.session(write=True) as session:
            row = session.scalar(
                select(PushSubscription).where(
                    PushSubscription.endpoint == endpoint, PushSubscription.username == username
                )
            )
            if row is not None:
                session.delete(row)

    # -- delivery ---------------------------------------------------------------------

    def _load_pending(self) -> list[tuple[NotificationEvent, list[tuple[int, dict[str, Any]]]]]:
        out: list[tuple[NotificationEvent, list[tuple[int, dict[str, Any]]]]] = []
        with self._db.session() as session:
            events = session.scalars(
                select(NotificationEvent)
                .where(NotificationEvent.dispatched_at.is_(None))
                .order_by(NotificationEvent.id)
                .limit(50)
            ).all()
            for event in events:
                targets: list[tuple[int, dict[str, Any]]] = []
                if self.enabled:
                    stmt = select(PushSubscription)
                    if event.audience == "parent":
                        stmt = stmt.where(PushSubscription.role == "parent")
                    elif event.child_id and event.child_id in self._cfg.children:
                        stmt = stmt.where(
                            PushSubscription.username == self._cfg.children[event.child_id].username
                        )
                    else:
                        stmt = stmt.where(PushSubscription.id < 0)
                    for sub in session.scalars(stmt):
                        try:
                            keys = json.loads(self._fernet.decrypt(sub.keys_encrypted.encode()))
                        except (InvalidToken, ValueError):
                            log.warning("dropping undecryptable push subscription id=%s", sub.id)
                            continue
                        targets.append((sub.id, {"endpoint": sub.endpoint, "keys": keys}))
                out.append((event, targets))
        return out

    def _finish(self, event_id: int, results: dict[int, str], now: datetime) -> None:
        with self._db.session(write=True) as session:
            event = session.get(NotificationEvent, event_id)
            if event is not None:
                event.dispatched_at = now
            for sub_id, outcome in results.items():
                sub = session.get(PushSubscription, sub_id)
                if sub is None:
                    continue
                if outcome == "ok":
                    sub.last_success_at, sub.failure_count = now, 0
                elif outcome == "gone":
                    session.delete(sub)
                else:
                    sub.failure_count += 1
                    if sub.failure_count >= MAX_FAILURES:
                        session.delete(sub)

    async def dispatch_pending(self) -> int:
        pending = await run_sync(self._load_pending)
        for event, targets in pending:
            results: dict[int, str] = {}
            payload = {
                "title": event.title,
                "body": event.body,
                "kind": event.kind,
                "url": "/parent" if event.audience == "parent" else "/child",
                "tag": event.dedupe_key,
            }
            for sub_id, info in targets:
                assert self._sender is not None
                try:
                    await run_sync(self._sender.send, info, payload)
                    results[sub_id] = "ok"
                except PushGone:
                    results[sub_id] = "gone"
                except PushError as exc:
                    log.warning("push delivery failed sub=%s: %s", sub_id, exc)
                    results[sub_id] = "error"
                except Exception:
                    log.exception("unexpected push failure sub=%s", sub_id)
                    results[sub_id] = "error"
            await run_sync(self._finish, event.id, results, self._clock.now())
        return len(pending)
