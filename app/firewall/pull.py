"""pfSense pulls the desired state from this controller (plan D1, 6.1, 6.3).

The controller holds no pfSense credential and never connects to it. ``publish`` only
records what pfSense should apply; pfSense fetches it once a minute from
``GET /firewall/v1/desired``, applies it with its own device map and clock, and reports what
it applied with ``POST /firewall/v1/applied``.

Health is "has pfSense fetched recently": the controller cannot see pfSense, only hear from
it. Before the first fetch after a restart, the time this process started stands in for it.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select

from app.clock import Clock
from app.db import Database
from app.firewall.base import AppliedState, DesiredState, FirewallHealth, GenerationSource
from app.firewall.protocol import Acknowledgement, render_desired
from app.models import FirewallAck


class PullFirewallAdapter:
    def __init__(
        self,
        db: Database,
        clock: Clock,
        generations: GenerationSource,
        degraded_after_seconds: int,
    ) -> None:
        self._db = db
        self._clock = clock
        self._generations = generations
        self._degraded_after = timedelta(seconds=degraded_after_seconds)
        self._publication: tuple[int, DesiredState] | None = None
        self.started_at = clock.now()
        self.last_fetch_at: datetime | None = None
        self._applied = self._load_latest_ack()

    def _load_latest_ack(self) -> AppliedState | None:
        with self._db.session() as session:
            row = session.scalars(
                select(FirewallAck).order_by(FirewallAck.id.desc()).limit(1)
            ).first()
        if row is None:
            return None
        return AppliedState(
            row.generation,
            row.mode,  # type: ignore[arg-type]  # validated before it was stored
            frozenset(filter(None, row.device_ids.split(","))),
            row.received_at,
        )

    # -- FirewallAdapter --------------------------------------------------------------

    async def publish(self, desired: DesiredState) -> int:
        generation = self._generations.next(desired.device_ids)
        self._publication = (generation, desired)
        return generation

    async def applied(self) -> AppliedState | None:
        return self._applied

    async def health(self) -> FirewallHealth:
        reference = self.last_fetch_at or self.started_at
        age = self._clock.now() - reference
        if age <= self._degraded_after:
            return FirewallHealth(ok=True, detail="pfSense is fetching")
        minutes = int(age.total_seconds() // 60)
        seen = "since this controller started" if self.last_fetch_at is None else ""
        return FirewallHealth(
            ok=False,
            detail=f"pfSense has not fetched the desired state for {minutes} min {seen}".strip(),
        )

    # -- used by the /firewall/v1 routes ------------------------------------------------

    def document(self) -> str:
        """The latest publication. The route publishes first, so one always exists by then."""
        if self._publication is None:
            raise RuntimeError("nothing has been published yet")
        generation, desired = self._publication
        return render_desired(generation, desired)

    def note_fetch(self, now: datetime) -> None:
        self.last_fetch_at = now

    def record_ack(self, ack: Acknowledgement, now: datetime) -> AppliedState:
        """Keep the acknowledgement; it is written to the database only when it changes."""
        applied = AppliedState(ack.generation, ack.mode, ack.device_ids, now)
        previous = self._applied
        if previous is None or (previous.generation, previous.mode, previous.device_ids) != (
            applied.generation,
            applied.mode,
            applied.device_ids,
        ):
            with self._db.session(write=True) as session:
                session.add(
                    FirewallAck(
                        received_at=now,
                        generation=ack.generation,
                        mode=ack.mode,
                        device_ids=",".join(sorted(ack.device_ids)),
                    )
                )
        self._applied = applied
        return applied
