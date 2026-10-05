"""Fail-open and "pfSense not checking in" alerts for parents (plan 6.5, D13).

pfSense sends no alerts (D13). This controller is the only alert channel, and it can only
infer what pfSense is doing from whether pfSense keeps fetching:

* **Not checking in** (live): no fetch for ``firewall.degraded_after_seconds``.
* **Fail-open probable** (live): no fetch for the grace period, so pfSense has probably
  allowed every device. "Probably": the controller cannot see pfSense.
* **Fail-open happened** (after the event): pfSense reports the episode once contact
  resumes (``last-failopen``); it stays on the dashboard until a parent dismisses it.

While this controller itself is off, nothing can alert anyone. Its own outages are detected
from a heartbeat at the next start and shown until pfSense acknowledges again.

Each change of state and each episode is written to the audit log and queued as a parent
notification, so parents with alerts on also get a push. Children never see any of this.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from sqlalchemy import select

from app.audit import record_audit
from app.clock import Clock, LogicalCalendar
from app.config import AppConfig
from app.db import Database
from app.firewall.protocol import Acknowledgement
from app.firewall.pull import PullFirewallAdapter
from app.models import FailopenEpisode, Meta
from app.notifications import queue_parent_notification

log = logging.getLogger("screentime.firewall")

LiveState = Literal["ok", "not_checking_in", "failopen_probable"]
# A second report whose start lies this close to a stored episode is the same episode.
SAME_EPISODE = timedelta(seconds=120)
HEARTBEAT_KEY = "heartbeat_at"


@dataclass(frozen=True)
class Banner:
    level: Literal["warn", "danger"]
    text: str
    episode_id: int | None = None  # dismissible when set


class FirewallAlerts:
    def __init__(
        self,
        db: Database,
        config: AppConfig,
        clock: Clock,
        calendar: LogicalCalendar,
        pull: PullFirewallAdapter,
    ) -> None:
        self._db = db
        self._cfg = config
        self._clock = clock
        self._cal = calendar
        self._pull = pull
        self._state: LiveState = "ok"
        # This controller's own last outage: (last heartbeat before it, start after it).
        self.outage: tuple[datetime, datetime] | None = None

    # -- what pfSense said about itself ------------------------------------------------

    def grace(self) -> timedelta:
        report = self._pull.report
        seconds = (
            report.stale[0] if report and report.stale else self._cfg.firewall.stale_grace_seconds
        )
        return timedelta(seconds=seconds)

    def fails_open(self) -> bool:
        """pfSense's STALE_POLICY: open unless it has reported ``closed``."""
        report = self._pull.report
        return not (report and report.stale and report.stale[1] == "closed")

    # -- live state ---------------------------------------------------------------------

    def live(self, now: datetime) -> tuple[LiveState, datetime]:
        """The live state and the time it is measured from (the last fetch, or start-up)."""
        reference = self._pull.last_fetch_at or self._pull.started_at
        age = now - reference
        if age >= self.grace():
            return "failopen_probable", reference
        if age >= timedelta(seconds=self._cfg.firewall.degraded_after_seconds):
            return "not_checking_in", reference
        return "ok", reference

    def _fmt(self, when: datetime, now: datetime) -> str:
        same_day = self._cal.local(when).date() == self._cal.local(now).date()
        return self._cal.format_local(when, "%H:%M" if same_day else "%a %d %b %H:%M")

    def _live_text(self, state: LiveState, reference: datetime, now: datetime) -> str:
        consequence = (
            "every device is allowed and the curfew is off"
            if self.fails_open()
            else "every device is switched off"
        )
        if state == "not_checking_in":
            minutes = int((now - reference).total_seconds() // 60)
            limit = int(self.grace().total_seconds() // 60)
            return (
                f"pfSense has not checked in for {minutes} min. "
                f"If this reaches {limit} min, {consequence}."
            )
        since = self._fmt(reference + self.grace(), now)
        probable = (
            "every device is probably allowed and the curfew is off"
            if self.fails_open()
            else "every device is probably switched off"
        )
        return f"Since {since} {probable}. pfSense cannot reach the screen-time controller."

    def banners(self, now: datetime) -> list[Banner]:
        out: list[Banner] = []
        state, reference = self.live(now)
        if state != "ok":
            level: Literal["warn", "danger"] = "warn" if state == "not_checking_in" else "danger"
            out.append(Banner(level, self._live_text(state, reference, now)))
        report = self._pull.report
        if state == "ok" and report is not None and report.mode == "fail-open":
            out.append(
                Banner(
                    "danger",
                    "pfSense reports that every device is allowed right now (fail-open): it "
                    "cannot use the controller's desired state.",
                )
            )
        if self.outage is not None and not self._acknowledged_since_start():
            down, up = self.outage
            out.append(
                Banner(
                    "warn",
                    f"The controller was off from {self._fmt(down, now)} to {self._fmt(up, now)}; "
                    "pfSense will confirm whether devices were opened.",
                )
            )
        for episode in self.open_episodes():
            minutes = max(1, round((episode.ended_at - episode.started_at).total_seconds() / 60))
            out.append(
                Banner(
                    "danger",
                    f"Every device was allowed from {self._fmt(episode.started_at, now)} to "
                    f"{self._fmt(episode.ended_at, now)} ({minutes} min), including during curfew.",
                    episode.id,
                )
            )
        return out

    def _acknowledged_since_start(self) -> bool:
        last = self._pull.last_ack_at
        return last is not None and last > self._pull.started_at

    # -- changes: audit and notify -------------------------------------------------------

    def update(self, now: datetime) -> None:
        """Record each change of live state once (called every minute by the scheduler)."""
        state, reference = self.live(now)
        if state == self._state:
            return
        previous, self._state = self._state, state
        titles = {
            "not_checking_in": "pfSense is not checking in",
            "failopen_probable": (
                "Every device is probably allowed"
                if self.fails_open()
                else "pfSense is not checking in"
            ),
            "ok": "pfSense is checking in again",
        }
        body = (
            self._live_text(state, reference, now)
            if state != "ok"
            else "The controller is back in control of the devices."
        )
        log.warning("firewall live state %s -> %s (last fetch %s)", previous, state, reference)
        with self._db.session(write=True) as session:
            record_audit(
                session, now, "system", f"firewall_{state}", "pfsense",
                "ok" if state == "ok" else "error", since=reference.isoformat(), previous=previous,
            )  # fmt: skip
            queue_parent_notification(
                session, self._cfg, now, kind=f"firewall_{state}", title=titles[state],
                body=body, dedupe=f"fw-live:{state}:{reference.isoformat()}",
            )  # fmt: skip

    def record_failopen(self, report: Acknowledgement, received_at: datetime) -> int | None:
        """Store the episode in ``last-failopen`` once; returns its id when it is new."""
        if report.last_failopen is None:
            return None
        started_ago, duration = report.last_failopen
        started = received_at - timedelta(seconds=started_ago)
        ended = started + timedelta(seconds=duration)
        with self._db.session(write=True) as session:
            same = session.scalars(
                select(FailopenEpisode).where(
                    FailopenEpisode.started_at > started - SAME_EPISODE,
                    FailopenEpisode.started_at < started + SAME_EPISODE,
                )
            ).first()
            if same is not None:
                return None
            episode = FailopenEpisode(started_at=started, ended_at=ended, reported_at=received_at)
            session.add(episode)
            session.flush()
            minutes = max(1, round(duration / 60))
            text = (
                f"Every device was allowed from {self._fmt(started, received_at)} to "
                f"{self._fmt(ended, received_at)} ({minutes} min), including during curfew."
            )
            record_audit(
                session, received_at, "pfsense", "failopen_episode", f"episode:{episode.id}",
                "error", started=started.isoformat(), ended=ended.isoformat(),
            )  # fmt: skip
            queue_parent_notification(
                session, self._cfg, received_at, kind="firewall_failopen_episode",
                title="pfSense allowed every device", body=text,
                dedupe=f"fw-episode:{episode.id}",
            )  # fmt: skip
            log.critical("pfSense reported a fail-open episode: %s", text)
            return episode.id

    def open_episodes(self) -> list[FailopenEpisode]:
        with self._db.session() as session:
            return list(
                session.scalars(
                    select(FailopenEpisode)
                    .where(FailopenEpisode.dismissed_at.is_(None))
                    .order_by(FailopenEpisode.started_at)
                )
            )

    def dismiss(self, episode_id: int, actor: str) -> bool:
        now = self._clock.now()
        with self._db.session(write=True) as session:
            episode = session.get(FailopenEpisode, episode_id)
            if episode is None or episode.dismissed_at is not None:
                return False
            episode.dismissed_at, episode.dismissed_by = now, actor[:32]
            record_audit(session, now, actor, "failopen_dismissed", f"episode:{episode_id}")
            return True

    # -- this controller's own outages ---------------------------------------------------

    def heartbeat(self, now: datetime) -> None:
        """Note that the controller is up (every minute, and at a clean stop)."""
        with self._db.session(write=True) as session:
            row = session.get(Meta, HEARTBEAT_KEY)
            if row is None:
                session.add(Meta(key=HEARTBEAT_KEY, value=now.isoformat()))
            else:
                row.value = now.isoformat()

    def on_start(self, now: datetime) -> None:
        """Detect an outage of this controller longer than the grace period."""
        with self._db.session() as session:
            row = session.get(Meta, HEARTBEAT_KEY)
        last = datetime.fromisoformat(row.value) if row is not None else None
        if last is not None and now - last > self.grace():
            self.outage = (last, now)
            with self._db.session(write=True) as session:
                record_audit(
                    session, now, "system", "controller_outage", "screentime", "error",
                    down=last.isoformat(), up=now.isoformat(),
                )  # fmt: skip
            log.warning("the controller was off from %s to %s", last, now)
        self.heartbeat(now)


def drift(config: AppConfig, report: Acknowledgement | None, published: int | None) -> list[str]:
    """Differences between config.yaml and what pfSense reports (C9). Empty means none."""
    if report is None:
        return ["pfSense has not acknowledged anything yet"]
    problems: list[str] = []
    if report.stale is None:
        problems.append("pfSense does not report its grace period (update the applier)")
    elif report.stale[0] != config.firewall.stale_grace_seconds:
        problems.append(
            f"firewall.stale_grace_seconds is {config.firewall.stale_grace_seconds} here but "
            f"STALE_GRACE is {report.stale[0]} on pfSense"
        )
    if report.known is None:
        problems.append("pfSense does not report its device map (update the applier)")
    else:
        for device_id, device in config.devices.items():
            kind = "personal" if device.type == "personal" else "tv"
            if device_id not in report.known:
                problems.append(
                    f"{device_id} is not in pfSense's device map: pfSense rejects every "
                    "desired state that includes it"
                )
            elif report.known[device_id] != (device.ip, kind):
                ip, their_kind = report.known[device_id]
                problems.append(
                    f"{device_id} is {device.ip} ({kind}) here but {ip} ({their_kind}) on pfSense"
                )
        for device_id in sorted(set(report.known) - set(config.devices)):
            problems.append(f"{device_id} is in pfSense's device map but not in config.yaml")
    unknown = sorted(report.device_ids - set(config.devices))
    if unknown:
        problems.append(f"pfSense has leases for unknown devices: {', '.join(unknown)}")
    if published is not None and report.generation != published:
        problems.append(
            f"pfSense last applied generation {report.generation}; this controller has published "
            f"{published} (a lag of one poll is normal)"
        )
    return problems
