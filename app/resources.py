"""Resource and timing evidence for the diagnostics page and ``admin_cli.py status``.

A Raspberry Pi 1 has little headroom, so the decision to keep or replace it should rest on
measurements, not opinion (Pi1_Adaptation_Plan.md section 9.3). The service samples these
figures every minute, logs a warning when a threshold is crossed, and writes a small 0600
JSON snapshot that the admin CLI (a separate process) can read.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.clock import Clock
from app.db import Database

log = logging.getLogger("screentime.resources")

LOW_MEMORY_MB = 64
TICK_LAG_WARN_SECONDS = 5.0
STATUS_FILE = "status.json"
BACKUP_STATUS_FILE = "backup-status.json"
THROTTLED_SYSFS = Path("/sys/devices/platform/soc/soc:firmware/get_throttled")

# Bits of the firmware's get_throttled value (Raspberry Pi documentation, vcgencmd).
_THROTTLE_BITS = {
    0: "under-voltage now",
    1: "ARM frequency capped now",
    2: "throttled now",
    3: "soft temperature limit now",
    16: "under-voltage has occurred since boot",
    17: "ARM frequency capping has occurred",
    18: "throttling has occurred",
    19: "soft temperature limit has occurred",
}


class LagTracker:
    """How late the timer tick runs: actual minus intended interval, kept for one hour."""

    def __init__(self, window_seconds: float = 3600.0) -> None:
        self._window = window_seconds
        self._samples: deque[tuple[float, float]] = deque()

    def record(self, now: float, lag: float) -> None:
        self._samples.append((now, max(0.0, lag)))
        while self._samples and now - self._samples[0][0] > self._window:
            self._samples.popleft()

    def max_lag(self) -> float | None:
        return max((lag for _, lag in self._samples), default=None)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def process_memory_mb(status: Path = Path("/proc/self/status")) -> tuple[int | None, int | None]:
    """Resident memory now and its high-water mark since start (VmRSS, VmHWM)."""
    values: dict[str, int] = {}
    for line in (_read(status) or "").splitlines():
        key, _, rest = line.partition(":")
        if key in ("VmRSS", "VmHWM") and rest.split():
            values[key] = int(rest.split()[0]) // 1024
    return values.get("VmRSS"), values.get("VmHWM")


def available_memory_mb(meminfo: Path = Path("/proc/meminfo")) -> int | None:
    for line in (_read(meminfo) or "").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    return None


def load_average() -> tuple[float, float, float] | None:
    try:
        return os.getloadavg()
    except OSError:
        return None


def throttle_flags(
    sysfs: Path = THROTTLED_SYSFS,
    run: Callable[[list[str]], str | None] | None = None,
) -> list[str] | None:
    """Decoded under-voltage/throttling flags, [] when clean, None when not a Raspberry Pi.

    The firmware's sysfs attribute works inside the hardened service (PrivateDevices hides
    /dev/vcio, which ``vcgencmd`` needs); ``vcgencmd`` is the fallback for the admin CLI.
    """
    raw = _read(sysfs)
    if raw is None:
        raw = (run or _vcgencmd)(["vcgencmd", "get_throttled"])
        if raw is None:
            return None
        raw = raw.strip().removeprefix("throttled=")
    try:
        value = int(raw.strip(), 16)
    except ValueError:
        return None
    return [text for bit, text in _THROTTLE_BITS.items() if value & (1 << bit)]


def _vcgencmd(argv: list[str]) -> str | None:
    if shutil.which(argv[0]) is None:
        return None
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False)  # noqa: S603
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def read_backup_status(directory: Path) -> dict[str, Any] | None:
    """Written by deploy/backup.sh after every run (it runs as a separate systemd unit)."""
    raw = _read(directory / BACKUP_STATUS_FILE)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


@dataclass
class ResourceSnapshot:
    taken_at: str
    rss_mb: int | None
    peak_rss_mb: int | None
    available_mb: int | None
    load: tuple[float, float, float] | None
    tick_lag_max_seconds: float | None
    pfsense_fetch_age_seconds: int | None  # pull mode: seconds since pfSense last fetched
    argon2_verify_seconds: float | None
    clock_synchronised: bool
    throttling: list[str] | None
    backup: dict[str, Any] | None

    @property
    def low_memory(self) -> bool:
        return self.available_mb is not None and self.available_mb < LOW_MEMORY_MB

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def lines(self) -> list[tuple[str, str]]:
        """(label, value) rows shared by the diagnostics page and the admin CLI."""

        def num(value: float | None, unit: str, fmt: str = "{:.0f}") -> str:
            return "n/a" if value is None else fmt.format(value) + unit

        backup = "never recorded"
        if self.backup:
            result = self.backup.get("result", "unknown")
            backup = f"{result} at {self.backup.get('at', '?')}"
            if result != "ok":
                backup += f" ({self.backup.get('detail', '')}); last success {self.backup.get('last_success_at') or 'never'}"
        if self.throttling is None:
            throttling = "not available (not a Raspberry Pi?)"
        else:
            throttling = ", ".join(self.throttling) or "none"
        return [
            ("App memory (RSS / peak)", f"{num(self.rss_mb, ' MB')} / {num(self.peak_rss_mb, ' MB')}"),
            ("System memory available", num(self.available_mb, " MB") + (" LOW" if self.low_memory else "")),
            ("Load average (1/5/15 min)", "n/a" if self.load is None else " / ".join(f"{v:.2f}" for v in self.load)),
            ("Timer tick lag (max, last hour)", num(self.tick_lag_max_seconds, " s", "{:.1f}")),
            ("pfSense last fetch", "n/a" if self.pfsense_fetch_age_seconds is None else f"{self.pfsense_fetch_age_seconds} s ago"),
            ("Last password check", num(self.argon2_verify_seconds, " s", "{:.2f}")),
            ("Clock synchronised", "yes" if self.clock_synchronised else "NO"),
            ("Under-voltage / throttling", throttling),
            ("Last backup", backup),
        ]  # fmt: skip


class ResourceMonitor:
    def __init__(
        self,
        db: Database,
        clock: Clock,
        tick_lag: LagTracker,
        status_dir: Path,
        backup_status_dir: Path,
        *,
        clock_synchronised: Callable[[], bool],
        last_verify_seconds: Callable[[], float | None],
        last_pfsense_fetch: Callable[[], datetime | None] = lambda: None,
    ) -> None:
        self._last_pfsense_fetch = last_pfsense_fetch
        self._db = db
        self._clock = clock
        self._tick_lag = tick_lag
        self.status_file = status_dir / STATUS_FILE
        self._backup_dir = backup_status_dir
        self._clock_synchronised = clock_synchronised
        self._last_verify_seconds = last_verify_seconds

    def snapshot(self) -> ResourceSnapshot:
        now = self._clock.now()
        fetched = self._last_pfsense_fetch()
        rss, peak = process_memory_mb()
        return ResourceSnapshot(
            taken_at=now.isoformat(timespec="seconds"),
            rss_mb=rss,
            peak_rss_mb=peak,
            available_mb=available_memory_mb(),
            load=load_average(),
            tick_lag_max_seconds=self._tick_lag.max_lag(),
            pfsense_fetch_age_seconds=(
                None if fetched is None else int((now - fetched).total_seconds())
            ),
            argon2_verify_seconds=self._last_verify_seconds(),
            clock_synchronised=self._clock_synchronised(),
            throttling=throttle_flags(),
            backup=read_backup_status(self._backup_dir),
        )

    def sample(self) -> ResourceSnapshot:
        """Periodic sample: warn on thresholds and publish the snapshot for the admin CLI."""
        snap = self.snapshot()
        if snap.low_memory:
            log.warning(
                "available memory is low: %s MB (threshold %d MB)", snap.available_mb, LOW_MEMORY_MB
            )
        if snap.throttling and any(flag.endswith("now") for flag in snap.throttling):
            log.warning("raspberry pi firmware reports: %s", ", ".join(snap.throttling))
        try:
            self.status_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.status_file.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(snap.to_json())
            os.replace(tmp, self.status_file)
        except OSError as exc:
            log.warning("could not write %s: %s", self.status_file, exc)
        return snap


def load_status_file(path: Path) -> dict[str, Any] | None:
    raw = _read(path)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None
