"""Resource evidence (CHG-11): parsing, thresholds and the snapshot file."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.resources import (
    LagTracker,
    ResourceSnapshot,
    available_memory_mb,
    load_status_file,
    percentile_95,
    process_memory_mb,
    read_backup_status,
    throttle_flags,
)


def test_process_and_system_memory_are_read_from_proc(tmp_path: Path) -> None:
    status = tmp_path / "status"
    status.write_text("Name:\tpython3\nVmHWM:\t  98304 kB\nVmRSS:\t   81920 kB\n")
    assert process_memory_mb(status) == (80, 96)
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal:  485376 kB\nMemFree: 1000 kB\nMemAvailable:  307200 kB\n")
    assert available_memory_mb(meminfo) == 300
    assert available_memory_mb(tmp_path / "missing") is None
    rss, peak = process_memory_mb()  # the real /proc on Linux
    assert rss is not None and peak is not None and peak >= rss


def test_throttle_flags_decode_the_firmware_bits(tmp_path: Path) -> None:
    sysfs = tmp_path / "get_throttled"
    sysfs.write_text("50005\n")
    assert throttle_flags(sysfs) == [
        "under-voltage now",
        "throttled now",
        "under-voltage has occurred since boot",
        "throttling has occurred",
    ]
    sysfs.write_text("0\n")
    assert throttle_flags(sysfs) == []


def test_throttle_flags_fall_back_to_vcgencmd_or_report_unavailable(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    assert throttle_flags(missing, run=lambda argv: "throttled=0x10000\n") == [
        "under-voltage has occurred since boot"
    ]
    assert throttle_flags(missing, run=lambda argv: None) is None
    assert throttle_flags(missing, run=lambda argv: "garbage") is None


def test_percentile_uses_nearest_rank() -> None:
    assert percentile_95([]) is None
    assert percentile_95([7]) == 7
    assert percentile_95(range(1, 101)) == 95
    assert percentile_95([10] * 19 + [900]) == 10


def test_lag_tracker_keeps_one_hour() -> None:
    tracker = LagTracker(window_seconds=3600)
    assert tracker.max_lag() is None
    tracker.record(0.0, 12.0)
    tracker.record(10.0, -0.2)  # early wake-ups count as zero
    assert tracker.max_lag() == 12.0
    tracker.record(3700.0, 1.5)
    assert tracker.max_lag() == 1.5


def test_backup_status_tolerates_missing_and_corrupt_files(tmp_path: Path) -> None:
    assert read_backup_status(tmp_path) is None
    (tmp_path / "backup-status.json").write_text("{not json")
    assert read_backup_status(tmp_path) is None
    (tmp_path / "backup-status.json").write_text(json.dumps({"result": "ok", "at": "t"}))
    assert read_backup_status(tmp_path) == {"result": "ok", "at": "t"}


def snapshot(**changes: object) -> ResourceSnapshot:
    values: dict[str, object] = {
        "taken_at": "2026-09-27T10:00:00+00:00",
        "rss_mb": 72,
        "peak_rss_mb": 95,
        "available_mb": 290,
        "load": (0.31, 0.25, 0.2),
        "tick_lag_max_seconds": 0.4,
        "ssh_p95_ms": 120,
        "ssh_operations": 40,
        "argon2_verify_seconds": 1.41,
        "clock_synchronised": True,
        "throttling": [],
        "backup": {"result": "ok", "at": "2026-09-27T03:15:00+10:00"},
    }
    values.update(changes)
    return ResourceSnapshot(**values)  # type: ignore[arg-type]


def test_snapshot_rows_are_readable() -> None:
    rows = dict(snapshot().lines())
    assert rows["App memory (RSS / peak)"] == "72 MB / 95 MB"
    assert rows["Timer tick lag (max, last hour)"] == "0.4 s"
    assert rows["pfSense SSH p95 (last hour)"] == "120 ms over 40 operations"
    assert rows["Last password check"] == "1.41 s"
    assert rows["Under-voltage / throttling"] == "none"
    low = dict(
        snapshot(
            available_mb=50,
            throttling=None,
            clock_synchronised=False,
            backup={
                "result": "failed",
                "at": "x",
                "detail": "not a mount point",
                "last_success_at": None,
            },
            tick_lag_max_seconds=None,
        ).lines()
    )
    assert low["System memory available"] == "50 MB LOW"
    assert low["Clock synchronised"] == "NO"
    assert "not available" in low["Under-voltage / throttling"]
    assert low["Last backup"] == "failed at x (not a mount point); last success never"
    assert low["Timer tick lag (max, last hour)"] == "n/a"


def test_status_file_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "status.json"
    path.write_text(snapshot().to_json())
    data = load_status_file(path)
    assert data is not None and data["argon2_verify_seconds"] == 1.41
    assert load_status_file(tmp_path / "missing.json") is None


@pytest.mark.parametrize("content", ["[]", "{bad"])
def test_status_file_must_be_an_object(tmp_path: Path, content: str) -> None:
    path = tmp_path / "status.json"
    path.write_text(content)
    assert load_status_file(path) is None
