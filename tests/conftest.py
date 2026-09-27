"""Shared fixtures. All tests run against a temporary SQLite file and a FakeClock."""

from __future__ import annotations

import copy
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from app.audit import configure_logging
from app.bootstrap import sync_reference_data
from app.clock import FakeClock, LogicalCalendar
from app.config import AppConfig, UserCfg
from app.db import Database
from app.firewall.dry_run import DryRunFirewallAdapter
from app.sessions import SessionService

MELBOURNE = ZoneInfo("Australia/Melbourne")
MONDAY = date(2026, 9, 21)  # a weekday, before the October DST change
SATURDAY = date(2026, 9, 26)

# Valid Argon2id hash of the password "correct horse" (generated once; see test_auth).
ARGON_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$"
    "Gg5sNwUqGxQ1oS4m2mVn5ZcQmC0m5Xk3mJm4qZ3v8pM"
)

BASE_CONFIG: dict[str, Any] = {
    "timezone": "Australia/Melbourne",
    "logical_day_reset": "02:00",
    "children": {
        "child8": {
            "display_name": "Child 8",
            "username": "child8",
            "weekday_allowance_minutes": 120,
            "weekend_allowance_minutes": 180,
            "weekday_earliest_start": "09:00",
            "owned_devices": ["ipad"],
            "permitted_shared_devices": ["kids_tv", "lounge_tv"],
        },
        "child12": {
            "display_name": "Child 12",
            "username": "child12",
            "weekday_allowance_minutes": 120,
            "weekend_allowance_minutes": 180,
            "weekday_earliest_start": "09:00",
            "owned_devices": ["iphone_child12"],
            "permitted_shared_devices": ["kids_tv", "lounge_tv"],
        },
    },
    "devices": {
        "ipad": {
            "display_name": "iPad",
            "ip": "192.168.12.30",
            "type": "personal",
            "owner": "child8",
            "education_allowlist": True,
        },
        "iphone_child12": {
            "display_name": "iPhone",
            "ip": "192.168.12.31",
            "type": "personal",
            "owner": "child12",
            "education_allowlist": True,
        },
        "kids_tv": {
            "display_name": "Kids TV",
            "ip": "192.168.12.40",
            "type": "shared_tv",
            "weekday_cutoff": "18:30",
        },
        "lounge_tv": {"display_name": "Lounge TV", "ip": "192.168.12.41", "type": "shared_tv"},
    },
    "sessions": {
        "default_minutes": 30,
        "child_choices_minutes": [15, 30, 60],
        "child_extension_minutes": 15,
        "warning_minutes": 5,
        "max_concurrent_devices_per_child": 1,
        "stop_returns_unused_reserved_time": True,
    },
    "parents": {
        "tv_session_choices_minutes": [15, 30, 60],
        "allow_until_stopped": True,
        "allowance_grants_minutes": [15, 30, 60],
        "grants_override_all_child_restrictions": True,
        "until_stopped_end_at_logical_day_reset": True,
    },
    "always_allowed": {
        "duolingo": {
            "enabled": True,
            "domains": ["www.duolingo.com", "d35aaqx5ub95lt.cloudfront.net"],
        },
        "khan_academy": {"enabled": True, "domains": ["www.khanacademy.org"]},
        "sora_school": {"enabled": True, "domains": []},
    },
    "firewall": {"mode": "dry_run", "reconcile_seconds": 30, "education_dns_refresh_seconds": 300},
    "notifications": {
        "browser_push_enabled": False,
        "warning_minutes": 5,
        "parent_notifications_enabled": True,
    },
    "security": {"secure_cookies": False, "enforce_file_modes": False},
}


class Replace(dict[str, Any]):
    """Marker: use this dict instead of merging it into the base section."""


def make_config(tmp_path: Path | None = None, **overrides: Any) -> AppConfig:
    """Build a config from BASE_CONFIG; dict overrides are merged unless wrapped in Replace."""
    raw = copy.deepcopy(BASE_CONFIG)
    for key, value in overrides.items():
        if (
            isinstance(value, dict)
            and not isinstance(value, Replace)
            and isinstance(raw.get(key), dict)
        ):
            raw[key].update(value)
        else:
            raw[key] = value
    if tmp_path is not None:
        raw["storage"] = {"data_dir": str(tmp_path / "data")}
    return AppConfig.model_validate(raw)


def at(hour: int, minute: int = 0, day: date = MONDAY, second: int = 0) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, second, tzinfo=MELBOURNE)


@dataclass
class Env:
    config: AppConfig
    db: Database
    clock: FakeClock
    calendar: LogicalCalendar
    service: SessionService
    firewall: DryRunFirewallAdapter
    tmp_path: Path

    def set(self, hour: int, minute: int = 0, day: date = MONDAY, second: int = 0) -> datetime:
        self.clock.set(at(hour, minute, day, second))
        return self.clock.now()


@pytest.fixture
def anyio_backend() -> str:
    """The app runs on asyncio under uvicorn. Older anyio plugins (Debian) also try trio."""
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def _capturable_app_logging() -> None:
    """Install the app's log handler once, but let records reach pytest's caplog as well.

    configure_logging() stops propagation so journald sees each line once. Older pytest
    releases (Debian Trixie ships 8.3) only capture through the root logger.
    """
    configure_logging()
    logging.getLogger("screentime").propagate = True


@pytest.fixture(autouse=True)
def _dispose_databases(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Close every SQLite engine a test opened so no connections leak between tests."""
    created: list[Database] = []
    original = Database.__init__

    def tracking(self: Database, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        created.append(self)

    monkeypatch.setattr(Database, "__init__", tracking)
    yield
    for db in created:
        db.dispose()


def build_env(tmp_path: Path, start: datetime | None = None, **config_overrides: Any) -> Env:
    config = make_config(tmp_path, **config_overrides)
    db = Database(tmp_path / "data" / "test.db")
    db.upgrade()
    users = {
        "child8": UserCfg(role="child", child_id="child8", password_hash=ARGON_HASH),
        "child12": UserCfg(role="child", child_id="child12", password_hash=ARGON_HASH),
        "parents": UserCfg(role="parent", password_hash=ARGON_HASH),
    }
    with db.session(write=True) as session:
        sync_reference_data(session, config, users)
    clock = FakeClock(start or at(10, 0))
    calendar = LogicalCalendar(config.zone, config.logical_day_reset)
    service = SessionService(db, config, calendar, clock)
    return Env(config, db, clock, calendar, service, DryRunFirewallAdapter(), tmp_path)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return build_env(tmp_path)
