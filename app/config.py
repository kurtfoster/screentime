"""YAML configuration and credential loading.

Everything the household can tune lives here. Loading is strict: unknown keys,
dangling references and malformed values raise :class:`ConfigError` listing every
problem at once, so the service refuses to start rather than run half-configured.
"""

from __future__ import annotations

import ipaddress
import re
import stat
from datetime import time
from pathlib import Path
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_ARGON2ID_RE = re.compile(
    r"^\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"
)
# OWASP Password Storage Cheat Sheet minimum for Argon2id (ASVS V2.4 defers to it).
ARGON2_MIN_MEMORY_KIB = 19456
ARGON2_MIN_TIME_COST = 2
_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TABLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")


class ConfigError(Exception):
    """Raised when configuration or credentials are invalid."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))

    def render(self) -> str:
        return "Invalid configuration:\n" + "\n".join(f"  - {p}" for p in self.problems)


def parse_hhmm(value: Any) -> time:
    """Parse a quoted "HH:MM" string. Unquoted YAML sexagesimals arrive as ints and are rejected."""
    if isinstance(value, time):
        return value
    if not isinstance(value, str):
        raise ValueError(f'must be a quoted "HH:MM" string, got {value!r}')
    match = re.fullmatch(r"([01]\d|2[0-3]):([0-5]\d)", value.strip())
    if not match:
        raise ValueError(f'must be "HH:MM" in 24-hour time, got {value!r}')
    return time(int(match.group(1)), int(match.group(2)))


HHMM = Annotated[time, BeforeValidator(parse_hhmm)]
Minutes = Annotated[int, Field(gt=0, le=24 * 60)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChildCfg(_Strict):
    display_name: str = Field(min_length=1, max_length=40)
    username: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,31}$")
    weekday_allowance_minutes: int = Field(ge=0, le=24 * 60)
    weekend_allowance_minutes: int = Field(ge=0, le=24 * 60)
    weekday_earliest_start: HHMM | None = None
    owned_devices: list[str] = Field(default_factory=list)
    permitted_shared_devices: list[str] = Field(default_factory=list)


class DeviceCfg(_Strict):
    display_name: str = Field(min_length=1, max_length=40)
    ip: str
    type: Literal["personal", "shared_tv"]
    owner: str | None = None
    education_allowlist: bool = False
    weekday_cutoff: HHMM | None = None
    enabled: bool = True

    @field_validator("ip")
    @classmethod
    def _valid_ipv4(cls, value: str) -> str:
        try:
            return str(ipaddress.IPv4Address(value))
        except ValueError as exc:
            raise ValueError(f"must be a valid IPv4 address, got {value!r}") from exc


class SessionsCfg(_Strict):
    default_minutes: Minutes = 30
    child_choices_minutes: list[Minutes] = Field(default_factory=lambda: [15, 30, 60], min_length=1)
    child_extension_minutes: Minutes = 15
    warning_minutes: Minutes = 5
    max_concurrent_devices_per_child: int = Field(default=1, ge=1, le=10)
    stop_returns_unused_reserved_time: bool = True

    @model_validator(mode="after")
    def _default_is_a_choice(self) -> SessionsCfg:
        if self.default_minutes not in self.child_choices_minutes:
            raise ValueError("default_minutes must be one of child_choices_minutes")
        if sorted(set(self.child_choices_minutes)) != self.child_choices_minutes:
            raise ValueError("child_choices_minutes must be unique and ascending")
        return self


class ParentsCfg(_Strict):
    tv_session_choices_minutes: list[Minutes] = Field(
        default_factory=lambda: [15, 30, 60], min_length=1
    )
    allow_until_stopped: bool = True
    allowance_grants_minutes: list[Minutes] = Field(
        default_factory=lambda: [15, 30, 60], min_length=1
    )
    grants_override_all_child_restrictions: bool = True
    until_stopped_end_at_logical_day_reset: bool = True


class ServiceCfg(_Strict):
    enabled: bool = True
    domains: list[str] = Field(default_factory=list)

    @field_validator("domains")
    @classmethod
    def _valid_hostnames(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in value:
            host = raw.strip().lower().rstrip(".")
            if "*" in host:
                raise ValueError(
                    f"{raw!r}: wildcards are not supported; list each hostname or subdomain explicitly"
                )
            if not _HOSTNAME_RE.match(host):
                raise ValueError(f"{raw!r} is not a valid hostname")
            cleaned.append(host)
        return cleaned


class FirewallCfg(_Strict):
    mode: Literal["dry_run", "pfsense_ssh"] = "dry_run"
    host: str = "192.168.12.1"
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str = "screentime"
    ssh_key_path: str = "/opt/screentime/.ssh/id_ed25519"
    ssh_known_hosts_path: str | None = None
    ssh_timeout_seconds: int = Field(default=10, ge=1, le=120)
    command: str = "/usr/local/sbin/screenctl"
    use_sudo: bool = True
    # Reuse one SSH connection for every wrapper call (ControlMaster). A new key exchange per
    # call costs about a second on a Raspberry Pi 1. Switch off if pfSense's sshd objects.
    ssh_multiplex: bool = True
    active_table: str = "SCR_ACTIVE"
    education_table: str = "SCR_EDU_ALLOW"
    reconcile_seconds: int = Field(default=30, ge=5, le=3600)
    education_dns_refresh_seconds: int = Field(default=300, ge=30, le=86400)
    include_ipv6_in_education: bool = True

    @field_validator("active_table", "education_table")
    @classmethod
    def _table_name(cls, value: str) -> str:
        if not _TABLE_RE.match(value):
            raise ValueError("must be a simple pf table name (letters, digits, underscore)")
        return value

    @field_validator("command", "host", "ssh_user")
    @classmethod
    def _no_shell_metacharacters(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_./:@-]+", value):
            raise ValueError("contains characters that are not allowed")
        return value


class NotificationsCfg(_Strict):
    browser_push_enabled: bool = True
    warning_minutes: Minutes | None = None
    parent_notifications_enabled: bool = True


class PasswordHashCfg(_Strict):
    """Argon2id cost. The default is the OWASP minimum: about 1.4 s per verify on a Pi 1."""

    memory_kib: int = Field(default=ARGON2_MIN_MEMORY_KIB, le=1024 * 1024)
    time_cost: int = Field(default=ARGON2_MIN_TIME_COST, le=20)
    parallelism: int = Field(default=1, ge=1, le=16)

    @model_validator(mode="after")
    def _not_below_owasp_minimum(self) -> PasswordHashCfg:
        if self.memory_kib < ARGON2_MIN_MEMORY_KIB or self.time_cost < ARGON2_MIN_TIME_COST:
            raise ValueError(
                f"password_hash must be at least memory_kib={ARGON2_MIN_MEMORY_KIB} and "
                f"time_cost={ARGON2_MIN_TIME_COST} (OWASP minimum for Argon2id)"
            )
        return self


class SecurityCfg(_Strict):
    secure_cookies: bool = True
    session_ttl_minutes: int = Field(default=720, ge=5, le=60 * 24 * 7)
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_window_minutes: int = Field(default=15, ge=1, le=1440)
    login_lockout_minutes: int = Field(default=15, ge=1, le=1440)
    grant_actions_per_minute: int = Field(default=20, ge=1, le=600)
    trusted_proxies: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])
    enforce_file_modes: bool = True
    password_hash: PasswordHashCfg = Field(default_factory=PasswordHashCfg)


class StorageCfg(_Strict):
    data_dir: Path = Path("/opt/screentime/data")
    database_path: Path | None = None

    @property
    def db_file(self) -> Path:
        return self.database_path or self.data_dir / "screentime.db"


class UiCfg(_Strict):
    # Dashboards poll quickly only near a session's end (warning and extension decisions);
    # otherwise slowly. Each poll costs a few hundred milliseconds of CPU on a Pi 1.
    poll_fast_seconds: int = Field(default=5, ge=2, le=60)
    poll_idle_seconds: int = Field(default=15, ge=2, le=300)

    @model_validator(mode="after")
    def _fast_is_faster(self) -> UiCfg:
        if self.poll_fast_seconds > self.poll_idle_seconds:
            raise ValueError("poll_fast_seconds must not exceed poll_idle_seconds")
        return self


class ClockCfg(_Strict):
    # Fail closed until the system clock is known to be right (no RTC on the Pi). Set false
    # only on development machines, where there is no systemd-timesyncd marker to read.
    require_sync: bool = True
    sync_marker: Path = Path("/run/systemd/timesync/synchronized")


class PushCfg(_Strict):
    vapid_subject: str = "mailto:admin@screen.home.arpa"
    vapid_key_file: Path | None = None
    # Subscription endpoints must be on one of these hosts or their subdomains, so a signed-in
    # user cannot make the controller send requests to arbitrary (LAN) addresses.
    allowed_endpoint_hosts: list[str] = Field(
        default_factory=lambda: [
            "web.push.apple.com",
            "fcm.googleapis.com",
            "updates.push.services.mozilla.com",
            "notify.windows.com",
        ],
        min_length=1,
    )

    @field_validator("allowed_endpoint_hosts")
    @classmethod
    def _valid_hosts(cls, value: list[str]) -> list[str]:
        cleaned = [raw.strip().lower().strip(".") for raw in value]
        for host in cleaned:
            if not _HOSTNAME_RE.match(host) or "." not in host:
                raise ValueError(f"{host!r} is not a valid push service host name")
        return cleaned


class AppConfig(_Strict):
    timezone: str = "Australia/Melbourne"
    logical_day_reset: HHMM = time(2, 0)
    children: dict[str, ChildCfg]
    devices: dict[str, DeviceCfg]
    sessions: SessionsCfg = Field(default_factory=SessionsCfg)
    parents: ParentsCfg = Field(default_factory=ParentsCfg)
    always_allowed: dict[str, ServiceCfg] = Field(default_factory=dict)
    firewall: FirewallCfg = Field(default_factory=FirewallCfg)
    notifications: NotificationsCfg = Field(default_factory=NotificationsCfg)
    security: SecurityCfg = Field(default_factory=SecurityCfg)
    storage: StorageCfg = Field(default_factory=StorageCfg)
    push: PushCfg = Field(default_factory=PushCfg)
    clock: ClockCfg = Field(default_factory=ClockCfg)
    ui: UiCfg = Field(default_factory=UiCfg)

    @field_validator("timezone")
    @classmethod
    def _known_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown timezone {value!r}") from exc
        return value

    @field_validator("children", "devices")
    @classmethod
    def _identifier_keys(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not value:
            raise ValueError("must define at least one entry")
        for key in value:
            if not _ID_RE.match(key):
                raise ValueError(f"id {key!r} must be lowercase letters, digits or underscores")
        return value

    @model_validator(mode="after")
    def _cross_references(self) -> AppConfig:
        problems: list[str] = []
        problems += self._check_children()
        problems += self._check_devices()
        if (
            self.notifications.warning_minutes is not None
            and self.notifications.warning_minutes != self.sessions.warning_minutes
        ):
            problems.append(
                "notifications.warning_minutes must equal sessions.warning_minutes "
                "(a single warning point is supported)"
            )
        if problems:
            raise ValueError("\n".join(problems))
        return self

    def _check_children(self) -> list[str]:
        problems: list[str] = []
        usernames: dict[str, str] = {}
        for child_id, child in self.children.items():
            if child.username in usernames:
                problems.append(
                    f"children.{child_id}.username duplicates children.{usernames[child.username]}"
                )
            usernames[child.username] = child_id
            for dev_id in child.permitted_shared_devices:
                device = self.devices.get(dev_id)
                if device is None:
                    problems.append(
                        f"children.{child_id}.permitted_shared_devices: unknown device {dev_id!r}"
                    )
                elif device.type != "shared_tv":
                    problems.append(
                        f"children.{child_id}.permitted_shared_devices lists {dev_id!r}, which is a "
                        f"personal device; only shared_tv devices may be listed (personal devices are "
                        f"usable by their owner only)"
                    )
            for dev_id in child.owned_devices:
                device = self.devices.get(dev_id)
                if device is None:
                    problems.append(f"children.{child_id}.owned_devices: unknown device {dev_id!r}")
                elif device.owner != child_id:
                    problems.append(
                        f"children.{child_id}.owned_devices lists {dev_id!r} but devices.{dev_id}.owner "
                        f"is {device.owner!r}"
                    )
        return problems

    def _check_devices(self) -> list[str]:
        problems: list[str] = []
        seen_ips: dict[str, str] = {}
        for dev_id, device in self.devices.items():
            if device.ip in seen_ips:
                problems.append(f"devices.{dev_id}.ip duplicates devices.{seen_ips[device.ip]}")
            seen_ips[device.ip] = dev_id
            if device.type == "personal":
                if device.owner is None:
                    problems.append(f"devices.{dev_id}: personal devices require an owner")
                elif device.owner not in self.children:
                    problems.append(f"devices.{dev_id}.owner: unknown child {device.owner!r}")
            elif device.owner is not None:
                problems.append(f"devices.{dev_id}: shared_tv devices must not have an owner")
        return problems

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @property
    def warning_minutes(self) -> int:
        return self.sessions.warning_minutes

    def devices_owned_by(self, child_id: str) -> list[str]:
        return [d for d, cfg in self.devices.items() if cfg.owner == child_id]

    def child_id_for_username(self, username: str) -> str | None:
        for child_id, child in self.children.items():
            if child.username == username:
                return child_id
        return None

    def education_hosts(self) -> dict[str, str]:
        """Map each enabled allowlist hostname to the service that listed it."""
        hosts: dict[str, str] = {}
        for service, cfg in self.always_allowed.items():
            if cfg.enabled:
                for domain in cfg.domains:
                    hosts.setdefault(domain, service)
        return hosts


def argon2_parameters(stored_hash: str) -> tuple[int, int, int] | None:
    """``(memory_kib, time_cost, parallelism)`` from an Argon2id hash string, without argon2."""
    match = _ARGON2ID_RE.match(stored_hash)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def hash_cost_problem(cfg: PasswordHashCfg, stored_hash: str) -> str | None:
    """Why a users.yaml hash should be regenerated with the configured parameters, if it should.

    Hashes carry their own parameters and keep verifying, so this is advice, not an error.
    """
    params = argon2_parameters(stored_hash)
    if params is None:
        return None
    memory, time_cost, parallelism = params
    label = f"m={memory},t={time_cost},p={parallelism}"
    if memory > cfg.memory_kib or time_cost > cfg.time_cost:
        return f"uses {label}, above the configured budget, so each login is slower than needed"
    if memory < cfg.memory_kib or time_cost < cfg.time_cost:
        return f"uses {label}, below the configured minimum"
    return None


class UserCfg(_Strict):
    role: Literal["child", "parent"]
    child_id: str | None = None
    password_hash: str

    @field_validator("password_hash")
    @classmethod
    def _argon2id_only(cls, value: str) -> str:
        if not _ARGON2ID_RE.match(value):
            raise ValueError(
                "must be an Argon2id hash; generate one with scripts/make_password_hash.py "
                "(placeholder values such as '$argon2id$...' are not accepted)"
            )
        return value


class UsersFile(_Strict):
    users: dict[str, UserCfg]


def _format_validation_error(exc: ValidationError, prefix: str = "") -> list[str]:
    problems: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"])
        msg = err["msg"].removeprefix("Value error, ")
        for line in msg.splitlines():
            problems.append(f"{prefix}{loc}: {line}" if loc else f"{prefix}{line}")
    return problems


def _read_yaml(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError([f"{path}: file not found"]) from exc
    except OSError as exc:
        raise ConfigError([f"{path}: cannot be read ({exc.strerror})"]) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError([f"{path}: invalid YAML ({exc})"]) from exc


def check_private_mode(path: Path) -> str | None:
    """Return a problem description if the file is readable by group or others."""
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    if mode & 0o077:
        return f"{path}: mode is {mode:04o}; secrets files must be 0600 (chmod 600 {path})"
    return None


def load_config(path: Path | str) -> AppConfig:
    path = Path(path)
    raw = _read_yaml(path)
    if not isinstance(raw, dict):
        raise ConfigError([f"{path}: top level must be a mapping"])
    try:
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc)) from exc


def load_users(path: Path | str, config: AppConfig) -> dict[str, UserCfg]:
    """Load users.yaml and cross-check it against the configured children."""
    path = Path(path)
    problems: list[str] = []
    if config.security.enforce_file_modes:
        mode_problem = check_private_mode(path)
        if mode_problem:
            problems.append(mode_problem)
    raw = _read_yaml(path)
    if not isinstance(raw, dict):
        raise ConfigError([f"{path}: top level must be a mapping"])
    try:
        users = UsersFile.model_validate(raw).users
    except ValidationError as exc:
        raise ConfigError(problems + _format_validation_error(exc)) from exc

    child_users: dict[str, str] = {}
    parents = 0
    for name, user in users.items():
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,31}", name):
            problems.append(f"users.{name}: username must be lowercase letters, digits, . _ -")
        if user.role == "parent":
            parents += 1
            if user.child_id is not None:
                problems.append(f"users.{name}: parent users must not have a child_id")
            continue
        if user.child_id is None or user.child_id not in config.children:
            problems.append(f"users.{name}: child_id {user.child_id!r} is not a configured child")
            continue
        if config.children[user.child_id].username != name:
            problems.append(
                f"users.{name}: username must match children.{user.child_id}.username "
                f"({config.children[user.child_id].username!r})"
            )
        if user.child_id in child_users:
            problems.append(
                f"users.{name}: child {user.child_id} already has user {child_users[user.child_id]}"
            )
        child_users[user.child_id] = name
    if parents == 0:
        problems.append("users: at least one parent user is required")
    for child_id in config.children:
        if child_id not in child_users:
            problems.append(f"users: no login defined for child {child_id!r}")
    if problems:
        raise ConfigError(problems)
    return users


def load_all(
    config_path: Path | str, users_path: Path | str
) -> tuple[AppConfig, dict[str, UserCfg]]:
    config = load_config(config_path)
    return config, load_users(users_path, config)
