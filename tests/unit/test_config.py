"""Configuration and credential validation (spec section 6)."""

from __future__ import annotations

import copy
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from app.__main__ import main
from app.config import ConfigError, load_config, parse_hhmm
from tests.conftest import BASE_CONFIG, make_config

ROOT = Path(__file__).resolve().parents[2]


def write(tmp_path: Path, raw: dict[str, Any], name: str = "config.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(raw))
    return path


def bad(raw: dict[str, Any], tmp_path: Path) -> str:
    with pytest.raises(ConfigError) as exc:
        load_config(write(tmp_path, raw))
    return exc.value.render()


def mutated(mutate: Any) -> dict[str, Any]:
    raw = copy.deepcopy(BASE_CONFIG)
    mutate(raw)
    return raw


def test_example_and_dev_configs_are_valid() -> None:
    for name in ("config.example.yaml", "config.dev.yaml"):
        cfg = load_config(ROOT / "config" / name)
        assert set(cfg.children) == {"child8", "child12"}
        assert cfg.devices["kids_tv"].weekday_cutoff is not None


def test_example_config_matches_the_specification_defaults() -> None:
    cfg = load_config(ROOT / "config" / "config.example.yaml")
    assert (
        cfg.timezone == "Australia/Melbourne" and cfg.logical_day_reset.strftime("%H:%M") == "02:00"
    )
    assert cfg.children["child8"].weekday_allowance_minutes == 120
    assert cfg.children["child8"].weekend_allowance_minutes == 180
    assert cfg.sessions.child_choices_minutes == [15, 30, 60] and cfg.sessions.default_minutes == 30
    assert cfg.sessions.warning_minutes == 5 and cfg.sessions.max_concurrent_devices_per_child == 1
    fw = cfg.firewall
    assert fw.mode == "dry_run" and fw.host == "192.168.12.1" and fw.reconcile_seconds == 30
    assert (fw.max_lease_seconds, fw.ack_timeout_seconds) == (900, 150)
    assert (fw.degraded_after_seconds, fw.stale_grace_seconds) == (180, 600)
    assert cfg.parents.until_stopped_end_at_logical_day_reset is True


def test_defaults_and_derived_helpers() -> None:
    cfg = make_config()
    assert cfg.devices_owned_by("child8") == ["ipad"]
    assert (
        cfg.child_id_for_username("child12") == "child12" and cfg.child_id_for_username("x") is None
    )
    assert cfg.storage.db_file.name == "screentime.db"


@pytest.mark.parametrize("value", ["09:00", "00:00", "23:59"])
def test_time_parser_accepts_quoted_hhmm(value: str) -> None:
    assert parse_hhmm(value).strftime("%H:%M") == value


@pytest.mark.parametrize("value", ["9:00", "24:00", "09:60", "0900", 540, None, "noon"])
def test_time_parser_rejects_everything_else(value: Any) -> None:
    with pytest.raises(ValueError):
        parse_hhmm(value)


def test_unquoted_yaml_time_is_rejected_with_a_clear_message(tmp_path: Path) -> None:
    """YAML 1.1 reads an unquoted 18:30 as the integer 1110 (base-60); refuse it loudly."""
    path = tmp_path / "c.yaml"
    text = yaml.safe_dump(BASE_CONFIG).replace("'18:30'", "18:30")
    assert "weekday_cutoff: 18:30" in text
    assert yaml.safe_load(text)["devices"]["kids_tv"]["weekday_cutoff"] == 1110
    path.write_text(text)
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    assert "quoted" in exc.value.render() and "weekday_cutoff" in exc.value.render()


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda r: r.update(bogus=1), "bogus"),
        (lambda r: r.update(timezone="Mars/Olympus"), "unknown timezone"),
        (lambda r: r["children"]["child8"].update(weekday_earliest_start="9am"), "HH:MM"),
        (
            lambda r: r["children"]["child8"].update(weekday_allowance_minutes=-1),
            "weekday_allowance_minutes",
        ),
        (lambda r: r["devices"]["ipad"].update(ip="192.168.12.999"), "valid IPv4"),
        (lambda r: r["devices"]["ipad"].update(ip="192.168.12.40"), "duplicates"),
        (lambda r: r["devices"]["ipad"].pop("owner"), "require an owner"),
        (lambda r: r["devices"]["ipad"].update(owner="ghost"), "unknown child"),
        (lambda r: r["devices"]["kids_tv"].update(owner="child8"), "must not have an owner"),
        (
            lambda r: r["children"]["child8"].update(permitted_shared_devices=["nope"]),
            "unknown device",
        ),
        (lambda r: r["children"]["child12"].update(owned_devices=["ipad"]), "owner is"),
        (lambda r: r["sessions"].update(default_minutes=45), "default_minutes"),
        (lambda r: r["sessions"].update(child_choices_minutes=[30, 15]), "ascending"),
        (lambda r: r["notifications"].update(warning_minutes=10), "must equal"),
        (lambda r: r["firewall"].update(mode="telnet"), "mode"),
        (lambda r: r["firewall"].update(reconcile_seconds=1), "reconcile_seconds"),
        (lambda r: r["firewall"].update(host="pfsense.home.arpa"), "IPv4 address"),
        (lambda r: r["firewall"].update(stale_grace_seconds=150), "less than stale_grace"),
        (lambda r: r["devices"].update({"a" * 33: r["devices"]["lounge_tv"]}), "32 characters"),
        # v1.2 removed these; each says where it went (plan 6, section 9).
        (lambda r: r["firewall"].update(mode="pfsense_ssh"), "use pfsense_pull"),
        (lambda r: r["firewall"].update(command="/usr/local/sbin/screenctl"), "screenctl is gone"),
        (lambda r: r["firewall"].update(ssh_user="screentime"), "there is no SSH"),
        (lambda r: r["firewall"].update(active_table="SCR_ACTIVE"), "screentime-pull.conf"),
        (lambda r: r["firewall"].update(education_dns_refresh_seconds=300), "SCR_EDU_ALLOW"),
        (
            lambda r: r.update(always_allowed={"duolingo": {"domains": []}}),
            "Host alias SCR_EDU_ALLOW",
        ),
        (lambda r: r["devices"]["ipad"].update(education_allowlist=True), "SCR_EDU_DEVICES"),
        (lambda r: r.update(children={}), "at least one"),
        (lambda r: r["children"].update({"Bad-Id": r["children"]["child8"]}), "lowercase"),
    ],
)
def test_invalid_configuration_is_rejected_with_a_clear_error(
    tmp_path: Path, mutate: Any, needle: str
) -> None:
    assert needle in bad(mutated(mutate), tmp_path)


def test_the_specification_sample_conflict_is_reported_clearly(tmp_path: Path) -> None:
    """The spec's sample lists a personal iPad as a shared device for both children."""

    def mutate(raw: dict[str, Any]) -> None:
        for child in raw["children"].values():
            child["permitted_shared_devices"] = ["ipad", "kids_tv", "lounge_tv"]

    message = bad(mutated(mutate), tmp_path)
    assert "personal device" in message and "'ipad'" in message


def test_all_problems_are_reported_together(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        raw["timezone"] = "Nope/Nope"
        raw["devices"]["ipad"]["ip"] = "x"
        raw["sessions"]["default_minutes"] = 7

    message = bad(mutated(mutate), tmp_path)
    assert message.count("\n  - ") >= 3


def test_missing_file_and_bad_yaml(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")
    broken = tmp_path / "broken.yaml"
    broken.write_text("a: [unclosed")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(broken)
    scalar = tmp_path / "scalar.yaml"
    scalar.write_text("- 1\n- 2\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(scalar)


# --- command line ----------------------------------------------------------------------------


def test_check_config_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = write(tmp_path, {**BASE_CONFIG})
    assert main(["--config", str(cfg), "--check-config"]) == 0
    out = capsys.readouterr().out
    assert "Configuration OK" in out and "dry_run" in out
    assert "logins:        in the database" in out
    assert main(["--config", str(tmp_path / "missing.yaml"), "--check-config"]) == 2
    assert "Invalid configuration" in capsys.readouterr().err
    assert main(["--version"]) == 0


def test_users_option_is_gone(tmp_path: Path) -> None:
    """Credentials live in the database (plan 7.3): there is no users.yaml to point at."""
    cfg = write(tmp_path, {**BASE_CONFIG})
    with pytest.raises(SystemExit):
        main(["--config", str(cfg), "--users", "users.yaml", "--check-config"])


def test_password_min_length_is_configurable_but_bounded() -> None:
    assert make_config().security.password_min_length == 4
    assert make_config(security={"password_min_length": 12}).security.password_min_length == 12
    for bad in (0, 129):
        with pytest.raises(ValidationError):
            make_config(security={"password_min_length": bad})


def test_init_db_cli_creates_and_seeds_the_database(tmp_path: Path) -> None:
    raw = copy.deepcopy(BASE_CONFIG)
    raw["storage"] = {"data_dir": str(tmp_path / "data")}
    cfg = write(tmp_path, raw)
    assert main(["--config", str(cfg), "--init-db"]) == 0
    db_file = tmp_path / "data" / "screentime.db"
    assert db_file.exists()
    assert main(["--config", str(cfg), "--init-db"]) == 0  # idempotent
    con = sqlite3.connect(db_file)
    rows = con.execute("SELECT username, role, enabled, password_hash FROM users").fetchall()
    con.close()
    # Each configured child has an account, without a password until a parent sets one.
    assert sorted(rows) == [("child12", "child", 1, ""), ("child8", "child", 1, "")]


def test_service_refuses_to_start_on_invalid_config(tmp_path: Path) -> None:
    bad_cfg = tmp_path / "config.yaml"
    bad_cfg.write_text("children: {}\ndevices: {}\n")
    env = {
        **os.environ,
        "SCREENTIME_CONFIG": str(bad_cfg),
    }
    result = subprocess.run(
        [sys.executable, "-c", "import app.main as m; m.app"],
        capture_output=True, text=True, env=env, cwd=ROOT, timeout=60, check=False,
    )  # fmt: skip
    assert result.returncode != 0 and "Invalid configuration" in result.stderr


def test_poll_intervals_must_be_ordered() -> None:
    with pytest.raises(ValidationError):
        make_config(ui={"poll_fast_seconds": 20, "poll_idle_seconds": 10})
    assert make_config().ui.poll_idle_seconds == 15
