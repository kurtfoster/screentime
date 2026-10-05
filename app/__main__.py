"""Command line entry point: ``python -m app --check-config``.

Accounts and passwords are managed with ``scripts/admin_cli.py user ...``, not here.

``--check-config`` runs before every service start (ExecStartPre), so it imports only the
configuration layer: no FastAPI, Starlette, uvicorn, SQLAlchemy, Alembic or argon2. On a
Raspberry Pi 1 each of those costs seconds.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.config import ConfigError, PasswordHashCfg, config_path_from_env, load_config
from app.version import VERSION

# Candidates at or above the OWASP minimum, plus v1.0's parameters for comparison.
CALIBRATION_SETS = [(19456, 2, 1), (19456, 3, 1), (32768, 2, 1), (47104, 2, 1), (65536, 3, 4)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app", description="Screen-Time Controller")
    parser.add_argument(
        "--config", type=Path, default=config_path_from_env(), help="path to config.yaml"
    )
    parser.add_argument(
        "--check-config", action="store_true", help="validate configuration and exit"
    )
    parser.add_argument(
        "--init-db", action="store_true", help="create/upgrade the database and exit"
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="print installed library versions and fail if any is below the pyproject floor",
    )
    parser.add_argument(
        "--calibrate-hash",
        action="store_true",
        help="print password-check times on this host for candidate Argon2id parameters",
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    args = parser.parse_args(argv)

    if args.version:
        print(VERSION)
        return 0
    if args.check_deps:
        return check_deps()
    if not (args.check_config or args.init_db or args.calibrate_hash):
        parser.print_help()
        return 0

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(exc.render(), file=sys.stderr)
        return 2

    if args.calibrate_hash:
        calibrate(config.security.password_hash)
        return 0

    if args.check_config:
        print(f"Configuration OK (version {VERSION})")
        print(
            f"  timezone:      {config.timezone} (logical day resets {config.logical_day_reset:%H:%M})"
        )
        print(f"  children:      {', '.join(c.display_name for c in config.children.values())}")
        print(f"  devices:       {', '.join(config.devices)}")
        print(f"  firewall mode: {config.firewall.mode}")
        print("  logins:        in the database (scripts/admin_cli.py user list)")
        if config.firewall.mode == "dry_run":
            print("  warning: firewall.mode is dry_run; nothing is enforced on pfSense")
        return 0

    from app.bootstrap import sync_reference_data
    from app.db import Database

    db = Database(config.storage.db_file)
    db.upgrade_if_needed()
    with db.session(write=True) as session:
        sync_reference_data(session, config)
    print(f"Database ready at {config.storage.db_file}")
    return 0


def calibrate(current: PasswordHashCfg) -> None:
    """Time one verify per candidate. Every row meets the OWASP minimum."""
    from app.passwords import PasswordHashing

    print("Verify time on this host (lower is faster logins). Target: about 2 s or less on the")
    print("Raspberry Pi. Set the chosen values in security.password_hash; existing passwords are")
    print("re-hashed with them at each user's next sign-in.\n")
    for memory, time_cost, parallelism in CALIBRATION_SETS:
        cfg = PasswordHashCfg(memory_kib=memory, time_cost=time_cost, parallelism=parallelism)
        hashing = PasswordHashing(cfg)
        stored = hashing.hash("calibration-password")
        hashing.verify(stored, "calibration-password")
        marks = []
        if cfg == current:
            marks.append("configured")
        if (memory, time_cost, parallelism) == (65536, 3, 4):
            marks.append("v1.0 default")
        note = f"  ({', '.join(marks)})" if marks else ""
        print(
            f"  m={memory:<6} t={time_cost} p={parallelism}  "
            f"verify {hashing.last_verify_seconds or 0:6.2f} s{note}"
        )


def check_deps() -> int:
    from app.runtime_deps import check_dependencies

    statuses = check_dependencies()
    print(f"Python {sys.version.split()[0]}")
    for status in statuses:
        mark = "ok" if status.ok else "FAIL"
        print(f"  {mark:4}  {status.name:18} {status.installed or '-':12} (minimum {status.floor})")
    failed = [s for s in statuses if not s.ok]
    if failed:
        print(
            f"{len(failed)} dependency problem(s): "
            + "; ".join(f"{s.name}: {s.problem}" for s in failed),
            file=sys.stderr,
        )
        return 1
    print("All dependencies meet the minimum versions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
