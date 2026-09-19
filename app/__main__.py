"""Command line entry point: ``python -m app --check-config``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.config import ConfigError, load_all
from app.main import config_paths_from_env
from app.version import VERSION


def main(argv: list[str] | None = None) -> int:
    default_config, default_users = config_paths_from_env()
    parser = argparse.ArgumentParser(prog="python -m app", description="Screen-Time Controller")
    parser.add_argument("--config", type=Path, default=default_config, help="path to config.yaml")
    parser.add_argument("--users", type=Path, default=default_users, help="path to users.yaml")
    parser.add_argument(
        "--check-config", action="store_true", help="validate configuration and exit"
    )
    parser.add_argument(
        "--init-db", action="store_true", help="create/upgrade the database and exit"
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    args = parser.parse_args(argv)

    if args.version:
        print(VERSION)
        return 0
    if not (args.check_config or args.init_db):
        parser.print_help()
        return 0

    try:
        config, users = load_all(args.config, args.users)
    except ConfigError as exc:
        print(exc.render(), file=sys.stderr)
        return 2

    if args.check_config:
        print(f"Configuration OK (version {VERSION})")
        print(
            f"  timezone:      {config.timezone} (logical day resets {config.logical_day_reset:%H:%M})"
        )
        print(f"  children:      {', '.join(c.display_name for c in config.children.values())}")
        print(f"  devices:       {', '.join(config.devices)}")
        print(f"  firewall mode: {config.firewall.mode}")
        print(f"  users:         {', '.join(users)}")
        hosts = config.education_hosts()
        print(f"  allowlist:     {len(hosts)} hostnames")
        if not hosts:
            print(
                "  warning: always_allowed has no domains; education apps will be blocked when idle"
            )
        if config.firewall.mode == "dry_run":
            print("  warning: firewall.mode is dry_run; nothing is enforced on pfSense")
        return 0

    from app.bootstrap import sync_reference_data
    from app.db import Database

    db = Database(config.storage.db_file)
    db.upgrade()
    with db.session(write=True) as session:
        sync_reference_data(session, config, users)
    print(f"Database ready at {config.storage.db_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
