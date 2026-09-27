#!/usr/bin/env python3
"""Print an Argon2id hash for users.yaml. The password is read without echo and never logged.

The hash uses security.password_hash from config.yaml (--config, or $SCREENTIME_CONFIG when
it exists), so it matches what the service verifies against. Without a config file it uses
the OWASP minimum (m=19456 KiB, t=2, p=1).

Usage:
    .venv/bin/python scripts/make_password_hash.py            # prompts twice
    printf '%s' "$PASSWORD" | .venv/bin/python scripts/make_password_hash.py --stdin
    .venv/bin/python scripts/make_password_hash.py --calibrate  # time candidate parameters here
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import ConfigError, PasswordHashCfg, load_config
from app.passwords import PasswordHashing

# Candidates at or above the OWASP minimum, plus v1.0's parameters for comparison.
CALIBRATION_SETS = [(19456, 2, 1), (19456, 3, 1), (32768, 2, 1), (47104, 2, 1), (65536, 3, 4)]


def hash_settings(config_path: Path | None) -> PasswordHashCfg:
    if config_path is None:
        env = os.environ.get("SCREENTIME_CONFIG")
        config_path = Path(env) if env and Path(env).exists() else None
    if config_path is None:
        return PasswordHashCfg()
    return load_config(config_path).security.password_hash


def calibrate(current: PasswordHashCfg) -> None:
    print("Verify time on this host (lower is faster logins; all rows meet the OWASP minimum")
    print("except where noted). Target: about 2 s or less on the Raspberry Pi.\n")
    for memory, time_cost, parallelism in CALIBRATION_SETS:
        cfg = PasswordHashCfg(memory_kib=memory, time_cost=time_cost, parallelism=parallelism)
        hashing = PasswordHashing(cfg)
        stored = hashing.hash("calibration-password")
        started = time.perf_counter()
        hashing.verify(stored, "calibration-password")
        elapsed = time.perf_counter() - started
        marks = []
        if cfg == current:
            marks.append("configured")
        if (memory, time_cost, parallelism) == (65536, 3, 4):
            marks.append("v1.0 default")
        note = f"  ({', '.join(marks)})" if marks else ""
        print(f"  m={memory:<6} t={time_cost} p={parallelism}  verify {elapsed:6.2f} s{note}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--stdin", action="store_true", help="read the password from standard input"
    )
    parser.add_argument("--config", type=Path, help="config.yaml to take parameters from")
    parser.add_argument(
        "--calibrate", action="store_true", help="print verify times for candidate parameters"
    )
    args = parser.parse_args()
    try:
        settings = hash_settings(args.config)
    except ConfigError as exc:
        print(exc.render(), file=sys.stderr)
        return 2
    if args.calibrate:
        calibrate(settings)
        return 0
    if args.stdin:
        password = sys.stdin.read().rstrip("\n")
    else:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Repeat password: "):
            print("Passwords do not match.", file=sys.stderr)
            return 1
    if len(password) < 6:
        print("Use at least 6 characters.", file=sys.stderr)
        return 1
    print(PasswordHashing(settings).hash(password))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
