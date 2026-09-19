#!/usr/bin/env python3
"""Print an Argon2id hash for users.yaml. The password is read without echo and never logged.

Usage:
    .venv/bin/python scripts/make_password_hash.py            # prompts twice
    printf '%s' "$PASSWORD" | .venv/bin/python scripts/make_password_hash.py --stdin
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.auth import hash_password


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--stdin", action="store_true", help="read the password from standard input"
    )
    args = parser.parse_args()
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
    print(hash_password(password))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
