#!/usr/bin/env python3
"""Seed the development database with throwaway logins (child8, child12, parent1, parent2).

Development only: the passwords are printed so you can sign in. Never use them in production;
on the Pi, accounts are created with ``scripts/admin_cli.py user add-parent`` and
``user set-password``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.accounts import AccountError
from app.config import load_config
from app.context import build_context

ROOT = Path(__file__).resolve().parent.parent
CHILDREN = {"child8": "child8-dev", "child12": "child12-dev"}
PARENTS = {"parent1": ("Parent One", "parent1-dev"), "parent2": ("Parent Two", "parent2-dev")}


def main() -> None:
    config = load_config(os.environ.get("SCREENTIME_CONFIG", ROOT / "config" / "config.dev.yaml"))
    ctx = build_context(config, enable_push=False)
    for username, (name, password) in PARENTS.items():
        try:
            ctx.accounts.add_parent(username, name, password, "make_dev_users")
        except AccountError:
            ctx.accounts.set_password(username, password, "make_dev_users")
    for username, password in CHILDREN.items():
        ctx.accounts.set_password(username, password, "make_dev_users")
    print(f"Seeded {config.storage.db_file}")
    for username, password in {**CHILDREN, **{u: p for u, (_, p) in PARENTS.items()}}.items():
        print(f"  {username}: {password}")


if __name__ == "__main__":
    main()
