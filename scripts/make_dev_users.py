#!/usr/bin/env python3
"""Write config/users.dev.yaml with throwaway development passwords (child8/child12/parents).

Development only: the passwords are printed so you can sign in. Never use them in production.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.auth import hash_password

PASSWORDS = {"child8": "child8-dev", "child12": "child12-dev", "parents": "parents-dev"}


def main() -> None:
    target = Path(__file__).resolve().parent.parent / "config" / "users.dev.yaml"
    lines = ["users:"]
    for name, password in PASSWORDS.items():
        lines.append(f"  {name}:")
        lines.append(f"    role: {'parent' if name == 'parents' else 'child'}")
        if name != "parents":
            lines.append(f"    child_id: {name}")
        lines.append(f'    password_hash: "{hash_password(password)}"')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"Wrote {target}")
    for name, password in PASSWORDS.items():
        print(f"  {name}: {password}")


if __name__ == "__main__":
    main()
