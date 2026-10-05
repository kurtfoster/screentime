"""The bearer token pfSense presents to fetch the desired state and acknowledge (plan 6.5).

Only a SHA-256 of the token is stored (in the data directory, mode 0600), so a copy of the
database or the data directory does not reveal it. ``scripts/admin_cli.py firewall-token
rotate`` prints a new token once; it goes into pfSense's root-only configuration file.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

TOKEN_FILE = "firewall-token.sha256"  # noqa: S105  # a file name, not a secret
_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def rotate(data_dir: Path) -> str:
    """Create a new token, store its hash (replacing the old one at once) and return it."""
    token = secrets.token_urlsafe(32)
    data_dir.mkdir(parents=True, exist_ok=True)
    target = data_dir / TOKEN_FILE
    tmp = target.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(_digest(token) + "\n")
    os.replace(tmp, target)
    return token


def is_configured(data_dir: Path) -> bool:
    return (data_dir / TOKEN_FILE).is_file()


def check(data_dir: Path, presented: str) -> bool:
    """Constant-time comparison of the presented token's hash with the stored one."""
    try:
        stored = (data_dir / TOKEN_FILE).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return False
    if not presented or len(presented) > 128 or not set(presented) <= _TOKEN_CHARS:
        return False
    return hmac.compare_digest(_digest(presented), stored)
