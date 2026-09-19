"""Application secret material: one random secret on disk, purpose-specific keys derived from it."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path


def load_or_create_secret(path: Path) -> bytes:
    """Return the 32-byte application secret, creating it (mode 0600) on first use."""
    if path.exists():
        data = path.read_bytes()
        if len(data) >= 32:
            return data[:32]
    path.parent.mkdir(parents=True, exist_ok=True)
    data = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return data


def derive_key(secret: bytes, purpose: str) -> bytes:
    return hmac.new(secret, purpose.encode(), hashlib.sha256).digest()


def fernet_key(secret: bytes, purpose: str) -> bytes:
    return base64.urlsafe_b64encode(derive_key(secret, purpose))
