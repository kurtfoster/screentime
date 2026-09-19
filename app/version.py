"""Release version, read from the VERSION file shipped at the repository root."""

from __future__ import annotations

from pathlib import Path

_VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"


def get_version() -> str:
    try:
        return _VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0-unknown"
    except OSError:
        return "0.0.0-unknown"


VERSION = get_version()
