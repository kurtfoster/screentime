#!/usr/bin/env python3
"""Inspect and reset sessions and list policy state without the web UI. See `--help`."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.admin import main

if __name__ == "__main__":
    raise SystemExit(main())
