#!/usr/bin/env python3
"""One-shot reconcile of pfSense with the database (add --education to refresh the allowlist)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.admin import main

if __name__ == "__main__":
    raise SystemExit(main(["reconcile", *sys.argv[1:]]))
