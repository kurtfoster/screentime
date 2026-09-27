"""Start-up cost on a single-core Raspberry Pi 1 (CHG-08): what is imported and when."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.db import Database, script_heads

ROOT = Path(__file__).resolve().parents[2]
HEAVY = ("fastapi", "starlette", "uvicorn", "sqlalchemy", "alembic", "argon2")


def run_python(code: str, *, env: dict[str, str] | None = None) -> dict[str, object]:
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        env=env,
        timeout=60,
    ).stdout
    result: dict[str, object] = json.loads(out.strip().splitlines()[-1])
    return result


def test_check_config_imports_only_the_configuration_layer() -> None:
    code = f"""
import contextlib, io, json, sys
from app.__main__ import main
with contextlib.redirect_stdout(io.StringIO()):
    code = main(["--config", "config/config.example.yaml", "--users", "missing.yaml", "--check-config"])
print(json.dumps({{"code": code, "heavy": [m for m in {HEAVY!r} if m in sys.modules]}}))
"""
    result = run_python(code)
    assert result["code"] == 2  # users file missing: still a clean, validated failure
    assert result["heavy"] == []


def test_script_heads_are_read_without_alembic(tmp_path: Path) -> None:
    assert script_heads() == {"0001"}
    (tmp_path / "a.py").write_text("revision = '0001'\ndown_revision = None\n")
    (tmp_path / "b.py").write_text('revision: str = "0002"\ndown_revision: str | None = "0001"\n')
    assert script_heads(tmp_path) == {"0002"}


def test_alembic_runs_only_when_the_schema_is_behind(tmp_path: Path) -> None:
    db_file = tmp_path / "st.db"
    first = Database(db_file)
    assert first.upgrade_if_needed() is True
    first.dispose()
    code = f"""
import json, sys
from app.db import Database
db = Database({str(db_file)!r})
ran = db.upgrade_if_needed()
print(json.dumps({{"ran": ran, "alembic": "alembic" in sys.modules}}))
"""
    assert run_python(code) == {"ran": False, "alembic": False}
