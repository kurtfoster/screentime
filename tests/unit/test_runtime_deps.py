"""Runtime dependency floors (python -m app --check-deps and the diagnostics list)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.__main__ import main
from app.runtime_deps import (
    DependencyStatus,
    check_dependencies,
    declared_floors,
    dependency_report,
    version_key,
)


@pytest.mark.parametrize(
    ("low", "high"),
    [("0.0.9", "0.0.20"), ("2.0.40", "2.0.54"), ("0.46.1", "1.6.0"), ("21.1.0", "25.1.0")],
)
def test_versions_compare_numerically(low: str, high: str) -> None:
    assert version_key(low) < version_key(high)


def test_debian_suffixes_and_trailing_zeros_are_ignored() -> None:
    assert version_key("2.0.40+ds1") == version_key("2.0.40")
    assert version_key("1.13") == version_key("1.13.0")
    assert version_key("2.10.6rc1") == (2, 10, 6)


def test_floors_are_the_raspberry_pi_os_trixie_versions() -> None:
    floors = declared_floors()
    assert floors["argon2-cffi"] == "21.1"
    assert floors["fastapi"] == "0.115" and floors["starlette"] == "0.46"
    assert floors["pydantic"] == "2.10" and floors["cryptography"] == "43"
    assert {"py-vapid", "http-ece", "dnspython", "uvicorn", "python-multipart"} <= set(floors)


def test_missing_and_old_packages_are_reported(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\ndependencies = ["alpha>=1.2", "beta>=2.0", "gamma>=0.1"]\n')
    versions = {"alpha": "1.10.0", "beta": "1.9"}
    statuses = {s.name: s for s in check_dependencies(pyproject, versions.get)}
    assert statuses["alpha"].ok and statuses["alpha"].problem is None
    assert not statuses["beta"].ok and "older than the minimum 2.0" in (
        statuses["beta"].problem or ""
    )
    assert statuses["gamma"].problem == "not installed"


def test_unsupported_requirement_syntax_is_rejected(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\ndependencies = ["alpha~=1.2"]\n')
    with pytest.raises(ValueError, match="unsupported requirement"):
        declared_floors(pyproject)


def test_development_environment_meets_every_floor(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--check-deps"]) == 0
    out = capsys.readouterr().out
    assert "argon2-cffi" in out and "All dependencies meet" in out
    assert all(isinstance(s, DependencyStatus) and s.ok for s in dependency_report())


def test_check_deps_fails_loudly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "app.runtime_deps.check_dependencies",
        lambda: [DependencyStatus("argon2-cffi", "21.1", "18.0"), DependencyStatus("x", "1", None)],
    )
    assert main(["--check-deps"]) == 1
    err = capsys.readouterr().err
    assert "2 dependency problem(s)" in err and "argon2-cffi: 18.0 is older" in err
