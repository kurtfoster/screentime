"""Resolved runtime library versions checked against the ``pyproject.toml`` floors.

On the Raspberry Pi the libraries come from Raspberry Pi OS packages, so a monthly
``apt full-upgrade`` can change them underneath the application. ``python -m app
--check-deps`` and the parent diagnostics page show exactly what is installed, which is the
evidence needed after an upgrade or for a support call.
"""

from __future__ import annotations

import functools
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
_REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*>=\s*([0-9][0-9A-Za-z.+-]*)\s*$")


@dataclass(frozen=True)
class DependencyStatus:
    name: str
    floor: str
    installed: str | None

    @property
    def ok(self) -> bool:
        return self.installed is not None and version_key(self.installed) >= version_key(self.floor)

    @property
    def problem(self) -> str | None:
        if self.installed is None:
            return "not installed"
        if not self.ok:
            return f"{self.installed} is older than the minimum {self.floor}"
        return None


def version_key(version: str) -> tuple[int, ...]:
    """Numeric release segments only ("2.0.40+ds1" -> (2, 0, 40)); enough for a floor check."""
    parts: list[int] = []
    for piece in version.split("."):
        match = re.match(r"\d+", piece)
        if match is None:
            break
        parts.append(int(match.group()))
        if match.end() != len(piece):
            break
    while parts and parts[-1] == 0:
        parts.pop()  # 1.13 and 1.13.0 compare equal
    return tuple(parts)


def declared_floors(pyproject: Path = PYPROJECT) -> dict[str, str]:
    """``name -> minimum version`` for every ``name>=x`` runtime dependency."""
    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)
    floors: dict[str, str] = {}
    for requirement in data["project"]["dependencies"]:
        match = _REQUIREMENT_RE.match(requirement)
        if match is None:
            raise ValueError(f"unsupported requirement format in {pyproject}: {requirement!r}")
        floors[match.group(1)] = match.group(2)
    return floors


def installed_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def check_dependencies(
    pyproject: Path = PYPROJECT,
    version_of: Callable[[str], str | None] = installed_version,
) -> list[DependencyStatus]:
    return [
        DependencyStatus(name, floor, version_of(name))
        for name, floor in declared_floors(pyproject).items()
    ]


@functools.cache
def dependency_report() -> tuple[DependencyStatus, ...]:
    """Cached for the life of the process: packages cannot change without a restart."""
    try:
        return tuple(check_dependencies())
    except (OSError, ValueError, KeyError):
        return ()
