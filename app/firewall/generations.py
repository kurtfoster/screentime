"""The publication generation, kept in the database (plan 6.3).

The generation identifies a set of desired devices, so acknowledgements can be matched to
what was published. It changes only when the set changes and survives restarts, so pfSense
never sees a number go backwards. It is a correlation identifier, not an anti-replay control.
"""

from __future__ import annotations

from app.db import Database
from app.models import Meta

_KEY = "firewall_generation"


class DbGenerations:
    def __init__(self, db: Database) -> None:
        self._db = db
        self._generation = 0
        self._devices: frozenset[str] | None = None
        with db.session() as session:
            row = session.get(Meta, _KEY)
            if row is not None:
                number, _, devices = row.value.partition(" ")
                self._generation = int(number)
                self._devices = frozenset(filter(None, devices.split(",")))

    def next(self, device_ids: frozenset[str]) -> int:
        if device_ids == self._devices:
            return self._generation
        generation = self._generation + 1
        with self._db.session(write=True) as session:
            row = session.get(Meta, _KEY)
            value = f"{generation} {','.join(sorted(device_ids))}"
            if row is None:
                session.add(Meta(key=_KEY, value=value))
            else:
                row.value = value
        self._generation, self._devices = generation, device_ids
        return generation
