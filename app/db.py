"""SQLite engine, transactions and Alembic upgrade helpers.

SQLite runs in WAL mode. Write transactions use ``BEGIN IMMEDIATE`` so a policy check
and the insert it justifies are serialised (spec section 18); reads use a plain
deferred ``BEGIN`` and see a consistent snapshot.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Engine, create_engine, event, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeDecorator

if TYPE_CHECKING:
    from alembic.config import Config

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
_REVISION_RE = re.compile(
    r"^(down_revision|revision)\s*(?::[^=]+)?=\s*['\"]?([^'\"\s]+)['\"]?", re.M
)

_write_tx: ContextVar[bool] = ContextVar("screentime_write_tx", default=False)


class UTCDateTime(TypeDecorator[datetime]):
    """Store UTC instants; always return timezone-aware UTC datetimes."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected; use timezone-aware values")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


def _on_connect(dbapi_connection: Any, _record: Any) -> None:
    dbapi_connection.isolation_level = None  # we emit BEGIN ourselves
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    # FULL: a committed session or grant survives a power cut (a Pi 1 has no battery and
    # SD cards reorder writes). The write rate is a few rows a minute, so the cost is nil.
    cursor.execute("PRAGMA synchronous=FULL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=10000")
    cursor.close()


def _on_begin(conn: Connection) -> None:
    conn.exec_driver_sql("BEGIN IMMEDIATE" if _write_tx.get() else "BEGIN")


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine: Engine = create_engine(
            f"sqlite:///{self.path}",
            connect_args={"check_same_thread": False, "timeout": 10},
        )
        event.listen(self.engine, "connect", _on_connect)
        event.listen(self.engine, "begin", _on_begin)

    @property
    def url(self) -> str:
        return f"sqlite:///{self.path}"

    @contextmanager
    def session(self, *, write: bool = False) -> Iterator[Session]:
        """Open a transaction; commits on success, rolls back on any exception."""
        token = _write_tx.set(write)
        try:
            with Session(self.engine, expire_on_commit=False) as session:
                try:
                    yield session
                    session.commit()
                except BaseException:
                    session.rollback()
                    raise
        finally:
            _write_tx.reset(token)

    def check(self) -> bool:
        try:
            with self.session() as session:
                session.execute(text("SELECT 1"))
        except Exception:
            return False
        return True

    def upgrade(self) -> None:
        upgrade_to_head(self.url)

    def upgrade_if_needed(self) -> bool:
        """Run Alembic only when the schema is behind. Returns whether it ran.

        Importing and running Alembic costs several seconds on a Raspberry Pi 1, and on almost
        every start the database is already at the head revision.
        """
        heads = script_heads()
        if len(heads) == 1 and current_revision(self) in heads:
            return False
        self.upgrade()
        return True

    def dispose(self) -> None:
        self.engine.dispose()


def script_heads(versions_dir: Path = MIGRATIONS_DIR / "versions") -> set[str]:
    """Head revision(s) of the migration scripts, read as text so Alembic is not imported."""
    revisions: set[str] = set()
    parents: set[str] = set()
    for script in versions_dir.glob("*.py"):
        found = dict(_REVISION_RE.findall(script.read_text(encoding="utf-8")))
        if "revision" in found:
            revisions.add(found["revision"])
        if found.get("down_revision") not in (None, "None"):
            parents.add(found["down_revision"])
    return revisions - parents


def alembic_config(url: str) -> Config:
    from alembic.config import Config

    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def upgrade_to_head(url: str) -> None:
    from alembic import command

    command.upgrade(alembic_config(url), "head")


def current_revision(db: Database) -> str | None:
    with db.session() as session:
        try:
            row = session.execute(text("SELECT version_num FROM alembic_version")).first()
        except Exception:
            return None
    return str(row[0]) if row else None
