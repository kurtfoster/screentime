"""SQLite engine, transactions and Alembic upgrade helpers.

SQLite runs in WAL mode. Write transactions use ``BEGIN IMMEDIATE`` so a policy check
and the insert it justifies are serialised (spec section 18); reads use a plain
deferred ``BEGIN`` and see a consistent snapshot.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import DateTime, Engine, create_engine, event, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeDecorator

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"

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
    cursor.execute("PRAGMA synchronous=NORMAL")
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

    def dispose(self) -> None:
        self.engine.dispose()


def alembic_config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def upgrade_to_head(url: str) -> None:
    command.upgrade(alembic_config(url), "head")


def current_revision(db: Database) -> str | None:
    with db.session() as session:
        try:
            row = session.execute(text("SELECT version_num FROM alembic_version")).first()
        except Exception:
            return None
    return str(row[0]) if row else None
