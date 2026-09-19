"""Append-oriented audit trail plus structured application logging."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditEvent

audit_log = logging.getLogger("screentime.audit")

_SECRET_KEYS = {"password", "password_hash", "token", "cookie", "private_key", "secret", "keys"}


def _scrub(details: dict[str, Any]) -> dict[str, Any]:
    return {k: ("[redacted]" if k.lower() in _SECRET_KEYS else v) for k, v in details.items()}


def record_audit(
    db: Session,
    now: datetime,
    actor: str,
    event_type: str,
    subject: str = "",
    result: str = "ok",
    **details: Any,
) -> None:
    """Add an audit row to the caller's transaction and mirror it to the audit logger."""
    safe = _scrub(details)
    db.add(
        AuditEvent(
            timestamp=now,
            actor=actor,
            event_type=event_type,
            subject=subject,
            result=result,
            details_json=json.dumps(safe, default=str, sort_keys=True),
        )
    )
    audit_log.info(
        "audit actor=%s event=%s subject=%s result=%s details=%s",
        actor,
        event_type,
        subject,
        result,
        json.dumps(safe, default=str, sort_keys=True),
    )


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger("screentime")
    if any(getattr(h, "_screentime", False) for h in root.handlers):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler._screentime = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False
