"""Seed database reference rows (devices, children's accounts) from YAML on every start."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.accounts import sync_child_accounts
from app.config import AppConfig
from app.models import Device


def sync_reference_data(db: Session, config: AppConfig) -> None:
    """Upsert devices and child accounts; anything no longer in YAML is disabled, never deleted.

    Parent accounts and every password hash are owned by the database, not the YAML.
    """
    known_devices = {d.id: d for d in db.scalars(select(Device))}
    for dev_id, cfg in config.devices.items():
        row = known_devices.pop(dev_id, None)
        if row is None:
            row = Device(id=dev_id)
            db.add(row)
        row.display_name = cfg.display_name
        row.ip = cfg.ip
        row.type = cfg.type
        row.owner_child_id = cfg.owner
        row.enabled = cfg.enabled
    for stale in known_devices.values():
        stale.enabled = False
    sync_child_accounts(db, config)
