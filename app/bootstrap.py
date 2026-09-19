"""Seed database reference rows (devices, users) from YAML on every start."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import AppConfig, UserCfg
from app.models import Device, User


def sync_reference_data(db: Session, config: AppConfig, users: dict[str, UserCfg]) -> None:
    """Upsert devices and users; anything no longer in YAML is disabled, never deleted."""
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

    known_users = {u.username: u for u in db.scalars(select(User))}
    for username, cfg_user in users.items():
        urow = known_users.pop(username, None)
        if urow is None:
            urow = User(username=username)
            db.add(urow)
        urow.role = cfg_user.role
        urow.child_id = cfg_user.child_id
        urow.enabled = True
    for stale_user in known_users.values():
        stale_user.enabled = False
