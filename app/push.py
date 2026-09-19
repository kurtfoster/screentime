"""Web Push (VAPID) key handling and delivery. Notification is UX only; enforcement never waits on it."""

from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization

log = logging.getLogger("screentime.push")


class PushGone(Exception):
    """The push service says this subscription no longer exists (HTTP 404/410)."""


class PushError(Exception):
    """Delivery failed for a reason that may be transient."""


class PushSender(Protocol):
    def send(self, subscription_info: dict[str, Any], payload: dict[str, str]) -> None: ...


class VapidKeys:
    """VAPID application-server key pair, generated once and kept in a 0600 PEM file."""

    def __init__(self, private_key_file: Path) -> None:
        from py_vapid import Vapid02

        self.path = private_key_file
        if private_key_file.exists():
            self._vapid = Vapid02.from_file(str(private_key_file))
        else:
            private_key_file.parent.mkdir(parents=True, exist_ok=True)
            self._vapid = Vapid02()
            self._vapid.generate_keys()
            pem = self._vapid.private_pem()
            fd = os.open(private_key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(pem)
            log.info("generated new VAPID key pair at %s", private_key_file)

    @property
    def public_key(self) -> str:
        """URL-safe base64 of the uncompressed public point, as browsers expect."""
        raw = self._vapid.public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class WebPushSender:
    def __init__(self, keys: VapidKeys, subject: str) -> None:
        self._keys = keys
        self._subject = subject

    def send(self, subscription_info: dict[str, Any], payload: dict[str, str]) -> None:
        from pywebpush import WebPushException, webpush

        try:
            webpush(
                subscription_info=subscription_info,
                data=json.dumps(payload),
                vapid_private_key=str(self._keys.path),
                vapid_claims={"sub": self._subject},
                ttl=300,
                timeout=10,
            )
        except WebPushException as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status in (404, 410):
                raise PushGone(str(status)) from exc
            raise PushError(f"push failed (status {status})") from exc
