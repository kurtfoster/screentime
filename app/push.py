"""Web Push (VAPID) key handling and delivery. Notification is UX only; enforcement never waits on it.

The sender is the same construction ``pywebpush`` performs, on the libraries it uses itself
and that Raspberry Pi OS packages: ``py_vapid`` signs the VAPID JWT (RFC 8292), ``http_ece``
encrypts the payload (RFC 8291, aes128gcm) and the standard library POSTs it. No
cryptography is implemented here. Dropping ``pywebpush`` removes aiohttp, requests and
their compiled dependencies (install risk on ARMv6, memory and seconds of import time).
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

log = logging.getLogger("screentime.push")

TTL_SECONDS = 300
TIMEOUT_SECONDS = 10.0
JWT_LIFETIME_SECONDS = 12 * 3600  # push services reject tokens that live longer than 24 h
URGENT_KINDS = frozenset({"session_warning"})


class PushGone(Exception):
    """The push service says this subscription no longer exists (HTTP 404/410)."""


class PushError(Exception):
    """Delivery failed for a reason that may be transient."""


class EndpointRejected(ValueError):
    """A subscription endpoint is not an allowed push service (SSRF guard, CWE-918)."""


class PushSender(Protocol):
    def send(self, subscription_info: dict[str, Any], payload: dict[str, str]) -> None: ...


# (url, body, headers, timeout) -> HTTP status code
Transport = Callable[[str, bytes, dict[str, str], float], int]


def check_endpoint(endpoint: str, allowed_host_suffixes: Iterable[str]) -> str:
    """Accept only https URLs on a known push service, so the Pi never POSTs anywhere else.

    Without this, any signed-in user could make the controller send requests to arbitrary
    hosts, including LAN devices such as the pfSense web interface.
    """
    parts = urlsplit(endpoint)
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme != "https" or not host or len(endpoint) > 1024:
        raise EndpointRejected("endpoint must be an https URL")
    if parts.username is not None or parts.password is not None:
        raise EndpointRejected("endpoint must not contain credentials")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise EndpointRejected("endpoint must use a host name, not an IP address")
    if parts.port not in (None, 443):
        raise EndpointRejected("endpoint must use the standard https port")
    for suffix in allowed_host_suffixes:
        suffix = suffix.lower().strip(".")
        if host == suffix or host.endswith("." + suffix):
            return endpoint
    raise EndpointRejected(f"{host} is not a recognised push service")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect would be a request to a host that was never checked against the allowlist."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirects)


def urllib_transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, OSError) as exc:
        raise PushError(f"push service unreachable: {exc}") from exc


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

    def authorization(self, endpoint: str, subject: str) -> str:
        """``vapid t=<JWT>,k=<public key>`` for the endpoint's origin (RFC 8292)."""
        parts = urlsplit(endpoint)
        claims = {
            "aud": f"{parts.scheme}://{parts.netloc}",
            "sub": subject,
            "exp": int(time.time()) + JWT_LIFETIME_SECONDS,
        }
        headers: dict[str, str] = self._vapid.sign(claims)
        return headers["Authorization"]


class WebPushSender:
    def __init__(
        self,
        keys: VapidKeys,
        subject: str,
        allowed_host_suffixes: Iterable[str],
        transport: Transport = urllib_transport,
    ) -> None:
        self._keys = keys
        self._subject = subject
        self._allowed = tuple(allowed_host_suffixes)
        self._transport = transport

    @staticmethod
    def encrypt(payload: bytes, p256dh: str, auth: str) -> bytes:
        """RFC 8291 aes128gcm body, from a fresh ephemeral P-256 key for every message."""
        import http_ece

        ephemeral = ec.generate_private_key(ec.SECP256R1())
        body: bytes = http_ece.encrypt(
            payload,
            private_key=ephemeral,
            dh=_b64url_decode(p256dh),
            auth_secret=_b64url_decode(auth),
            version="aes128gcm",
        )
        return body

    def send(self, subscription_info: dict[str, Any], payload: dict[str, str]) -> None:
        endpoint = str(subscription_info.get("endpoint", ""))
        try:
            check_endpoint(endpoint, self._allowed)
        except EndpointRejected as exc:
            # Stored before the allowlist existed, or the allowlist was narrowed: drop it.
            raise PushGone(str(exc)) from exc
        keys = subscription_info.get("keys") or {}
        try:
            body = self.encrypt(json.dumps(payload).encode(), keys["p256dh"], keys["auth"])
        except Exception as exc:  # malformed browser keys: the subscription is unusable
            raise PushGone(f"invalid subscription keys ({exc.__class__.__name__})") from exc
        headers = {
            "Authorization": self._keys.authorization(endpoint, self._subject),
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
            "TTL": str(TTL_SECONDS),
            "Urgency": "high" if payload.get("kind") in URGENT_KINDS else "normal",
        }
        status = self._transport(endpoint, body, headers, TIMEOUT_SECONDS)
        if status in (404, 410):
            raise PushGone(str(status))
        if not 200 <= status < 300:
            raise PushError(f"push failed (status {status})")
