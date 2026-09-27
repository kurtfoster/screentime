"""Web Push sender (RFC 8291 payload encryption, RFC 8292 VAPID) and the endpoint allowlist."""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Iterator
from email.message import Message
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

import http_ece
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from pydantic import ValidationError

from app.config import PushCfg
from app.push import (
    EndpointRejected,
    PushError,
    PushGone,
    VapidKeys,
    WebPushSender,
    check_endpoint,
    urllib_transport,
)

ALLOWED = PushCfg().allowed_endpoint_hosts
ENDPOINT = "https://fcm.googleapis.com/fcm/send/abc123"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class UserAgent:
    """A browser's push subscription: its own P-256 key pair and auth secret."""

    def __init__(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        public = self.private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        self.auth = b"sixteen-byte-sec"
        self.info = {"endpoint": ENDPOINT, "keys": {"p256dh": b64(public), "auth": b64(self.auth)}}

    def decrypt(self, body: bytes) -> dict[str, Any]:
        plain = http_ece.decrypt(
            body, private_key=self.private_key, auth_secret=self.auth, version="aes128gcm"
        )
        result: dict[str, Any] = json.loads(plain)
        return result


class Capture:
    def __init__(self, status: int = 201) -> None:
        self.status = status
        self.requests: list[tuple[str, bytes, dict[str, str], float]] = []

    def __call__(self, url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
        self.requests.append((url, body, headers, timeout))
        return self.status


@pytest.fixture
def keys(tmp_path: Path) -> VapidKeys:
    return VapidKeys(tmp_path / "vapid.pem")


def sender(keys: VapidKeys, transport: Capture) -> WebPushSender:
    return WebPushSender(keys, "mailto:parents@example.invalid", ALLOWED, transport)


def test_payload_round_trips_through_rfc8291_encryption(keys: VapidKeys) -> None:
    ua, capture = UserAgent(), Capture()
    payload = {"title": "Time is nearly up", "body": "5 minutes left", "kind": "session_warning"}
    sender(keys, capture).send(ua.info, payload)
    url, body, headers, timeout = capture.requests[0]
    assert url == ENDPOINT and timeout == 10.0
    assert ua.decrypt(body) == payload
    assert headers["Content-Encoding"] == "aes128gcm" and headers["TTL"] == "300"
    assert headers["Urgency"] == "high"
    sender(keys, capture).send(ua.info, {"kind": "session_ended"})
    assert capture.requests[1][2]["Urgency"] == "normal"
    assert capture.requests[0][1][:16] != capture.requests[1][1][:16]  # fresh salt per message


def test_vapid_header_is_a_valid_es256_token_for_the_push_origin(keys: VapidKeys) -> None:
    capture = Capture()
    sender(keys, capture).send(UserAgent().info, {"kind": "x"})
    auth = capture.requests[0][2]["Authorization"]
    assert auth.startswith("vapid t=")
    token, _, key = auth.removeprefix("vapid t=").partition(",k=")
    assert key == keys.public_key
    header_b64, claims_b64, sig_b64 = token.split(".")
    assert json.loads(unb64(header_b64))["alg"] == "ES256"
    claims = json.loads(unb64(claims_b64))
    assert claims["aud"] == "https://fcm.googleapis.com"
    assert claims["sub"] == "mailto:parents@example.invalid"
    assert time.time() < claims["exp"] <= time.time() + 24 * 3600
    signature = unb64(sig_b64)
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64(key))
    der = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    public.verify(der, f"{header_b64}.{claims_b64}".encode(), ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize(
    ("status", "error"), [(404, PushGone), (410, PushGone), (500, PushError), (302, PushError)]
)
def test_status_codes_map_to_outcomes(keys: VapidKeys, status: int, error: type[Exception]) -> None:
    with pytest.raises(error):
        sender(keys, Capture(status)).send(UserAgent().info, {"kind": "x"})


def test_unusable_subscriptions_are_dropped_without_a_request(keys: VapidKeys) -> None:
    capture = Capture()
    lan = {**UserAgent().info, "endpoint": "https://192.168.12.1/api"}
    with pytest.raises(PushGone, match="IP address"):
        sender(keys, capture).send(lan, {"kind": "x"})
    broken = {"endpoint": ENDPOINT, "keys": {"p256dh": "AAAA", "auth": "AAAA"}}
    with pytest.raises(PushGone, match="invalid subscription keys"):
        sender(keys, capture).send(broken, {"kind": "x"})
    assert capture.requests == []


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://fcm.googleapis.com/fcm/send/abc",
        "https://web.push.apple.com/QGx1",
        "https://updates.push.services.mozilla.com/wpush/v2/gAAA",
        "https://wns2-par02p.notify.windows.com/w/?token=BQYAAAD",
        "https://fcm.googleapis.com:443/fcm/send/abc",
    ],
)
def test_known_push_services_are_accepted(endpoint: str) -> None:
    assert check_endpoint(endpoint, ALLOWED) == endpoint


@pytest.mark.parametrize(
    ("endpoint", "why"),
    [
        ("http://fcm.googleapis.com/fcm/send/abc", "https URL"),
        ("https://192.168.12.1/", "IP address"),
        ("https://[::1]/x", "IP address"),
        ("https://user:pw@fcm.googleapis.com/x", "credentials"),
        ("https://fcm.googleapis.com:8443/x", "standard https port"),
        ("https://fcm.googleapis.com.evil.example/x", "not a recognised push service"),
        ("https://notgoogleapis.com/x", "not a recognised push service"),
        ("https://pfsense.home.arpa/", "not a recognised push service"),
        ("https:///nohost", "https URL"),
    ],
)
def test_other_endpoints_are_rejected(endpoint: str, why: str) -> None:
    with pytest.raises(EndpointRejected, match=why):
        check_endpoint(endpoint, ALLOWED)


def test_allowlist_entries_must_be_host_names() -> None:
    with pytest.raises(ValidationError):
        PushCfg(allowed_endpoint_hosts=["localhost"])
    with pytest.raises(ValidationError):
        PushCfg(allowed_endpoint_hosts=[])
    assert PushCfg(allowed_endpoint_hosts=["Push.Example.COM."]).allowed_endpoint_hosts == [
        "push.example.com"
    ]


# --- the standard-library transport, against a local HTTP server --------------------------------


class _Handler(BaseHTTPRequestHandler):
    seen: ClassVar[list[tuple[str, bytes, Message]]] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Handler.seen.append((self.path, body, self.headers))
        codes = {"/ok": 201, "/gone": 410, "/redirect": 302}
        self.send_response(codes.get(self.path, 500))
        if self.path == "/redirect":
            self.send_header("Location", "/ok")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def server() -> Iterator[str]:
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    _Handler.seen.clear()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_transport_posts_and_never_follows_redirects(server: str) -> None:
    headers = {"TTL": "300", "Content-Encoding": "aes128gcm"}
    assert urllib_transport(f"{server}/ok", b"cipher", headers, 5) == 201
    assert urllib_transport(f"{server}/gone", b"x", headers, 5) == 410
    assert urllib_transport(f"{server}/redirect", b"x", headers, 5) == 302
    assert [p for p, _, _ in _Handler.seen] == ["/ok", "/gone", "/redirect"]  # no follow-up /ok
    assert _Handler.seen[0][1] == b"cipher" and _Handler.seen[0][2].get("TTL") == "300"


def test_transport_reports_unreachable_services() -> None:
    with pytest.raises(PushError, match="unreachable"):
        urllib_transport("http://127.0.0.1:9/x", b"x", {}, 2)
