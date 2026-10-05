"""The desired-state and acknowledgement grammar (plan 6.3)."""

from __future__ import annotations

import pytest

from app.firewall.base import DesiredState, Lease
from app.firewall.protocol import ProtocolError, parse_applied, render_desired

GOOD = (
    b"screentime-applied v1\n"
    b"generation 4711\n"
    b"mode normal\n"
    b"last-failopen 5400 1260\n"
    b"device ipad\n"
    b"device kids_tv\n"
    b"end\n"
)


def test_render_desired_matches_the_plan_example() -> None:
    state = DesiredState(
        (Lease("kids_tv", "192.168.12.40", 3600), Lease("ipad", "192.168.12.30", 1740))
    )
    assert render_desired(4711, state) == (
        "screentime-desired v1\ngeneration 4711\ndevice ipad 1740\ndevice kids_tv 3600\nend\n"
    )
    assert render_desired(1, DesiredState()) == "screentime-desired v1\ngeneration 1\nend\n"


def test_render_refuses_what_pfsense_would_reject() -> None:
    with pytest.raises(ProtocolError):
        render_desired(1, DesiredState((Lease("Bad-Id", "192.168.12.30", 10),)))
    with pytest.raises(ProtocolError):
        render_desired(1, DesiredState((Lease("ipad", "192.168.12.30", 0),)))


def test_parse_a_full_acknowledgement() -> None:
    ack = parse_applied(GOOD)
    assert ack.generation == 4711 and ack.mode == "normal"
    assert ack.device_ids == {"ipad", "kids_tv"} and ack.last_failopen == (5400, 1260)
    assert parse_applied(GOOD.replace(b"\n", b"\r\n")) == ack  # CRLF is accepted


def test_parse_minimal_acknowledgements() -> None:
    ack = parse_applied(b"screentime-applied v1\ngeneration 1\nmode fail-open\nend\n")
    assert ack.mode == "fail-open" and ack.device_ids == frozenset() and ack.last_failopen is None


@pytest.mark.parametrize(
    "body",
    [
        GOOD[:-4],  # truncated: no end line
        GOOD.rstrip(b"\n"),  # no final newline
        GOOD.replace(b"v1", b"v2"),
        GOOD.replace(b"generation 4711", b"generation -1"),
        GOOD.replace(b"generation 4711", b"generation 1234567890123456789"),
        GOOD.replace(b"mode normal", b"mode open"),
        GOOD.replace(b"device ipad", b"device iPad"),
        GOOD.replace(b"device ipad", b"device ipad;reboot"),
        GOOD.replace(b"device ipad", b"device ipad extra"),
        GOOD.replace(b"device kids_tv", b"device ipad"),  # duplicate
        GOOD.replace(b"last-failopen 5400 1260", b"last-failopen 5400"),
        GOOD.replace(b"last-failopen 5400 1260", b"last-failopen 1234567890 1"),
        GOOD.replace(b"device ipad\n", b"device ipad\nlast-failopen 1 1\n"),  # wrong place
        GOOD.replace(b"mode normal\n", b""),
        GOOD.replace(b"ipad", "ipäd".encode()),
        GOOD.replace(b"ipad", b"ip\x00ad"),
        GOOD.replace(b"device ipad\n", b"device ipad\n" * 400),
        b"",
    ],
)
def test_any_deviation_rejects_the_whole_document(body: bytes) -> None:
    with pytest.raises(ProtocolError):
        parse_applied(body)
