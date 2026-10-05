"""The desired-state and acknowledgement documents exchanged with pfSense (plan 6.3).

Both are small, line-based US-ASCII documents with a fixed first and last line. Parsing is
all-or-nothing: any unexpected line, character or size rejects the whole document, so a
truncated or tampered acknowledgement is never half-applied. The pfSense side has its own
parser for the desired document (deploy/pfsense-screentime-pull.sh); this module renders it.

Acknowledgement, in this order (optional lines marked ?, repeated lines *)::

    screentime-applied v1
    generation <1-18 digits>
    mode normal|grace|fail-open|fail-closed
    ? stale <grace seconds> open|closed           pfSense's STALE_GRACE and STALE_POLICY
    ? last-failopen <started seconds ago> <duration seconds>
    * device <id>                                  devices with a lease now
    * known <id> <ipv4> personal|tv                pfSense's device map
    end

``stale`` and ``known`` extend the plan's grammar: without them the controller could not
check that its copy of the grace period and its device list match pfSense (C9).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.firewall.base import AppliedMode, DesiredState

MAX_DOCUMENT_BYTES = 4096
DEVICE_ID_RE = re.compile(r"^[a-z0-9_]{1,32}$")
_GENERATION_RE = re.compile(r"^[0-9]{1,18}$")
_SECONDS_AGO_RE = re.compile(r"^[0-9]{1,9}$")
# fail-closed: STALE_POLICY=closed past the grace period (nothing allowed).
_MODES: frozenset[str] = frozenset({"normal", "grace", "fail-open", "fail-closed"})
_IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$"
)

DESIRED_HEADER = "screentime-desired v1"
APPLIED_HEADER = "screentime-applied v1"
END = "end"


class ProtocolError(ValueError):
    """A document does not follow the grammar; the message never repeats its content."""


@dataclass(frozen=True)
class Acknowledgement:
    generation: int
    mode: AppliedMode
    device_ids: frozenset[str]
    # The most recent fail-open episode that has ended, in seconds relative to sending:
    # (started this many seconds ago, lasted this many seconds). Relative, so the two
    # clocks are never compared.
    last_failopen: tuple[int, int] | None = None
    # pfSense's STALE_GRACE seconds and STALE_POLICY, when it reports them.
    stale: tuple[int, str] | None = None
    # pfSense's device map: id -> (address, "personal" or "tv"), when it reports it.
    known: dict[str, tuple[str, str]] | None = None


def render_desired(generation: int, desired: DesiredState) -> str:
    lines = [DESIRED_HEADER, f"generation {generation}"]
    for lease in sorted(desired.leases, key=lambda x: x.device_id):
        if not DEVICE_ID_RE.match(lease.device_id) or lease.seconds < 1:
            raise ProtocolError("a lease cannot be expressed in the desired-state grammar")
        lines.append(f"device {lease.device_id} {lease.seconds}")
    lines.append(END)
    text = "\n".join(lines) + "\n"
    if len(text.encode("ascii")) > MAX_DOCUMENT_BYTES:
        raise ProtocolError("the desired state does not fit in 4,096 bytes")
    return text


def parse_applied(body: bytes) -> Acknowledgement:
    """Parse an acknowledgement strictly. LF and CRLF line endings are both accepted."""
    if len(body) > MAX_DOCUMENT_BYTES:
        raise ProtocolError("acknowledgement too large")
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("acknowledgement is not US-ASCII") from exc
    text = text.replace("\r\n", "\n")
    if not text.endswith("\n"):
        raise ProtocolError("acknowledgement does not end with a newline")
    lines = text[:-1].split("\n")
    if any(not line.isprintable() for line in lines):
        raise ProtocolError("acknowledgement contains control characters")
    if len(lines) < 4 or lines[0] != APPLIED_HEADER or lines[-1] != END:
        raise ProtocolError("acknowledgement header or end line missing")

    generation_line, mode_line, rest = lines[1], lines[2], lines[3:-1]
    key, _, value = generation_line.partition(" ")
    if key != "generation" or not _GENERATION_RE.match(value):
        raise ProtocolError("bad generation line")
    key, _, mode = mode_line.partition(" ")
    if key != "mode" or mode not in _MODES:
        raise ProtocolError("bad mode line")

    stale: tuple[int, str] | None = None
    if rest and rest[0].startswith("stale "):
        parts = rest[0].split(" ")
        if (
            len(parts) != 3
            or not _SECONDS_AGO_RE.match(parts[1])
            or parts[2]
            not in {
                "open",
                "closed",
            }
        ):
            raise ProtocolError("bad stale line")
        stale = (int(parts[1]), parts[2])
        rest = rest[1:]

    last_failopen: tuple[int, int] | None = None
    if rest and rest[0].startswith("last-failopen "):
        parts = rest[0].split(" ")
        if len(parts) != 3 or not all(_SECONDS_AGO_RE.match(p) for p in parts[1:]):
            raise ProtocolError("bad last-failopen line")
        last_failopen = (int(parts[1]), int(parts[2]))
        rest = rest[1:]

    devices: set[str] = set()
    while rest and rest[0].startswith("device "):
        parts = rest.pop(0).split(" ")
        if len(parts) != 2 or not DEVICE_ID_RE.match(parts[1]):
            raise ProtocolError("bad device line")
        if parts[1] in devices:
            raise ProtocolError("duplicate device line")
        devices.add(parts[1])

    known: dict[str, tuple[str, str]] | None = None
    for line in rest:
        parts = line.split(" ")
        if (
            len(parts) != 4
            or parts[0] != "known"
            or not DEVICE_ID_RE.match(parts[1])
            or not _IPV4_RE.match(parts[2])
            or parts[3] not in {"personal", "tv"}
        ):
            raise ProtocolError("bad line")
        known = known if known is not None else {}
        if parts[1] in known:
            raise ProtocolError("duplicate known line")
        known[parts[1]] = (parts[2], parts[3])
    return Acknowledgement(int(value), mode, frozenset(devices), last_failopen, stale, known)  # type: ignore[arg-type]
