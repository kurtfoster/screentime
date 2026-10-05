"""Firewall adapter contract (spec section 13.1, v1.2 plan 6.6).

The contract is declarative. The application publishes the complete desired state (which
devices may use the Internet, each with a lease in seconds); the firewall makes itself match
and acknowledges what it applied. Nothing in the application adds, removes or kills
individually, so an adapter cannot silently skip a step (LSP): revocation and the killing of
existing connections are the firewall's own job when a device leaves the set.

No route or business logic talks to a firewall directly; everything goes through a
:class:`FirewallAdapter`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

AppliedMode = Literal["normal", "grace", "fail-open", "fail-closed"]


class FirewallError(Exception):
    """A firewall operation failed (unreachable, rejected, timed out)."""


@dataclass(frozen=True)
class Lease:
    """One device the firewall should allow for ``seconds`` from when it applies the state."""

    device_id: str
    ip: str
    seconds: int


@dataclass(frozen=True)
class DesiredState:
    leases: tuple[Lease, ...] = ()

    @property
    def device_ids(self) -> frozenset[str]:
        return frozenset(lease.device_id for lease in self.leases)

    @property
    def ips(self) -> frozenset[str]:
        return frozenset(lease.ip for lease in self.leases)


@dataclass(frozen=True)
class AppliedState:
    """What the firewall last reported having applied."""

    generation: int
    mode: AppliedMode
    device_ids: frozenset[str]
    # When the acknowledgement arrived, by this controller's clock. None means "at once"
    # (the dry-run adapter acknowledges inside publish()).
    received_at: datetime | None = None


@dataclass(frozen=True)
class FirewallHealth:
    ok: bool
    detail: str = ""
    latency_ms: int = 0


@runtime_checkable
class FirewallAdapter(Protocol):
    async def publish(self, desired: DesiredState) -> int:
        """Make ``desired`` the state the firewall should apply; returns its generation."""
        ...

    async def applied(self) -> AppliedState | None:
        """The latest acknowledgement, or None if the firewall has not acknowledged yet."""
        ...

    async def health(self) -> FirewallHealth: ...


class GenerationSource(Protocol):
    def next(self, device_ids: frozenset[str]) -> int:
        """The generation for this device set: unchanged set, same number; changed, the next."""
        ...


class MemoryGenerations:
    """Generation counter for tests and the dry-run adapter on its own."""

    def __init__(self) -> None:
        self._generation = 0
        self._devices: frozenset[str] | None = None

    def next(self, device_ids: frozenset[str]) -> int:
        if device_ids != self._devices:
            self._generation += 1
            self._devices = device_ids
        return self._generation


def validate_ip(value: str, *, allow_v6: bool = False) -> str:
    """Return the canonical form of ``value`` or raise :class:`FirewallError`."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise FirewallError(f"invalid IP address {value!r}") from exc
    if address.version == 6 and not allow_v6:
        raise FirewallError(f"IPv6 address {value!r} not permitted here")
    return str(address)
