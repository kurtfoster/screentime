"""Firewall adapter contract (spec section 13.1).

No route or business logic may run firewall commands directly; everything goes
through a :class:`FirewallAdapter`. Adapters raise :class:`FirewallError` on any
failure so callers can fail closed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class FirewallError(Exception):
    """A firewall operation failed (unreachable, rejected, timed out)."""


@dataclass(frozen=True)
class FirewallHealth:
    ok: bool
    detail: str = ""
    latency_ms: int = 0


@runtime_checkable
class FirewallAdapter(Protocol):
    async def health(self) -> FirewallHealth: ...

    async def get_active_ips(self) -> set[str]: ...

    async def replace_active_ips(self, ips: set[str]) -> None: ...

    async def add_active_ip(self, ip: str) -> None: ...

    async def remove_active_ip(self, ip: str) -> None: ...

    async def kill_states(self, ip: str) -> None: ...

    async def replace_education_ips(self, ips: set[str]) -> None: ...


def validate_ip(value: str, *, allow_v6: bool = False) -> str:
    """Return the canonical form of ``value`` or raise :class:`FirewallError`."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise FirewallError(f"invalid IP address {value!r}") from exc
    if address.version == 6 and not allow_v6:
        raise FirewallError(f"IPv6 address {value!r} not permitted here")
    return str(address)
