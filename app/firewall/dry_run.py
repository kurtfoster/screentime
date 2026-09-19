"""In-memory firewall used for development and tests.

It records every call so tests can assert the add/remove/kill sequence, and it can be
told to fail so fail-closed behaviour can be exercised.
"""

from __future__ import annotations

from app.firewall.base import FirewallError, FirewallHealth, validate_ip


class DryRunFirewallAdapter:
    def __init__(self) -> None:
        self.active: set[str] = set()
        self.education: set[str] = set()
        self.calls: list[tuple[str, ...]] = []
        self.fail_all = False
        self.fail_ops: set[str] = set()

    def _record(self, op: str, *args: str) -> None:
        self.calls.append((op, *args))
        if self.fail_all or op in self.fail_ops:
            raise FirewallError(f"dry-run injected failure for {op}")

    def wipe(self) -> None:
        """Simulate a pfSense filter reload wiping dynamic table contents."""
        self.active.clear()
        self.education.clear()

    def clear_calls(self) -> None:
        self.calls.clear()

    def ops(self) -> list[tuple[str, ...]]:
        """Calls excluding read-only ones, for concise assertions."""
        return [c for c in self.calls if c[0] not in {"health", "get_active_ips"}]

    async def health(self) -> FirewallHealth:
        self.calls.append(("health",))
        if self.fail_all or "health" in self.fail_ops:
            return FirewallHealth(ok=False, detail="dry-run injected failure")
        return FirewallHealth(ok=True, detail="dry-run")

    async def get_active_ips(self) -> set[str]:
        self._record("get_active_ips")
        return set(self.active)

    async def replace_active_ips(self, ips: set[str]) -> None:
        canonical = {validate_ip(ip) for ip in ips}
        self._record("replace_active_ips", *sorted(canonical))
        self.active = canonical

    async def add_active_ip(self, ip: str) -> None:
        ip = validate_ip(ip)
        self._record("add_active_ip", ip)
        self.active.add(ip)

    async def remove_active_ip(self, ip: str) -> None:
        ip = validate_ip(ip)
        self._record("remove_active_ip", ip)
        self.active.discard(ip)

    async def kill_states(self, ip: str) -> None:
        ip = validate_ip(ip)
        self._record("kill_states", ip)

    async def replace_education_ips(self, ips: set[str]) -> None:
        canonical = {validate_ip(ip, allow_v6=True) for ip in ips}
        self._record("replace_education_ips", *sorted(canonical))
        self.education = canonical
