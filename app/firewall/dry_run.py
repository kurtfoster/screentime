"""In-memory firewall used for development and tests (spec section 25).

It behaves like the pfSense applier: each publication replaces the active set, connections of
devices that left it are killed, and the result is acknowledged at once, so the user
interface and the test suite run without pfSense. It records every call so tests can assert
what pfSense would have done, and it can be told to fail or to stop acknowledging.
"""

from __future__ import annotations

from app.firewall.base import (
    AppliedState,
    DesiredState,
    FirewallError,
    FirewallHealth,
    GenerationSource,
    MemoryGenerations,
    validate_ip,
)


class DryRunFirewallAdapter:
    def __init__(self, generations: GenerationSource | None = None) -> None:
        self.generations: GenerationSource = generations or MemoryGenerations()
        self.active: set[str] = set()
        self.active_devices: frozenset[str] = frozenset()
        self.leases: dict[str, int] = {}
        self.education: set[str] = set()
        self.calls: list[tuple[str, ...]] = []
        self.fail_all = False
        self.fail_ops: set[str] = set()
        # False simulates a firewall that still fetches but no longer applies or acknowledges
        # (fail_all simulates one that cannot be reached at all).
        self.acknowledge = True
        self._applied: AppliedState | None = None

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
        """Calls that changed something (what pfSense would have done), for concise assertions."""
        return [c for c in self.calls if c[0] in {"apply", "kill_states", "replace_education_ips"}]

    async def publish(self, desired: DesiredState) -> int:
        self._record("publish")
        generation = self.generations.next(desired.device_ids)
        if not self.acknowledge:
            return generation
        ips = {validate_ip(ip) for ip in desired.ips}
        if ips != self.active:
            self.calls.append(("apply", *sorted(ips)))
        for gone in sorted(self.active - ips):
            self.calls.append(("kill_states", gone))
        self.active = ips
        self.active_devices = desired.device_ids
        self.leases = {lease.device_id: lease.seconds for lease in desired.leases}
        self._applied = AppliedState(generation, "normal", desired.device_ids)
        return generation

    async def applied(self) -> AppliedState | None:
        return self._applied

    async def health(self) -> FirewallHealth:
        self.calls.append(("health",))
        if self.fail_all or "health" in self.fail_ops:
            return FirewallHealth(ok=False, detail="dry-run injected failure")
        return FirewallHealth(ok=True, detail="dry-run")

    async def replace_education_ips(self, ips: set[str]) -> None:
        canonical = {validate_ip(ip, allow_v6=True) for ip in ips}
        self._record("replace_education_ips", *sorted(canonical))
        self.education = canonical
