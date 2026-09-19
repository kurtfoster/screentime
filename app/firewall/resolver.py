"""Education allowlist resolver (spec section 14).

YAML lists hostnames; this turns them into destination IPs for the ``SCR_EDU_ALLOW``
table. It is deliberately empirical: last-known-good addresses are kept through DNS
blips, staleness is logged, and the parent diagnostics page shows every hostname.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from app.clock import Clock
from app.config import AppConfig
from app.firewall.audited import AuditedFirewall
from app.firewall.base import FirewallError

log = logging.getLogger("screentime.resolver")

MIN_REFRESH_SECONDS = 60


class DnsFailure(Exception):
    """A hostname could not be resolved."""


@dataclass(frozen=True)
class DnsAnswer:
    ips: frozenset[str]
    cnames: tuple[str, ...] = ()
    ttl: int | None = None


class DnsClient(Protocol):
    async def resolve(self, host: str) -> DnsAnswer: ...


class DnsPythonClient:
    """Resolve A and AAAA records through the system resolver, following CNAME chains."""

    def __init__(self, timeout: float = 5.0) -> None:
        import dns.asyncresolver

        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout

    async def resolve(self, host: str) -> DnsAnswer:
        import dns.exception
        import dns.resolver

        ips: set[str] = set()
        cnames: list[str] = []
        ttls: list[int] = []
        errors: list[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                answer = await self._resolver.resolve(host, rdtype)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as exc:
                errors.append(f"{rdtype}: {exc.__class__.__name__}")
                continue
            except dns.exception.DNSException as exc:
                errors.append(f"{rdtype}: {exc.__class__.__name__}")
                continue
            ips.update(str(rdata) for rdata in answer)
            if answer.rrset is not None:
                ttls.append(int(answer.rrset.ttl))
            chain = getattr(answer, "chaining_result", None)
            if chain is not None:
                for rrset in chain.cnames:
                    for item in rrset:
                        target = str(item.target).rstrip(".")
                        if target not in cnames:
                            cnames.append(target)
        if not ips:
            raise DnsFailure("; ".join(errors) or "no addresses")
        return DnsAnswer(frozenset(ips), tuple(cnames), min(ttls) if ttls else None)


@dataclass
class HostStatus:
    host: str
    service: str
    status: str = "pending"  # pending | ok | stale | failed
    ips: set[str] = field(default_factory=set)
    cnames: list[str] = field(default_factory=list)
    ttl: int | None = None
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    consecutive_failures: int = 0
    last_error: str = ""


class EducationResolver:
    def __init__(
        self, config: AppConfig, dns: DnsClient, firewall: AuditedFirewall, clock: Clock
    ) -> None:
        self._cfg = config
        self._dns = dns
        self._fw = firewall
        self._clock = clock
        self.hosts: dict[str, HostStatus] = {
            host: HostStatus(host, service) for host, service in config.education_hosts().items()
        }
        self.last_refresh_at: datetime | None = None
        self.last_push_at: datetime | None = None
        self.last_push_ok: bool | None = None
        self.last_push_error = ""
        self.pushed: set[str] = set()
        self._pushed_once = False

    def _wanted(self, ip: str) -> bool:
        return self._cfg.firewall.include_ipv6_in_education or ":" not in ip

    async def _resolve_one(self, status: HostStatus, sem: asyncio.Semaphore) -> None:
        async with sem:
            status.last_attempt_at = self._clock.now()
            try:
                answer = await self._dns.resolve(status.host)
            except Exception as exc:
                status.consecutive_failures += 1
                status.last_error = str(exc) or exc.__class__.__name__
                status.status = "stale" if status.ips else "failed"
                log.warning(
                    "resolve host=%s ok=false failures=%d error=%s kept_ips=%d",
                    status.host,
                    status.consecutive_failures,
                    status.last_error,
                    len(status.ips),
                )
                return
            status.ips = {ip for ip in answer.ips if self._wanted(ip)}
            status.cnames = list(answer.cnames)
            status.ttl = answer.ttl
            status.status = "ok"
            status.last_success_at = status.last_attempt_at
            status.consecutive_failures = 0
            status.last_error = ""
            log.info(
                "resolve host=%s ok=true ips=%d cnames=%s ttl=%s",
                status.host,
                len(status.ips),
                ",".join(status.cnames),
                status.ttl,
            )

    def union(self) -> set[str]:
        merged: set[str] = set()
        for status in self.hosts.values():
            merged |= status.ips
        return merged

    async def refresh(self) -> set[str]:
        """Resolve every host, then replace the pf table atomically. Returns the pushed set."""
        sem = asyncio.Semaphore(8)
        await asyncio.gather(*(self._resolve_one(s, sem) for s in self.hosts.values()))
        self.last_refresh_at = self._clock.now()
        merged = self.union()
        if self.hosts and not merged:
            # Nothing has ever resolved: keep whatever pf already holds rather than emptying it.
            self.last_push_ok = False
            self.last_push_error = "no hostname has resolved yet; table left unchanged"
            log.error("education table not replaced: %s", self.last_push_error)
            return set()
        try:
            await self._fw.replace_education_ips(merged)
        except FirewallError as exc:
            self.last_push_ok = False
            self.last_push_error = str(exc)
            log.error("education table update failed: %s", exc)
            return set()
        self.last_push_at = self._clock.now()
        self.last_push_ok = True
        self.last_push_error = ""
        self.pushed = merged
        self._pushed_once = True
        return merged

    def next_interval_seconds(self) -> float:
        """Refresh at the configured interval, sooner if a record's TTL is shorter."""
        base = float(self._cfg.firewall.education_dns_refresh_seconds)
        ttls = [s.ttl for s in self.hosts.values() if s.status == "ok" and s.ttl]
        if ttls:
            return float(max(MIN_REFRESH_SECONDS, min(base, min(ttls))))
        return base

    def unresolved(self) -> list[HostStatus]:
        return [s for s in self.hosts.values() if s.status in {"failed", "pending"}]

    def stale(self) -> list[HostStatus]:
        return [s for s in self.hosts.values() if s.status == "stale"]
