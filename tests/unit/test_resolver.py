"""Education allowlist resolver (spec section 14): CNAME/A/AAAA, TTL, failures, last-known-good."""

from __future__ import annotations

import asyncio

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from app.clock import FakeClock
from app.db import Database
from app.firewall.audited import AuditedFirewall
from app.firewall.dry_run import DryRunFirewallAdapter
from app.firewall.resolver import DnsAnswer, DnsFailure, DnsPythonClient, EducationResolver
from tests.conftest import Replace, at, make_config


class ScriptedDns:
    def __init__(self) -> None:
        self.answers: dict[str, DnsAnswer | Exception] = {}
        self.calls = 0

    async def resolve(self, host: str) -> DnsAnswer:
        self.calls += 1
        result = self.answers[host]
        if isinstance(result, Exception):
            raise result
        return result


def build(tmp_path, **overrides):  # type: ignore[no-untyped-def]
    config = make_config(tmp_path, **overrides)
    db = Database(tmp_path / "data" / "r.db")
    db.upgrade()
    clock = FakeClock(at(10))
    adapter = DryRunFirewallAdapter()
    fw = AuditedFirewall(adapter, db, clock, "dry_run")
    dns = ScriptedDns()
    return EducationResolver(config, dns, fw, clock), dns, adapter, clock


A = DnsAnswer(frozenset({"104.18.1.1"}), ("edge.example.net",), 300)
B = DnsAnswer(frozenset({"13.32.1.1", "2600:9000::1"}), (), 60)
C = DnsAnswer(frozenset({"151.101.1.1"}), (), 3600)


def hosts() -> dict[str, DnsAnswer | Exception]:
    return {"www.duolingo.com": A, "d35aaqx5ub95lt.cloudfront.net": B, "www.khanacademy.org": C}


@pytest.mark.anyio
async def test_union_of_all_hosts_replaces_the_table(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, fw, _ = build(tmp_path)
    dns.answers = hosts()
    pushed = await resolver.refresh()
    assert pushed == {"104.18.1.1", "13.32.1.1", "2600:9000::1", "151.101.1.1"}
    assert fw.education == pushed
    status = resolver.hosts["www.duolingo.com"]
    assert (
        status.status == "ok"
        and status.cnames == ["edge.example.net"]
        and status.service == "duolingo"
    )
    assert resolver.unresolved() == [] and resolver.last_push_ok is True


@pytest.mark.anyio
async def test_ipv6_can_be_excluded(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, fw, _ = build(tmp_path, firewall={"include_ipv6_in_education": False})
    dns.answers = hosts()
    await resolver.refresh()
    assert "2600:9000::1" not in fw.education and "13.32.1.1" in fw.education


@pytest.mark.anyio
async def test_transient_failure_keeps_last_known_good_and_logs_staleness(  # type: ignore[no-untyped-def]
    tmp_path, caplog: pytest.LogCaptureFixture
) -> None:
    resolver, dns, fw, clock = build(tmp_path)
    dns.answers = hosts()
    await resolver.refresh()
    dns.answers["www.duolingo.com"] = DnsFailure("SERVFAIL")
    clock.advance(minutes=5)
    with caplog.at_level("WARNING", logger="screentime.resolver"):
        pushed = await resolver.refresh()
    assert "104.18.1.1" in pushed and "104.18.1.1" in fw.education  # last known good retained
    status = resolver.hosts["www.duolingo.com"]
    assert (
        status.status == "stale"
        and status.consecutive_failures == 1
        and "SERVFAIL" in status.last_error
    )
    assert resolver.stale() == [status] and resolver.unresolved() == []
    assert any("ok=false" in r.message and "www.duolingo.com" in r.message for r in caplog.records)
    dns.answers["www.duolingo.com"] = A
    await resolver.refresh()
    assert status.status == "ok" and status.consecutive_failures == 0


@pytest.mark.anyio
async def test_addresses_that_change_are_replaced_not_accumulated(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, fw, _ = build(tmp_path)
    dns.answers = hosts()
    await resolver.refresh()
    dns.answers["www.duolingo.com"] = DnsAnswer(frozenset({"104.18.9.9"}), (), 300)
    await resolver.refresh()
    assert "104.18.9.9" in fw.education and "104.18.1.1" not in fw.education


@pytest.mark.anyio
async def test_nothing_resolved_leaves_the_existing_table_alone(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, fw, _ = build(tmp_path)
    fw.education = {"9.9.9.9"}
    dns.answers = {h: DnsFailure("NXDOMAIN") for h in hosts()}
    assert await resolver.refresh() == set()
    assert fw.education == {"9.9.9.9"}
    assert {s.host for s in resolver.unresolved()} == set(hosts())
    assert resolver.last_push_ok is False and "left unchanged" in resolver.last_push_error


@pytest.mark.anyio
async def test_partial_failure_still_updates_with_what_resolved(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, _fw, _ = build(tmp_path)
    dns.answers = {**hosts(), "www.khanacademy.org": DnsFailure("timeout")}
    pushed = await resolver.refresh()
    assert "151.101.1.1" not in pushed and "104.18.1.1" in pushed
    assert [s.host for s in resolver.unresolved()] == ["www.khanacademy.org"]


@pytest.mark.anyio
async def test_firewall_failure_is_recorded_not_raised(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, fw, _ = build(tmp_path)
    dns.answers = hosts()
    fw.fail_ops = {"replace_education_ips"}
    assert await resolver.refresh() == set()
    assert resolver.last_push_ok is False and "injected" in resolver.last_push_error
    fw.fail_ops = set()
    assert await resolver.refresh()
    assert resolver.last_push_ok is True


@pytest.mark.anyio
async def test_no_hostnames_configured_clears_the_table(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, _, fw, _ = build(tmp_path, always_allowed=Replace())
    fw.education = {"1.1.1.1"}
    await resolver.refresh()
    assert fw.education == set()


@pytest.mark.anyio
async def test_disabled_services_are_not_resolved(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, _, _ = build(
        tmp_path,
        always_allowed=Replace({"duolingo": {"enabled": False, "domains": ["www.duolingo.com"]}}),
    )
    assert resolver.hosts == {}
    await resolver.refresh()
    assert dns.calls == 0


def test_refresh_interval_respects_short_ttls(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, _, _ = build(tmp_path)
    assert resolver.next_interval_seconds() == 300
    dns.answers = hosts()
    asyncio.run(resolver.refresh())
    assert resolver.next_interval_seconds() == 60  # B has a 60s TTL
    for s in resolver.hosts.values():
        s.ttl = 5
    assert resolver.next_interval_seconds() == 60  # never hammer DNS faster than once a minute
    for s in resolver.hosts.values():
        s.ttl = 3600
    assert resolver.next_interval_seconds() == 300  # never slower than the configured refresh


# --- the real dnspython client against a local DNS server -------------------------------------


class MiniDns(asyncio.DatagramProtocol):
    """Authoritative-ish responder: www -> CNAME edge -> A/AAAA; broken -> SERVFAIL; gone -> NXDOMAIN."""

    def connection_made(self, transport) -> None:  # type: ignore[no-untyped-def]
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[no-untyped-def]
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA | dns.flags.RA
        question = query.question[0]
        name = question.name.to_text()
        rdtype = question.rdtype
        if name == "broken.test.":
            response.set_rcode(dns.rcode.SERVFAIL)
        elif name in ("www.test.", "edge.test."):
            if name == "www.test.":
                response.answer.append(
                    dns.rrset.from_text("www.test.", 120, "IN", "CNAME", "edge.test.")
                )
            if rdtype == dns.rdatatype.A:
                response.answer.append(
                    dns.rrset.from_text("edge.test.", 90, "IN", "A", "203.0.113.10", "203.0.113.11")
                )
            elif rdtype == dns.rdatatype.AAAA:
                response.answer.append(
                    dns.rrset.from_text("edge.test.", 90, "IN", "AAAA", "2001:db8::10")
                )
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)
        self.transport.sendto(response.to_wire(), addr)


async def _with_dns(coro_fn):  # type: ignore[no-untyped-def]
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(MiniDns, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    try:
        return await coro_fn(DnsPythonClient(timeout=3, nameservers=["127.0.0.1"], port=port))
    finally:
        transport.close()


def test_dnspython_follows_cname_chains_and_collects_a_and_aaaa() -> None:
    async def scenario(client: DnsPythonClient) -> DnsAnswer:
        return await client.resolve("www.test")

    answer = asyncio.run(_with_dns(scenario))
    assert answer.ips == {"203.0.113.10", "203.0.113.11", "2001:db8::10"}
    assert "edge.test" in answer.cnames
    assert answer.ttl == 90  # the smallest TTL along the chain answer


def test_dnspython_reports_nxdomain_and_servfail_as_failures() -> None:
    async def scenario(client: DnsPythonClient) -> list[str]:
        errors = []
        for host in ("gone.test", "broken.test"):
            try:
                await client.resolve(host)
            except DnsFailure as exc:
                errors.append(str(exc))
        return errors

    errors = asyncio.run(_with_dns(scenario))
    assert len(errors) == 2 and "NXDOMAIN" in errors[0]


def test_resolver_end_to_end_with_real_dns_and_lkg(tmp_path) -> None:  # type: ignore[no-untyped-def]
    async def scenario(client: DnsPythonClient) -> tuple[set[str], set[str], str]:
        config = make_config(
            tmp_path, always_allowed=Replace({"svc": {"enabled": True, "domains": ["www.test"]}})
        )
        db = Database(tmp_path / "data" / "e2e.db")
        db.upgrade()
        clock = FakeClock(at(10))
        adapter = DryRunFirewallAdapter()
        resolver = EducationResolver(
            config, client, AuditedFirewall(adapter, db, clock, "dry_run"), clock
        )
        first = await resolver.refresh()
        client._resolver.nameservers = ["127.0.0.1"]
        client._resolver.port = 1  # nothing listens here: simulates DNS going away
        client._resolver.lifetime = 0.3
        client._resolver.timeout = 0.3
        second = await resolver.refresh()
        return first, second, resolver.hosts["www.test"].status

    first, second, status = asyncio.run(_with_dns(scenario))
    assert first == second == {"203.0.113.10", "203.0.113.11", "2001:db8::10"}
    assert status == "stale"


def edu_pushes(fw: DryRunFirewallAdapter) -> int:
    return sum(1 for call in fw.calls if call[0] == "replace_education_ips")


@pytest.mark.anyio
async def test_an_unchanged_set_is_not_pushed_again(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, fw, clock = build(tmp_path)
    dns.answers = hosts()
    first = await resolver.refresh()
    clock.advance(seconds=60)
    assert await resolver.refresh() == first  # still reports what the table holds
    assert edu_pushes(fw) == 1
    assert dns.calls == 6  # DNS is still refreshed on the usual cadence


@pytest.mark.anyio
async def test_a_changed_set_is_pushed_at_once(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, fw, clock = build(tmp_path)
    dns.answers = hosts()
    await resolver.refresh()
    dns.answers["www.khanacademy.org"] = DnsAnswer(frozenset({"151.101.9.9"}), (), 3600)
    clock.advance(seconds=60)
    await resolver.refresh()
    assert edu_pushes(fw) == 2 and "151.101.9.9" in fw.education


@pytest.mark.anyio
async def test_a_stale_push_is_repeated_to_heal_a_filter_reload(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, fw, clock = build(tmp_path)
    dns.answers = hosts()
    await resolver.refresh()
    fw.wipe()  # pfSense reloaded its filter and emptied the runtime table
    clock.advance(seconds=299)
    await resolver.refresh()
    assert edu_pushes(fw) == 1 and fw.education == set()
    clock.advance(seconds=1)  # education_dns_refresh_seconds (300) since the last push
    await resolver.refresh()
    assert edu_pushes(fw) == 2 and "104.18.1.1" in fw.education


@pytest.mark.anyio
async def test_a_failed_push_is_retried_on_the_next_refresh(tmp_path) -> None:  # type: ignore[no-untyped-def]
    resolver, dns, fw, clock = build(tmp_path)
    dns.answers = hosts()
    await resolver.refresh()
    dns.answers["www.khanacademy.org"] = DnsAnswer(frozenset({"151.101.9.9"}), (), 3600)
    fw.fail_ops = {"replace_education_ips"}
    await resolver.refresh()
    assert resolver.last_push_ok is False
    fw.fail_ops = set()
    clock.advance(seconds=60)
    await resolver.refresh()
    assert resolver.last_push_ok and "151.101.9.9" in fw.education
