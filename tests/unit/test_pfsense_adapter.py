"""PfSenseSshFirewallAdapter: command construction, parsing and failure handling."""

from __future__ import annotations

import sys
from collections.abc import Sequence

import pytest

from app.config import FirewallCfg
from app.firewall.base import FirewallError, validate_ip
from app.firewall.pfsense_ssh import CommandResult, PfSenseSshFirewallAdapter, subprocess_runner


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], bytes | None, float]] = []
        self.responses: list[CommandResult] = []
        self.default = CommandResult(0, "", "")

    async def __call__(
        self, argv: Sequence[str], stdin: bytes | None, timeout: float
    ) -> CommandResult:
        self.calls.append((list(argv), stdin, timeout))
        return self.responses.pop(0) if self.responses else self.default

    def remote(self, index: int = -1) -> str:
        return self.calls[index][0][-1]


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def adapter(runner: FakeRunner) -> PfSenseSshFirewallAdapter:
    return PfSenseSshFirewallAdapter(FirewallCfg(mode="pfsense_ssh"), runner)


@pytest.mark.anyio
async def test_ssh_command_line_is_key_based_non_interactive_and_pinned(
    adapter: PfSenseSshFirewallAdapter, runner: FakeRunner
) -> None:
    await adapter.add_active_ip("192.168.12.30")
    argv = runner.calls[0][0]
    assert argv[0] == "ssh"
    joined = " ".join(argv)
    for expected in (
        "-i /opt/screentime/.ssh/id_ed25519",
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "ConnectTimeout=10",
        "UserKnownHostsFile=/opt/screentime/.ssh/known_hosts",
        "screentime@192.168.12.1",
    ):
        assert expected in joined
    assert argv[-1] == "sudo /usr/local/sbin/screenctl add-active 192.168.12.30"


@pytest.mark.anyio
async def test_sudo_is_optional() -> None:
    runner = FakeRunner()
    adapter = PfSenseSshFirewallAdapter(FirewallCfg(mode="pfsense_ssh", use_sudo=False), runner)
    await adapter.remove_active_ip("192.168.12.31")
    assert runner.remote() == "/usr/local/sbin/screenctl del-active 192.168.12.31"


@pytest.mark.anyio
async def test_each_operation_maps_to_one_fixed_wrapper_command(
    adapter: PfSenseSshFirewallAdapter, runner: FakeRunner
) -> None:
    await adapter.remove_active_ip("192.168.12.30")
    await adapter.kill_states("192.168.12.30")
    await adapter.health()
    assert [c[0][-1].split(" ", 2)[2] for c in runner.calls] == [
        "del-active 192.168.12.30",
        "kill-states 192.168.12.30",
        "health",
    ]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "bad", ["192.168.12.30; reboot", "$(id)", "1.2.3", "", "::1", "192.168.12.30 -f", "a b"]
)
async def test_invalid_addresses_never_reach_the_command_line(
    adapter: PfSenseSshFirewallAdapter, runner: FakeRunner, bad: str
) -> None:
    for call in (adapter.add_active_ip, adapter.remove_active_ip, adapter.kill_states):
        with pytest.raises(FirewallError):
            await call(bad)
    assert runner.calls == []


@pytest.mark.anyio
async def test_get_active_ips_parses_and_ignores_junk(
    adapter: PfSenseSshFirewallAdapter, runner: FakeRunner
) -> None:
    runner.responses.append(CommandResult(0, "192.168.12.30\n\n  192.168.12.40  \nnot-an-ip\n", ""))
    assert await adapter.get_active_ips() == {"192.168.12.30", "192.168.12.40"}


@pytest.mark.anyio
async def test_replace_active_ips_diffs_without_killing_states(
    adapter: PfSenseSshFirewallAdapter, runner: FakeRunner
) -> None:
    runner.responses.append(CommandResult(0, "192.168.12.30\n192.168.12.31\n", ""))
    await adapter.replace_active_ips({"192.168.12.31", "192.168.12.40"})
    assert [c[0][-1].split(" ", 2)[2] for c in runner.calls] == [
        "show-active",
        "add-active 192.168.12.40",
        "del-active 192.168.12.30",
    ]


@pytest.mark.anyio
async def test_replace_education_sends_addresses_on_stdin_only(
    adapter: PfSenseSshFirewallAdapter, runner: FakeRunner
) -> None:
    await adapter.replace_education_ips({"104.18.1.1", "2606:4700::1"})
    argv, stdin, _ = runner.calls[0]
    assert argv[-1].endswith("replace-edu -")
    assert stdin == b"104.18.1.1\n2606:4700::1\n"
    await adapter.replace_education_ips(set())
    assert runner.calls[1][1] == b""


@pytest.mark.anyio
async def test_nonzero_exit_becomes_a_firewall_error_with_the_reason(
    adapter: PfSenseSshFirewallAdapter, runner: FakeRunner
) -> None:
    runner.responses.append(
        CommandResult(255, "", "ssh: connect to host 192.168.12.1 port 22: No route\n")
    )
    with pytest.raises(FirewallError, match="No route"):
        await adapter.add_active_ip("192.168.12.30")
    runner.responses.append(CommandResult(64, "", ""))
    with pytest.raises(FirewallError, match="exit 64"):
        await adapter.kill_states("192.168.12.30")


@pytest.mark.anyio
async def test_health_reports_failure_instead_of_raising(
    adapter: PfSenseSshFirewallAdapter, runner: FakeRunner
) -> None:
    runner.responses.append(CommandResult(0, "ok\n", ""))
    assert (await adapter.health()).ok
    runner.responses.append(CommandResult(255, "", "timeout"))
    result = await adapter.health()
    assert not result.ok and "timeout" in result.detail
    runner.responses.append(CommandResult(0, "weird\n", ""))
    assert not (await adapter.health()).ok


def test_only_fixed_operations_can_be_built(adapter: PfSenseSshFirewallAdapter) -> None:
    with pytest.raises(FirewallError):
        adapter.build_argv("flush-all")
    with pytest.raises(FirewallError):
        adapter.build_argv("add-active; reboot")


def test_validate_ip_canonicalises_and_restricts_v6() -> None:
    assert (
        validate_ip("192.168.012.030".replace("012", "12").replace("030", "30")) == "192.168.12.30"
    )
    assert validate_ip("2606:4700:0:0::1", allow_v6=True) == "2606:4700::1"
    with pytest.raises(FirewallError):
        validate_ip("2606:4700::1")


# --- the real subprocess runner ---------------------------------------------------------------


@pytest.mark.anyio
async def test_subprocess_runner_captures_output_and_stdin() -> None:
    code = "import sys; d = sys.stdin.read(); print('got', d.strip()); sys.stderr.write('warn'); sys.exit(3)"
    result = await subprocess_runner([sys.executable, "-c", code], b"hello", 10)
    assert (
        result.returncode == 3 and result.stdout.strip() == "got hello" and result.stderr == "warn"
    )


@pytest.mark.anyio
async def test_subprocess_runner_kills_on_timeout() -> None:
    with pytest.raises(FirewallError, match="timed out"):
        await subprocess_runner([sys.executable, "-c", "import time; time.sleep(30)"], None, 0.3)


@pytest.mark.anyio
async def test_subprocess_runner_reports_missing_binary() -> None:
    with pytest.raises(FirewallError, match="cannot execute"):
        await subprocess_runner(["/nonexistent/ssh"], None, 5)
