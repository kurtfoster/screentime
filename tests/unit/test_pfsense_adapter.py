"""PfSenseSshFirewallAdapter: command construction, parsing and failure handling."""

from __future__ import annotations

import shutil
import sys
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path

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


# --- connection multiplexing (CHG-03) --------------------------------------------------------


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """Control sockets must fit the Unix socket path limit; pytest's tmp_path names do not."""
    base = Path(tempfile.mkdtemp(prefix="stm", dir="/tmp"))
    yield base
    shutil.rmtree(base, ignore_errors=True)


def muxed(base, runner: FakeRunner, **cfg: object) -> PfSenseSshFirewallAdapter:  # type: ignore[no-untyped-def]
    return PfSenseSshFirewallAdapter(
        FirewallCfg(mode="pfsense_ssh", **cfg),  # type: ignore[arg-type]
        runner,
        control_dir=base / "data" / "ssh-mux",
    )


@pytest.mark.anyio
async def test_calls_share_one_connection_through_a_private_control_socket(short_dir) -> None:  # type: ignore[no-untyped-def]
    runner = FakeRunner()
    await muxed(short_dir, runner).add_active_ip("192.168.12.30")
    joined = " ".join(runner.calls[0][0])
    control = short_dir / "data" / "ssh-mux"
    assert "ControlMaster=auto" in joined and "ControlPersist=10m" in joined
    assert f"ControlPath={control}/%C" in joined and "ServerAliveInterval=10" in joined
    assert control.is_dir() and control.stat().st_mode & 0o777 == 0o700
    assert runner.remote() == "sudo /usr/local/sbin/screenctl add-active 192.168.12.30"
    assert len(runner.calls) == 1


@pytest.mark.anyio
async def test_multiplexing_can_be_switched_off(short_dir) -> None:  # type: ignore[no-untyped-def]
    runner = FakeRunner()
    await muxed(short_dir, runner, ssh_multiplex=False).add_active_ip("192.168.12.30")
    assert "Control" not in " ".join(runner.calls[0][0])
    assert not (short_dir / "data" / "ssh-mux").exists()


@pytest.mark.anyio
async def test_a_stale_master_is_bypassed_once_before_failing(short_dir) -> None:  # type: ignore[no-untyped-def]
    runner = FakeRunner()
    runner.responses = [
        CommandResult(255, "", "mux_client_request_session: read from master failed"),
        CommandResult(0, "192.168.12.30\n", ""),
    ]
    assert await muxed(short_dir, runner).get_active_ips() == {"192.168.12.30"}
    first, second = (" ".join(c[0]) for c in runner.calls)
    assert "ControlMaster=auto" in first
    assert "ControlMaster=no" in second and "ControlPath=none" in second


@pytest.mark.anyio
async def test_only_one_retry_and_only_for_transport_errors(short_dir) -> None:  # type: ignore[no-untyped-def]
    runner = FakeRunner()
    runner.responses = [CommandResult(255, "", "a"), CommandResult(255, "", "Connection refused")]
    with pytest.raises(FirewallError, match="exit 255"):
        await muxed(short_dir, runner).add_active_ip("192.168.12.30")
    assert len(runner.calls) == 2

    wrapper_refusal = FakeRunner()
    wrapper_refusal.responses = [CommandResult(64, "", "screenctl: refused")]
    with pytest.raises(FirewallError, match="exit 64"):
        await muxed(short_dir, wrapper_refusal).add_active_ip("192.168.12.30")
    assert len(wrapper_refusal.calls) == 1  # the wrapper answered: nothing to retry


@pytest.mark.anyio
async def test_a_hung_master_is_retried_without_it(short_dir) -> None:  # type: ignore[no-untyped-def]
    calls: list[list[str]] = []

    async def runner(argv, stdin, timeout):  # type: ignore[no-untyped-def]
        calls.append(list(argv))
        if len(calls) == 1:
            raise FirewallError("ssh timed out after 15s")
        return CommandResult(0, "ok\n", "")

    adapter = PfSenseSshFirewallAdapter(
        FirewallCfg(mode="pfsense_ssh"), runner, control_dir=short_dir / "mux"
    )
    assert (await adapter.health()).ok
    assert "ControlMaster=no" in " ".join(calls[1])


@pytest.mark.anyio
async def test_timeouts_without_multiplexing_are_not_retried(runner: FakeRunner) -> None:
    calls = 0

    async def failing(argv, stdin, timeout):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        raise FirewallError("ssh timed out after 15s")

    adapter = PfSenseSshFirewallAdapter(FirewallCfg(mode="pfsense_ssh"), failing)
    with pytest.raises(FirewallError):
        await adapter.kill_states("192.168.12.30")
    assert calls == 1


@pytest.mark.anyio
async def test_education_payload_is_resent_on_the_retry(short_dir) -> None:  # type: ignore[no-untyped-def]
    runner = FakeRunner()
    runner.responses = [CommandResult(255, "", "x"), CommandResult(0, "", "")]
    await muxed(short_dir, runner).replace_education_ips({"1.1.1.1"})
    assert [c[1] for c in runner.calls] == [b"1.1.1.1\n", b"1.1.1.1\n"]


def test_a_control_path_too_long_for_a_socket_disables_multiplexing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    runner = FakeRunner()
    long_dir = tmp_path / ("x" * 60) / "ssh-mux"
    with caplog.at_level("WARNING", logger="screentime.firewall"):
        adapter = PfSenseSshFirewallAdapter(
            FirewallCfg(mode="pfsense_ssh"), runner, control_dir=long_dir
        )
    assert "Control" not in " ".join(adapter.build_argv("health"))
    assert any("multiplexing disabled" in r.message for r in caplog.records)


def test_the_production_control_path_fits() -> None:
    adapter = PfSenseSshFirewallAdapter(
        FirewallCfg(mode="pfsense_ssh"),
        FakeRunner(),
        control_dir=Path("/opt/screentime/data/ssh-mux"),
    )
    assert adapter._control_dir is not None
