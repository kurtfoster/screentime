"""Production adapter: drives pfSense through the root-owned ``screenctl`` wrapper over SSH.

This is the only place the system OpenSSH client is invoked. Operation names are drawn
from a fixed set and every address is validated before it reaches the command line, so
no caller-supplied text is ever interpreted by a remote shell.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from app.config import FirewallCfg
from app.firewall.base import FirewallError, FirewallHealth, validate_ip

log = logging.getLogger("screentime.firewall")

_OPS = frozenset(
    {"health", "show-active", "add-active", "del-active", "kill-states", "replace-edu"}
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], bytes | None, float], Awaitable[CommandResult]]


async def subprocess_runner(
    argv: Sequence[str], stdin: bytes | None, timeout: float
) -> CommandResult:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        raise FirewallError(f"cannot execute {argv[0]}: {exc.strerror}") from exc
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout)
    except TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        await proc.wait()
        raise FirewallError(f"ssh timed out after {timeout:.0f}s") from exc
    return CommandResult(
        proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")
    )


class PfSenseSshFirewallAdapter:
    def __init__(self, cfg: FirewallCfg, runner: Runner | None = None) -> None:
        self._cfg = cfg
        self._runner: Runner = runner or subprocess_runner

    def _known_hosts(self) -> str:
        if self._cfg.ssh_known_hosts_path:
            return self._cfg.ssh_known_hosts_path
        return str(Path(self._cfg.ssh_key_path).parent / "known_hosts")

    def build_argv(self, op: str, arg: str | None = None) -> list[str]:
        if op not in _OPS:
            raise FirewallError(f"operation {op!r} is not permitted")
        remote = [self._cfg.command, op]
        if arg is not None:
            remote.append(arg)
        if self._cfg.use_sudo:
            remote.insert(0, "sudo")
        return [
            "ssh",
            "-i", self._cfg.ssh_key_path,
            "-p", str(self._cfg.ssh_port),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={self._cfg.ssh_timeout_seconds}",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={self._known_hosts()}",
            "-o", "LogLevel=ERROR",
            f"{self._cfg.ssh_user}@{self._cfg.host}",
            " ".join(remote),
        ]  # fmt: skip

    async def _run(self, op: str, arg: str | None = None, stdin: bytes | None = None) -> str:
        argv = self.build_argv(op, arg)
        timeout = float(self._cfg.ssh_timeout_seconds) + 5.0
        result = await self._runner(argv, stdin, timeout)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            raise FirewallError(
                f"screenctl {op} failed (exit {result.returncode}): {detail[-1] if detail else 'no output'}"
            )
        return result.stdout

    async def health(self) -> FirewallHealth:
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            out = await self._run("health")
        except FirewallError as exc:
            return FirewallHealth(ok=False, detail=str(exc))
        elapsed = int((loop.time() - started) * 1000)
        ok = out.strip().startswith("ok")
        return FirewallHealth(ok=ok, detail=out.strip()[:200], latency_ms=elapsed)

    async def get_active_ips(self) -> set[str]:
        out = await self._run("show-active")
        ips: set[str] = set()
        for line in out.splitlines():
            token = line.strip()
            if not token:
                continue
            try:
                ips.add(validate_ip(token))
            except FirewallError:
                log.warning("ignoring unparseable table entry from pfSense: %r", token[:64])
        return ips

    async def replace_active_ips(self, ips: set[str]) -> None:
        """Converge the active table on ``ips`` using add/del (no state kills)."""
        desired = {validate_ip(ip) for ip in ips}
        current = await self.get_active_ips()
        for ip in sorted(desired - current):
            await self.add_active_ip(ip)
        for ip in sorted(current - desired):
            await self.remove_active_ip(ip)

    async def add_active_ip(self, ip: str) -> None:
        await self._run("add-active", validate_ip(ip))

    async def remove_active_ip(self, ip: str) -> None:
        await self._run("del-active", validate_ip(ip))

    async def kill_states(self, ip: str) -> None:
        await self._run("kill-states", validate_ip(ip))

    async def replace_education_ips(self, ips: set[str]) -> None:
        canonical = sorted({validate_ip(ip, allow_v6=True) for ip in ips})
        payload = ("\n".join(canonical) + "\n").encode() if canonical else b""
        await self._run("replace-edu", "-", stdin=payload)
