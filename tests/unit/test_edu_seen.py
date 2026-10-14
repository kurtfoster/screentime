"""deploy/pfsense-screentime-edu-seen.sh against stub pfctl, drill, logger and lockf.

Runs under bash and, when installed, dash (the Trixie container has it). FreeBSD sh itself is
covered by `screentime-edu-seen --self-test` on pfSense in Phase B. Time is fixed per run with
SCREENTIME_SEEN_NOW, which, like every stub, is honoured only for a non-root user.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "pfsense-screentime-edu-seen.sh"
SHELLS = [s for s in ("bash", "dash") if shutil.which(s)]
KEEP = 4 * 3600

PFCTL = """#!/bin/sh
echo "$*" >> "$STUB/pfctl.log"
case "$*" in
  *"-T replace -f "*) cp "$6" "$STUB/table" ;;
  *"-T flush") : > "$STUB/table" ;;
  *"-T show") cat "$STUB/table" 2>/dev/null ;;
esac
exit 0
"""

# drill stub: prints the answer section from $STUB/dns.<name>, then an authority section whose
# A record must never be taken.
DRILL = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB/drill.log"
[ -f "$STUB/dns.$1" ] || exit 0
echo ';; ANSWER SECTION:'
cat "$STUB/dns.$1"
echo ''
echo ';; AUTHORITY SECTION:'
echo 'ns.example. 60 IN A 9.9.9.9'
"""
LOGGER = """#!/bin/sh
echo "$*" >> "$STUB/syslog"
"""
LOCKF = """#!/bin/sh
echo "$*" > "$STUB/lockf.args"
[ -f "$STUB/busy" ] && exit 75
shift 4
exec "$@"
"""

FILTERDNS = """pf soraapp.com SCR_EDU_ALLOW
pf SCR_EDU_ALLOW read.soraapp.com
pf other.example.com SOME_OTHER_ALIAS
"""


class Seen:
    def __init__(self, tmp: Path, shell: str) -> None:
        self.shell = shell
        self.stub = tmp / "stub"
        self.stub.mkdir()
        self.state = tmp / "state"
        self.state.mkdir(mode=0o700)
        for name, body in (
            ("pfctl", PFCTL),
            ("drill", DRILL),
            ("logger", LOGGER),
            ("lockf", LOCKF),
        ):
            path = self.stub / name
            path.write_text(body)
            path.chmod(0o755)
        self.filterdns = tmp / "filterdns.conf"
        self.filterdns.write_text(FILTERDNS)

    def answer(self, name: str, *addresses: str, cname: str = "") -> None:
        lines = [f"{name}. 60 IN CNAME {cname}." if cname else ""]
        owner = cname or name
        lines += [f"{owner}. 60 IN A {ip}" for ip in addresses]
        (self.stub / f"dns.{name}").write_text("\n".join(ln for ln in lines if ln) + "\n")

    def run(self, now: int, *args: str, lock: bool = False) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": os.environ["PATH"],
            "STUB": str(self.stub),
            "SCREENTIME_SEEN_FILTERDNS": str(self.filterdns),
            "SCREENTIME_SEEN_STATE": str(self.state),
            "SCREENTIME_SEEN_PFCTL": str(self.stub / "pfctl"),
            "SCREENTIME_SEEN_DRILL": str(self.stub / "drill"),
            "SCREENTIME_SEEN_LOGGER": str(self.stub / "logger"),
            "SCREENTIME_SEEN_LOCKF": str(self.stub / "lockf"),
            "SCREENTIME_SEEN_NOW": str(now),
            "SCREENTIME_SEEN_PASSES": "1",
        }
        if not lock:
            environment["SCREENTIME_SEEN_LOCKED"] = "1"
        return subprocess.run(
            [self.shell, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
            check=False,
        )

    def table(self) -> list[str]:
        path = self.stub / "table"
        return sorted(path.read_text().split()) if path.exists() else []

    def queried(self) -> list[str]:
        log = self.stub / "drill.log"
        return [ln.split()[0] for ln in log.read_text().splitlines()] if log.exists() else []

    def syslog(self) -> str:
        log = self.stub / "syslog"
        return log.read_text() if log.exists() else ""

    def pfctl_calls(self) -> list[str]:
        log = self.stub / "pfctl.log"
        return log.read_text().splitlines() if log.exists() else []


@pytest.fixture(params=SHELLS)
def s(request: pytest.FixtureRequest, tmp_path: Path) -> Seen:
    if os.getuid() == 0:
        pytest.skip("stubs are honoured only for a non-root user, by design")
    return Seen(tmp_path, request.param)


# --- hostnames and resolution -----------------------------------------------------------------


def test_reads_only_the_allowlist_in_either_field_order_through_unbound(s: Seen) -> None:
    assert s.run(100_000).returncode == 0
    assert sorted(s.queried()) == ["read.soraapp.com", "soraapp.com"]
    calls = (s.stub / "drill.log").read_text().splitlines()
    assert all(c.split()[1:] == ["@127.0.0.1", "A"] for c in calls)


@pytest.mark.parametrize(
    "line",
    [
        "pf $(reboot) SCR_EDU_ALLOW",
        "pf bad_name.example SCR_EDU_ALLOW",
        "pf -x.example SCR_EDU_ALLOW",
        "pf nodot SCR_EDU_ALLOW",
        "pf a;b.example SCR_EDU_ALLOW",
    ],
)
def test_names_that_are_not_plain_dns_names_are_skipped(s: Seen, line: str) -> None:
    s.filterdns.write_text(line + "\n")
    assert s.run(100_000).returncode == 0
    assert s.queried() == []


def test_upper_case_names_are_lowered_and_deduplicated(s: Seen) -> None:
    s.filterdns.write_text("pf SoraApp.COM SCR_EDU_ALLOW\npf soraapp.com SCR_EDU_ALLOW\n")
    s.run(100_000)
    assert s.queried() == ["soraapp.com"]


def test_answers_and_cname_chains_fill_the_table_but_not_other_sections(s: Seen) -> None:
    s.answer("soraapp.com", "13.224.181.65", "13.224.181.94")
    s.answer("read.soraapp.com", "54.239.180.6", cname="dx33rfrmtypfh.cloudfront.net")
    assert s.run(100_000).returncode == 0
    assert s.table() == ["13.224.181.65", "13.224.181.94", "54.239.180.6"]
    assert any(c.startswith("-t SCR_EDU_SEEN -T replace -f ") for c in s.pfctl_calls())


@pytest.mark.parametrize(
    "address",
    [
        "0.1.2.3",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.12.20",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "256.1.1.1",
        "1.2.3",
        "01.2.3.4",
    ],
)
def test_lan_reserved_and_malformed_answers_never_enter_the_table(s: Seen, address: str) -> None:
    s.answer("soraapp.com", address, "13.224.181.65")
    s.run(100_000)
    assert s.table() == ["13.224.181.65"]


# --- history ----------------------------------------------------------------------------------


def test_an_address_is_kept_exactly_four_hours_after_it_was_last_seen(s: Seen) -> None:
    s.answer("soraapp.com", "13.224.181.65")
    s.run(100_000)
    s.answer("soraapp.com", "13.224.181.94")
    s.run(100_000 + KEEP)
    assert s.table() == ["13.224.181.65", "13.224.181.94"]
    s.run(100_000 + KEEP + 1)
    assert s.table() == ["13.224.181.94"]


def test_seeing_an_address_again_restarts_its_four_hours(s: Seen) -> None:
    s.answer("soraapp.com", "13.224.181.65")
    s.run(100_000)
    s.run(100_000 + 3 * 3600)
    s.answer("soraapp.com", "13.224.181.94")
    s.run(100_000 + 6 * 3600)
    assert s.table() == ["13.224.181.65", "13.224.181.94"]


def test_a_table_reset_by_a_filter_reload_is_rebuilt_from_the_history(s: Seen) -> None:
    s.answer("soraapp.com", "13.224.181.65")
    s.run(100_000)
    (s.stub / "table").write_text("192.0.2.1\n")  # pfSense reloaded the alias placeholder
    s.answer("soraapp.com", "13.224.181.94")
    s.run(100_020)
    assert s.table() == ["13.224.181.65", "13.224.181.94"]


def test_a_failing_resolver_keeps_the_history_and_logs_once(s: Seen) -> None:
    s.answer("soraapp.com", "13.224.181.65")
    s.run(100_000)
    (s.stub / "dns.soraapp.com").unlink()
    s.run(100_020)
    s.run(100_040)
    assert s.table() == ["13.224.181.65"]
    assert s.syslog().count("no addresses from 127.0.0.1") == 1
    s.answer("soraapp.com", "13.224.181.65")
    s.run(100_060)
    assert "resolving through 127.0.0.1 works" in s.syslog().splitlines()[-1]


def test_a_missing_source_leaves_the_table_alone_and_logs_once(s: Seen) -> None:
    s.answer("soraapp.com", "13.224.181.65")
    s.run(100_000)
    s.filterdns.unlink()
    calls = len(s.pfctl_calls())
    s.run(100_020)
    s.run(100_040)
    assert s.table() == ["13.224.181.65"] and len(s.pfctl_calls()) == calls
    assert s.syslog().count("no SCR_EDU_ALLOW hostnames") == 1


def test_a_damaged_history_cannot_inject_addresses(s: Seen) -> None:
    (s.state / "seen").write_text(
        "192.168.12.20 100000\n10.0.0.1 100000\nrubbish\n1.1.1.1 notatime\n13.224.181.65 99990\n"
    )
    s.run(100_000)
    assert s.table() == ["13.224.181.65"]


def test_the_table_is_bounded_to_the_most_recent_entries(s: Seen) -> None:
    old = [f"20.0.{i // 256}.{i % 256} 90000" for i in range(2100)]
    (s.state / "seen").write_text("\n".join(old) + "\n")
    s.answer("soraapp.com", "13.224.181.65")
    s.run(100_000)
    table = s.table()
    assert len(table) == 2048 and "13.224.181.65" in table


def test_an_empty_history_flushes_the_table(s: Seen) -> None:
    s.run(100_000)
    assert "-t SCR_EDU_SEEN -T flush" in s.pfctl_calls()


# --- operation --------------------------------------------------------------------------------


def test_status_lists_the_names_the_table_and_the_history(s: Seen) -> None:
    s.answer("soraapp.com", "13.224.181.65")
    s.run(100_000)
    res = s.run(100_600, "--status")
    assert res.returncode == 0
    assert "hostnames from SCR_EDU_ALLOW" in res.stdout and "  soraapp.com" in res.stdout
    assert "addresses in SCR_EDU_SEEN: 1" in res.stdout
    assert "oldest last seen 10 minutes ago (kept 240 minutes)" in res.stdout


def test_an_overlapping_run_exits_quietly(s: Seen) -> None:
    (s.stub / "busy").write_text("")
    res = s.run(100_000, lock=True)
    assert res.returncode == 0 and s.pfctl_calls() == []
    lockf = (s.stub / "lockf.args").read_text().split()
    assert lockf[:3] == ["-s", "-t", "0"] and lockf[3].endswith("/lock")


def test_self_test_passes(tmp_path: Path) -> None:
    if os.getuid() == 0:
        pytest.skip("must run unprivileged")
    for shell in SHELLS:
        res = subprocess.run(
            [shell, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            env={"PATH": os.environ["PATH"], "TMPDIR": str(tmp_path)},
            timeout=120,
            check=False,
        )
        assert res.returncode == 0, res.stdout + res.stderr
        assert "self-test passed" in res.stdout and "\nFAIL " not in "\n" + res.stdout


def test_usage(s: Seen) -> None:
    assert s.run(100_000, "--frobnicate").returncode == 64
