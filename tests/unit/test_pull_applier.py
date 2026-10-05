"""deploy/pfsense-screentime-pull.sh against stub pfctl, su (curl), sysctl, logger and lockf.

Runs under bash and, when installed, dash (the Trixie container has it). FreeBSD sh itself is
covered by `screentime-pull --self-test` on pfSense at Gate B. Time is fixed per run with
SCREENTIME_PULL_NOW, which, like every stub, is honoured only for a non-root user.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "pfsense-screentime-pull.sh"
TOKEN = "tok-ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"
FETCH = "env -i PATH=/bin:/usr/bin /usr/local/bin/curl -q -K -"
SHELLS = [s for s in ("bash", "dash") if shutil.which(s)]

PFCTL = """#!/bin/sh
echo "$*" >> "$STUB/pfctl.log"
case "$*" in
  *"-T replace -f "*) cp "$6" "$STUB/table.$2" ;;
  *"-T flush") : > "$STUB/table.$2" ;;
esac
exit 0
"""

# su stub: records its arguments, then plays curl. The fetch's response comes from
# $STUB/response (or a failure when $STUB/fail exists); an acknowledgement is recorded.
SU = """#!/bin/sh
printf '%s\\n' "$@" > "$STUB/su.args"
n=$(cat "$STUB/count" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$STUB/count"
cat > "$STUB/curl.$n"
if grep -q '/desired"' "$STUB/curl.$n"; then
  [ -f "$STUB/fail" ] && { echo "curl: (7) Failed to connect" >&2; exit 7; }
  cat "$STUB/response"
else
  cp "$STUB/curl.$n" "$STUB/ack"
fi
"""

SYSCTL = """#!/bin/sh
echo "{ sec = $(cat "$STUB/boot"), usec = 1 } Mon Oct  5 10:00:00 2026"
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

CONF = f"""PI_URL=https://screen.home.arpa
PI_ADDRESS=192.168.12.20
TOKEN={TOKEN}
CA_FILE={{ca}}
MANAGED_SUBNET=192.168.12.0/24
DEVICE_ipad="192.168.12.30 personal"
DEVICE_kids_tv="192.168.12.40 tv"
DEVICE_lounge_tv="192.168.12.41 tv"
MAX_LEASE=900
STALE_GRACE=600
STALE_POLICY=open
"""


def doc(*devices: str, generation: int = 7, end: bool = True) -> str:
    lines = ["screentime-desired v1", f"generation {generation}", *devices]
    return "\n".join([*lines, "end"] if end else lines) + "\n"


class Applier:
    def __init__(self, tmp: Path, shell: str) -> None:
        self.shell = shell
        self.stub = tmp / "stub"
        self.stub.mkdir()
        self.state = tmp / "state"
        self.state.mkdir(mode=0o700)
        for name, body in (
            ("pfctl", PFCTL),
            ("su", SU),
            ("sysctl", SYSCTL),
            ("logger", LOGGER),
            ("lockf", LOCKF),
        ):
            path = self.stub / name
            path.write_text(body)
            path.chmod(0o755)
        self.ca = tmp / "ca.crt"
        self.ca.write_text("-----BEGIN CERTIFICATE-----\n")
        self.conf = tmp / "screentime-pull.conf"
        self.write_conf(CONF.format(ca=self.ca))
        self.boot(1000)

    def write_conf(self, text: str, mode: int = 0o600) -> None:
        self.conf.write_text(text)
        self.conf.chmod(mode)

    def boot(self, sec: int) -> None:
        (self.stub / "boot").write_text(str(sec))

    def respond(self, body: str | bytes, fail: bool = False) -> None:
        data = body.encode() if isinstance(body, str) else body
        (self.stub / "response").write_bytes(data)
        if fail:
            (self.stub / "fail").write_text("")
        else:
            (self.stub / "fail").unlink(missing_ok=True)

    def run(
        self, now: int, *args: str, lock: bool = False, **env: str
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": os.environ["PATH"],
            "STUB": str(self.stub),
            "SCREENTIME_PULL_CONF": str(self.conf),
            "SCREENTIME_PULL_STATE": str(self.state),
            "SCREENTIME_PULL_PFCTL": str(self.stub / "pfctl"),
            "SCREENTIME_PULL_SU": str(self.stub / "su"),
            "SCREENTIME_PULL_SYSCTL": str(self.stub / "sysctl"),
            "SCREENTIME_PULL_LOGGER": str(self.stub / "logger"),
            "SCREENTIME_PULL_LOCKF": str(self.stub / "lockf"),
            "SCREENTIME_PULL_NOW": str(now),
            **env,
        }
        if not lock:
            environment["SCREENTIME_PULL_LOCKED"] = "1"
        return subprocess.run(
            [self.shell, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
            check=False,
        )

    def table(self, name: str) -> list[str]:
        path = self.stub / f"table.{name}"
        return path.read_text().split() if path.exists() else []

    def tables(self) -> tuple[list[str], list[str], list[str]]:
        return (
            self.table("SCR_ACTIVE_PERSONAL"),
            self.table("SCR_ACTIVE_TV"),
            self.table("SCR_FAILOPEN"),
        )

    def pfctl_calls(self) -> list[str]:
        log = self.stub / "pfctl.log"
        return log.read_text().splitlines() if log.exists() else []

    def kills(self) -> list[str]:
        return [c for c in self.pfctl_calls() if c.startswith("-k")]

    def ack(self) -> str:
        """The acknowledgement body as the controller receives it (curl unescapes \\n)."""
        config = (self.stub / "ack").read_text()
        line = next(ln for ln in config.splitlines() if ln.startswith("data-binary = "))
        return line.removeprefix('data-binary = "').removesuffix('"').replace("\\n", "\n")

    def syslog(self) -> str:
        log = self.stub / "syslog"
        return log.read_text() if log.exists() else ""

    def clear(self) -> None:
        for name in ("pfctl.log", "ack", "syslog"):
            (self.stub / name).unlink(missing_ok=True)


@pytest.fixture(params=SHELLS)
def a(request: pytest.FixtureRequest, tmp_path: Path) -> Applier:
    if os.getuid() == 0:
        pytest.skip("stubs are honoured only for a non-root user, by design")
    return Applier(tmp_path, request.param)


def test_dash_is_covered_somewhere() -> None:
    if "dash" not in SHELLS:
        pytest.skip("dash not installed here; the Trixie container runs these under dash")


# --- a good document ------------------------------------------------------------------------


def test_valid_document_fills_the_tables_and_is_acknowledged(a: Applier) -> None:
    a.respond(doc("device ipad 600", "device kids_tv 900"))
    res = a.run(10_000)
    assert res.returncode == 0, res.stderr
    assert a.tables() == (["192.168.12.30"], ["192.168.12.40"], [])
    assert a.ack() == (
        "screentime-applied v1\ngeneration 7\nmode normal\nstale 600 open\n"
        "device ipad\ndevice kids_tv\n"
        "known ipad 192.168.12.30 personal\nknown kids_tv 192.168.12.40 tv\n"
        "known lounge_tv 192.168.12.41 tv\nend\n"
    )


def test_the_acknowledgement_parses_on_the_controller(a: Applier) -> None:
    from app.firewall.protocol import parse_applied

    a.respond(doc("device ipad 600"))
    a.run(10_000)
    ack = parse_applied(a.ack().encode())
    assert ack.device_ids == {"ipad"} and ack.stale == (600, "open")
    assert ack.known == {
        "ipad": ("192.168.12.30", "personal"),
        "kids_tv": ("192.168.12.40", "tv"),
        "lounge_tv": ("192.168.12.41", "tv"),
    }


def test_crlf_line_endings_are_accepted(a: Applier) -> None:
    a.respond(doc("device ipad 600").replace("\n", "\r\n"))
    a.run(10_000)
    assert a.table("SCR_ACTIVE_PERSONAL") == ["192.168.12.30"]


def test_the_fetch_is_unprivileged_and_the_token_is_never_an_argument(a: Applier) -> None:
    a.respond(doc())
    a.run(10_000)
    args = (a.stub / "su.args").read_text().splitlines()
    assert args == ["-m", "nobody", "-c", FETCH]
    assert all(TOKEN not in arg for arg in args)
    config = (a.stub / "curl.1").read_text()
    assert f'header = "Authorization: Bearer {TOKEN}"' in config
    for option in (
        'url = "https://screen.home.arpa/firewall/v1/desired"',
        'proto = "=https"',
        "tlsv1.2",
        f'cacert = "{a.ca}"',
        'resolve = "screen.home.arpa:443:192.168.12.20"',
        "max-time = 10",
        "max-filesize = 4096",
        "fail",
    ):
        assert option in config.splitlines(), option
    assert TOKEN not in a.syslog()


# --- rejected documents: the whole document, never part of it --------------------------------


@pytest.mark.parametrize(
    "body",
    [
        doc("device ipad 600", end=False),  # truncated
        doc("device ipad 600") + "x" * 5000,  # oversize
        doc("device garage 600"),  # not in pfSense's device map
        doc("device ipad 600", "device ipad 300"),  # duplicate
        doc("device ipad 0"),
        doc("device ipad 901"),  # above MAX_LEASE
        doc("device ipad 600", generation=-1).replace("generation -1", "generation -1"),
        doc("device ipad 600").replace("generation 7", "generation 1234567890123456789"),
        doc("device ipad 600").replace("v1", "v2"),
        doc("device ipad 600") + "device kids_tv 60\n",  # after end
        doc("device ipad 600;reboot"),
        doc("device ipad $(reboot)"),
        doc("device ipad 600 extra"),
        doc("device  ipad 600"),  # double space
        doc("device ipad 600 "),  # trailing space
        doc("device IPAD 600"),
        doc("device ipad 6\r00"),  # CR inside a line
        doc("device ipad 600").replace("ipad", "ip\x00ad"),
        doc("device ipäd 600"),
        doc("device ipad 600", generation=7).replace("generation 7", "generation 7\ngeneration 8"),
        "",
    ],
)
def test_any_deviation_rejects_the_whole_document(a: Applier, body: str) -> None:
    a.respond(doc("device kids_tv 600"))
    a.run(10_000)
    a.respond(body)
    a.run(10_060)
    assert a.tables() == ([], ["192.168.12.40"], [])  # the previous leases, untouched
    assert "mode grace" in a.ack()
    assert "fetch failed: the document was rejected" in a.syslog()


@pytest.mark.parametrize(
    ("line", "value"),
    [
        ("PI_URL", "https://screen.home.arpa/;id"),
        ("PI_URL", "http://screen.home.arpa"),
        ("PI_ADDRESS", "10.0.0.5"),
        ("TOKEN", "short"),
        ("TOKEN", "has$dollar-and-more-characters"),
        ("CA_FILE", "relative.crt"),
        ("MAX_LEASE", "60"),
        ("STALE_GRACE", "abc"),
        ("STALE_POLICY", "sometimes"),
        ("TABLE_TV", "SCR;TV"),
        ("DEVICE_ipad", '"192.168.12.30 phone"'),
        ("DEVICE_ipad", '"192.168.13.30 personal"'),
        ("DEVICE_ipad", '"192.168.12.40 personal"'),  # the same address as kids_tv
        ("DEVICE_Bad", '"192.168.12.50 tv"'),
        ("UNKNOWN_KEY", "1"),
    ],
)
def test_bad_configuration_is_refused(a: Applier, line: str, value: str) -> None:
    lines = [ln for ln in CONF.format(ca=a.ca).splitlines() if not ln.startswith(f"{line}=")]
    a.write_conf("\n".join([*lines, f"{line}={value}"]) + "\n")
    a.respond(doc())
    res = a.run(10_000)
    assert res.returncode == 78, (res.stdout, res.stderr)
    assert a.pfctl_calls() == []


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666])
def test_a_configuration_readable_by_others_is_refused(a: Applier, mode: int) -> None:
    a.write_conf(CONF.format(ca=a.ca), mode)
    a.respond(doc())
    res = a.run(10_000, SCREENTIME_PULL_ENFORCE_OWNER="1")
    assert res.returncode == 78 and "have mode -rw-------" in res.stderr
    a.write_conf(CONF.format(ca=a.ca), 0o600)
    a.ca.chmod(0o644)
    assert a.run(10_000, SCREENTIME_PULL_ENFORCE_OWNER="1").returncode == 0


# --- leases, grace, fail-open, recovery ----------------------------------------------------


def test_leases_expire_between_polls(a: Applier) -> None:
    a.respond(doc("device ipad 120", "device kids_tv 600"))
    a.run(10_000)
    a.respond(doc(), fail=True)  # the controller is unreachable, still within grace
    a.run(10_060)
    assert a.tables() == (["192.168.12.30"], ["192.168.12.40"], [])
    a.clear()
    a.run(10_121)
    assert a.tables() == ([], ["192.168.12.40"], [])
    assert "-k 192.168.12.30" in a.kills()


def test_grace_then_fail_open_then_recovery(a: Applier) -> None:
    a.respond(doc("device ipad 900", "device kids_tv 900"))
    a.run(10_000)
    a.respond(doc(), fail=True)
    a.run(10_600)  # exactly STALE_GRACE: still grace
    assert a.tables()[2] == [] and "mode grace" in a.ack()
    a.run(10_660)
    personal, tv, failopen = a.tables()
    assert failopen == ["192.168.12.30", "192.168.12.40", "192.168.12.41"]
    assert personal == ["192.168.12.30"] and tv == ["192.168.12.40"]  # the leases are kept
    assert "mode fail-open" in a.ack() and "mode grace -> fail-open" in a.syslog()
    a.clear()
    a.respond(doc("device ipad 300", generation=8))
    a.run(11_260)  # 10 minutes of fail-open
    assert a.tables() == (["192.168.12.30"], [], [])
    assert set(a.kills()) == {
        "-k 192.168.12.40",
        "-k 0.0.0.0/0 -k 192.168.12.40",
        "-k 192.168.12.41",
        "-k 0.0.0.0/0 -k 192.168.12.41",
    }
    assert "last-failopen 600 600" in a.ack()
    assert "mode fail-open -> normal" in a.syslog()


def test_the_episode_is_reported_for_seven_days_and_survives_a_reboot(a: Applier) -> None:
    a.respond(doc(), fail=True)
    a.run(10_000)  # first run ever: grace counts from boot (1000), so already fail-open
    assert "mode fail-open" in a.ack()
    a.respond(doc())
    a.run(10_300)
    assert "last-failopen 300 300" in a.ack()
    a.boot(50_000)  # pfSense rebooted
    a.run(50_100)
    assert "last-failopen 40100 300" in a.ack()
    a.run(10_300 + 7 * 86400)
    assert "last-failopen" in a.ack()
    a.run(10_300 + 7 * 86400 + 1)
    assert "last-failopen" not in a.ack()


def test_stale_policy_closed_allows_nothing(a: Applier) -> None:
    a.write_conf(CONF.format(ca=a.ca).replace("STALE_POLICY=open", "STALE_POLICY=closed"))
    a.respond(doc("device ipad 900"))
    a.run(10_000)
    a.respond(doc(), fail=True)
    a.run(10_700)
    assert a.tables() == ([], [], [])
    assert "mode fail-closed" in a.ack() and "stale 600 closed" in a.ack()
    assert "-k 192.168.12.30" in a.kills()


# --- reboots (F7): state is on ZFS and survives ---------------------------------------------


def test_a_reboot_discards_leases_and_counts_grace_from_boot(a: Applier) -> None:
    a.respond(doc("device ipad 900"))
    a.run(10_000)
    a.boot(20_000)  # pfSense was off for hours: last_good is far older than STALE_GRACE
    a.respond(doc(), fail=True)
    a.run(20_100)
    assert a.tables() == ([], [], [])  # no lease from the previous boot, and no fail-open yet
    assert "mode grace" in a.ack()
    assert "leases from the previous boot discarded" in a.syslog()
    a.run(20_601)  # fetches kept failing for STALE_GRACE after boot
    assert a.tables()[2] == ["192.168.12.30", "192.168.12.40", "192.168.12.41"]


def test_a_failed_document_after_a_reboot_while_failed_open_keeps_the_episode_open(
    a: Applier,
) -> None:
    a.respond(doc(), fail=True)
    a.run(10_000)  # fail-open
    a.boot(30_000)
    a.run(30_100)  # grace after the reboot: the episode is still open
    assert "last-failopen" not in a.ack()
    a.respond(doc())
    a.run(30_200)
    assert "last-failopen 20200 20200" in a.ack()  # the time pfSense was down counts


# --- one run at a time, and no pfSense notifications ----------------------------------------


def test_an_overlapping_run_exits_quietly(a: Applier) -> None:
    a.respond(doc("device ipad 600"))
    (a.stub / "busy").write_text("")
    res = a.run(10_000, lock=True)
    assert res.returncode == 0 and a.pfctl_calls() == []
    lockf = (a.stub / "lockf.args").read_text().split()
    assert lockf[:3] == ["-s", "-t", "0"] and lockf[3].endswith("/lock")
    (a.stub / "busy").unlink()
    assert a.run(10_000, lock=True).returncode == 0
    assert a.table("SCR_ACTIVE_PERSONAL") == ["192.168.12.30"]


def test_the_pfsense_notifier_is_never_called() -> None:
    code = [
        ln
        for ln in SCRIPT.read_text().splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    assert not [ln for ln in code if "php" in ln or "notif" in ln.lower()]


def test_self_test_passes_and_refuses_root(tmp_path: Path) -> None:
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


def test_usage(a: Applier) -> None:
    assert a.run(10_000, "--frobnicate").returncode == 64
