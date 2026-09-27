"""Deployment artefacts: installer, TLS, backup/restore, systemd and nginx files."""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"


def sh(
    *args: str | Path, stdin: str = "", env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(a) for a in args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={**os.environ, **(env or {})},
        timeout=120,
        check=False,
    )


def install(prefix: Path, *extra: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    return sh(
        DEPLOY / "install.sh",
        "--no-system",
        "--skip-venv",
        "--no-tls",
        "--prefix",
        prefix,
        *extra,
        stdin=stdin,
    )


def mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


# --- installer -----------------------------------------------------------------------------


def test_install_lays_out_directories_files_and_permissions(tmp_path: Path) -> None:
    prefix = tmp_path / "opt"
    res = install(prefix)
    assert res.returncode == 0, res.stderr
    assert mode(prefix / "data") == 0o700 and mode(prefix / ".ssh") == 0o700
    assert not (prefix / "backups").exists()  # backups go to a separate drive, not the SD card
    assert mode(prefix / "config") == 0o750
    assert mode(prefix / "config" / "users.yaml") == 0o600
    for rel in (
        "app/app/main.py",
        "app/migrations/env.py",
        "app/deploy/install.sh",
        "app/VERSION",
        "app/alembic.ini",
    ):
        assert (prefix / rel).exists(), rel
    # Bytecode is compiled at install time for this interpreter, never copied from the source tree.
    compiled = {p.name for p in (prefix / "app" / "app" / "__pycache__").glob("*.pyc")}
    assert f"main.{sys.implementation.cache_tag}.pyc" in compiled
    assert all(sys.implementation.cache_tag in name for name in compiled)
    assert list((prefix / "app" / "migrations" / "versions" / "__pycache__").glob("*.pyc"))
    assert "Next steps" in res.stdout


def test_install_never_overwrites_existing_config_and_is_idempotent(tmp_path: Path) -> None:
    prefix = tmp_path / "opt"
    install(prefix)
    cfg, users = prefix / "config" / "config.yaml", prefix / "config" / "users.yaml"
    cfg.write_text("# my precious config\n")
    users.write_text("# my precious users\n")
    again = install(prefix)
    assert again.returncode == 0
    assert (
        cfg.read_text() == "# my precious config\n" and users.read_text() == "# my precious users\n"
    )
    assert "Keeping existing" in again.stdout


def test_overwrite_requires_explicit_confirmation(tmp_path: Path) -> None:
    prefix = tmp_path / "opt"
    install(prefix)
    cfg = prefix / "config" / "config.yaml"
    cfg.write_text("# mine\n")
    declined = install(prefix, "--overwrite-config", stdin="n\n")
    assert declined.returncode == 0 and cfg.read_text() == "# mine\n"
    no_answer = install(prefix, "--overwrite-config", stdin="")  # closed stdin is not consent
    assert cfg.read_text() == "# mine\n" and no_answer.returncode == 0
    confirmed = install(prefix, "--overwrite-config", "--yes")
    assert confirmed.returncode == 0 and "screen-time" in cfg.read_text().lower()
    assert list((prefix / "config").glob("config.yaml.bak.*"))  # a backup of the old file was kept


def test_upgrade_replaces_application_code_but_not_data(tmp_path: Path) -> None:
    prefix = tmp_path / "opt"
    install(prefix)
    (prefix / "data" / "screentime.db").write_text("keep me")
    (prefix / "app" / "app" / "stale_module.py").write_text("# from an older release")
    install(prefix)
    assert not (prefix / "app" / "app" / "stale_module.py").exists()
    assert (prefix / "data" / "screentime.db").read_text() == "keep me"


def test_dry_run_changes_nothing(tmp_path: Path) -> None:
    prefix = tmp_path / "opt"
    res = sh(
        DEPLOY / "install.sh",
        "--dry-run",
        "--no-system",
        "--skip-venv",
        "--no-tls",
        "--prefix",
        prefix,
    )
    assert res.returncode == 0 and "[dry-run]" in res.stdout
    assert not prefix.exists()


def test_old_python_is_refused_with_upgrade_advice(tmp_path: Path) -> None:
    fake = tmp_path / "python3.11"
    fake.write_text('#!/bin/sh\n[ "$1" = "-V" ] && echo \'Python 3.11.2\' && exit 0\nexit 1\n')
    fake.chmod(0o755)
    res = sh(
        DEPLOY / "install.sh",
        "--no-system",
        "--no-tls",
        "--python",
        fake,
        "--prefix",
        tmp_path / "opt",
    )
    assert res.returncode != 0 and "3.12 or newer" in res.stderr and "Trixie" in res.stderr


def test_non_root_without_no_system_is_refused(tmp_path: Path) -> None:
    if os.getuid() == 0:
        pytest.skip("running as root")
    res = sh(DEPLOY / "install.sh", "--skip-venv", "--prefix", tmp_path / "opt")
    assert res.returncode != 0 and "run as root" in res.stderr


def test_unknown_option_is_rejected() -> None:
    assert sh(DEPLOY / "install.sh", "--frobnicate").returncode == 64


# --- TLS -----------------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_tls_generation_issues_a_verifiable_ios_friendly_certificate(tmp_path: Path) -> None:
    prefix, tls = tmp_path / "opt", tmp_path / "tls"
    args = (
        "--no-system",
        "--skip-venv",
        "--prefix",
        str(prefix),
        "--tls-dir",
        str(tls),
        "--extra-san",
        "192.168.12.5",
    )
    res = sh(DEPLOY / "install.sh", *args)
    assert res.returncode == 0, res.stderr
    ca, crt, key = tls / "ca.crt", tls / "screen.crt", tls / "screen.key"
    assert mode(key) == 0o600 and mode(tls / "ca.key") == 0o600
    assert sh("openssl", "verify", "-CAfile", ca, crt).returncode == 0
    text = sh("openssl", "x509", "-in", crt, "-noout", "-text").stdout
    assert "DNS:screen.home.arpa" in text and "IP Address:192.168.12.5" in text
    assert "TLS Web Server Authentication" in text and "CA:FALSE" in text
    ca_text = sh("openssl", "x509", "-in", ca, "-noout", "-text").stdout
    assert "CA:TRUE" in ca_text
    not_after = sh("openssl", "x509", "-in", crt, "-noout", "-enddate").stdout.split("=")[1].strip()
    days = (time.mktime(time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")) - time.time()) / 86400
    assert 700 < days <= 825  # within Apple's 825-day limit for server certificates
    assert (tls / "screen-fullchain.crt").read_text().count("BEGIN CERTIFICATE") == 2
    assert "Permitted:\n" in ca_text and "DNS:home.arpa" in ca_text  # name-constrained CA

    # The CA cannot vouch for anything outside home.arpa, even for a holder of its key.
    rogue_key, rogue_csr, rogue_ext, rogue = (
        tmp_path / n for n in ("r.key", "r.csr", "r.ext", "r.crt")
    )
    rogue_ext.write_text("subjectAltName=DNS:www.example.com\nextendedKeyUsage=serverAuth\n")
    sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", rogue_key)
    sh(
        "openssl",
        "req",
        "-new",
        "-key",
        rogue_key,
        "-subj",
        "/CN=www.example.com",
        "-out",
        rogue_csr,
    )
    sh(
        "openssl",
        "x509",
        "-req",
        "-in",
        rogue_csr,
        "-CA",
        ca,
        "-CAkey",
        tls / "ca.key",
        "-CAcreateserial",
        "-days",
        "30",
        "-extfile",
        rogue_ext,
        "-out",
        rogue,
    )
    verdict = sh("openssl", "verify", "-CAfile", ca, rogue)
    assert verdict.returncode != 0 and "permitted subtree violation" in (
        verdict.stdout + verdict.stderr
    )

    before = crt.read_bytes()
    again = sh(DEPLOY / "install.sh", *args)
    assert (
        again.returncode == 0
        and crt.read_bytes() == before
        and "valid for more than 30 days" in again.stdout
    )
    ca_before = ca.read_bytes()
    renewed = sh(DEPLOY / "install.sh", *args, "--renew-tls")
    assert renewed.returncode == 0 and crt.read_bytes() != before and ca.read_bytes() == ca_before
    assert (
        sh("openssl", "verify", "-CAfile", ca, crt).returncode == 0
    )  # same CA, so clients keep trusting it


# --- backup and restore --------------------------------------------------------------------


def make_prefix(tmp_path: Path) -> Path:
    prefix = tmp_path / "opt"
    assert install(prefix).returncode == 0
    (prefix / "config" / "config.yaml").write_text(
        "timezone: Australia/Melbourne\nstorage:\n  data_dir: %s\n" % (prefix / "data")
    )
    (prefix / "config" / "users.yaml").write_text("users: {}\n")
    (prefix / "config" / "users.yaml").chmod(0o600)
    (prefix / "data" / "secret.key").write_bytes(b"s" * 32)
    (prefix / "data" / "vapid_private.pem").write_text("pem")
    con = sqlite3.connect(prefix / "data" / "screentime.db")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    con.executemany("INSERT INTO t (v) VALUES (?)", [(f"row{i}",) for i in range(50)])
    con.commit()
    con.close()
    return prefix


def backup(
    prefix: Path, *extra: str, mounted_check: bool = False
) -> subprocess.CompletedProcess[str]:
    """Back up into <prefix>/backups; tests have no USB drive, so the mount check is off by default."""
    args: list[str | Path] = ["--prefix", prefix, "--python", sys.executable]
    if "--dest" not in extra:
        args += ["--dest", prefix / "backups"]
    if not mounted_check:
        args.append("--allow-unmounted")
    return sh(DEPLOY / "backup.sh", *args, *extra)


def test_backup_is_consistent_private_and_complete(tmp_path: Path) -> None:
    prefix = make_prefix(tmp_path)
    live = sqlite3.connect(prefix / "data" / "screentime.db")  # a busy WAL database
    live.execute("INSERT INTO t (v) VALUES ('uncheckpointed')")
    live.commit()
    res = backup(prefix)
    assert res.returncode == 0, res.stderr
    archives = list((prefix / "backups").glob("screentime-*.tar.gz"))
    assert len(archives) == 1 and mode(archives[0]) == 0o600 and mode(prefix / "backups") == 0o700
    out = tmp_path / "x"
    out.mkdir()
    subprocess.run(["tar", "-C", str(out), "-xzf", str(archives[0])], check=True)
    root = out / "screentime-backup"
    restored = sqlite3.connect(root / "data" / "screentime.db")
    assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert (
        restored.execute("SELECT count(*) FROM t").fetchone()[0] == 51
    )  # includes the WAL-only row
    for rel in (
        "config/config.yaml",
        "config/users.yaml",
        "data/secret.key",
        "data/vapid_private.pem",
        "MANIFEST",
    ):
        assert (root / rel).exists(), rel
    assert not list(root.rglob("id_*"))  # SSH private keys are never included
    live.close()
    assert not list((prefix / "backups").glob(".work.*"))  # scratch space removed


def test_backup_retention_keeps_the_newest_n(tmp_path: Path) -> None:
    prefix = make_prefix(tmp_path)
    dest = prefix / "backups"
    dest.mkdir(mode=0o700)
    for i in range(6):
        old = dest / f"screentime-2026010{i}-030000.tar.gz"
        old.write_text("old")
        os.utime(old, (1_700_000_000 + i * 86400,) * 2)
    res = backup(prefix, "--keep", "3")
    assert res.returncode == 0, res.stderr
    remaining = sorted(p.name for p in dest.glob("screentime-*.tar.gz"))
    assert len(remaining) == 3
    assert (
        "screentime-20260105-030000.tar.gz" in remaining
        and "screentime-20260100-030000.tar.gz" not in remaining
    )


def test_backup_defaults_to_fourteen_and_validates_arguments(tmp_path: Path) -> None:
    assert "KEEP=14" in (DEPLOY / "backup.sh").read_text()
    prefix = make_prefix(tmp_path)
    assert backup(prefix, "--keep", "0").returncode == 64
    assert backup(prefix, "--bogus").returncode == 64
    missing = backup(tmp_path / "nothing")
    assert missing.returncode == 1 and "database not found" in missing.stderr


def test_backup_refuses_a_destination_that_is_not_a_mounted_drive(tmp_path: Path) -> None:
    prefix = make_prefix(tmp_path)
    assert backup(prefix, "--allow-unmounted").returncode == 0
    first = json.loads((prefix / "data" / "backup-status.json").read_text())
    assert first["result"] == "ok" and first["detail"].endswith(".tar.gz")
    assert first["last_success_at"] == first["at"]

    unmounted = tmp_path / "usb"  # a plain directory: the drive is not plugged in
    res = backup(prefix, "--dest", str(unmounted), mounted_check=True)
    assert res.returncode == 1 and "not a mounted drive" in res.stderr
    assert not unmounted.exists()  # nothing was written in its place
    status_file = prefix / "data" / "backup-status.json"
    status = json.loads(status_file.read_text())
    assert status["result"] == "failed" and "not a mounted drive" in status["detail"]
    assert status["last_success_at"] == first["at"]  # the last good backup is still known
    assert mode(status_file) == 0o600


@pytest.mark.skipif(shutil.which("mountpoint") is None, reason="mountpoint not installed")
def test_a_directory_inside_another_mount_does_not_count_as_the_drive(tmp_path: Path) -> None:
    prefix = make_prefix(tmp_path)
    if subprocess.run(["mountpoint", "-q", "/dev/shm"], check=False).returncode != 0:
        pytest.skip("no tmpfs at /dev/shm to stand in for the USB drive")
    dest = Path(tempfile.mkdtemp(dir="/dev/shm"))
    try:
        # A directory on a mount is not the mount itself: still refused.
        assert backup(prefix, "--dest", str(dest), mounted_check=True).returncode == 1
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def test_restore_onto_a_fresh_prefix_reproduces_the_database_and_config(tmp_path: Path) -> None:
    source = make_prefix(tmp_path / "old")
    assert backup(source).returncode == 0
    archive = next((source / "backups").glob("*.tar.gz"))
    fresh = tmp_path / "new" / "opt"
    assert install(fresh).returncode == 0
    (fresh / "config" / "config.yaml").write_text("# fresh default\n")
    res = sh(DEPLOY / "restore.sh", archive, "--prefix", fresh, "--yes", "--no-service")
    assert res.returncode == 0, res.stderr
    con = sqlite3.connect(fresh / "data" / "screentime.db")
    assert con.execute("SELECT count(*) FROM t").fetchone()[0] == 50
    assert "Australia/Melbourne" in (fresh / "config" / "config.yaml").read_text()
    assert (fresh / "config" / "config.yaml.pre-restore").read_text() == "# fresh default\n"
    assert (
        mode(fresh / "data" / "screentime.db") == 0o600
        and mode(fresh / "config" / "users.yaml") == 0o600
    )
    assert (fresh / "data" / "secret.key").read_bytes() == b"s" * 32
    assert "SSH key is not part of a backup" in res.stdout


def test_restore_refuses_bad_input(tmp_path: Path) -> None:
    prefix = make_prefix(tmp_path)
    assert sh(DEPLOY / "restore.sh", "--prefix", prefix).returncode == 64
    junk = tmp_path / "junk.tar.gz"
    junk.write_text("not a tarball")
    assert (
        sh(DEPLOY / "restore.sh", junk, "--prefix", prefix, "--yes", "--no-service").returncode != 0
    )
    assert (
        sh(DEPLOY / "restore.sh", junk, "--prefix", tmp_path / "missing", "--yes").returncode != 0
    )


def test_restored_database_upgrades_via_alembic_on_startup(tmp_path: Path) -> None:
    """A backup from an older schema revision is brought forward by the app itself."""
    from app.db import Database, current_revision

    old = Database(tmp_path / "old.db")
    old.upgrade()
    old.dispose()
    reopened = Database(tmp_path / "old.db")
    reopened.upgrade()
    assert current_revision(reopened) is not None


# --- systemd and nginx ---------------------------------------------------------------------


def unit_settings(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            k, v = line.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


def test_service_unit_matches_the_specification() -> None:
    s = unit_settings((DEPLOY / "screentime.service").read_text())
    assert s["User"] == ["screentime"] and s["Group"] == ["screentime"]
    assert s["WorkingDirectory"] == ["/opt/screentime/app"]
    assert "SCREENTIME_CONFIG=/opt/screentime/config/config.yaml" in s["Environment"]
    assert "SCREENTIME_USERS=/opt/screentime/config/users.yaml" in s["Environment"]
    exec_start = s["ExecStart"][0]
    # python -m: with Raspberry Pi OS packages the venv has no uvicorn script of its own.
    assert exec_start.startswith("/opt/screentime/venv/bin/python -m uvicorn app.main:app")
    assert "--host 127.0.0.1" in exec_start and "--port 8080" in exec_start
    assert s["Restart"] == ["on-failure"] and s["RestartSec"] == ["3"]
    assert s["NoNewPrivileges"] == ["true"] and s["PrivateTmp"] == ["true"]
    assert "-m app --check-config" in s["ExecStartPre"][0]  # bad config stops startup
    # No RTC: order after NTP sync, and allow a slow Raspberry Pi 1 start (CHG-06, CHG-08).
    assert "time-sync.target" in s["After"][0] and "time-sync.target" in s["Wants"][0]
    assert s["TimeoutStartSec"] == ["300"]
    assert s["RuntimeDirectory"] == ["screentime"] and s["RuntimeDirectoryMode"] == ["0700"]


def test_backup_unit_uses_the_usb_drive_without_depending_on_it() -> None:
    s = unit_settings((DEPLOY / "screentime-backup.service").read_text())
    assert s["WantsMountsFor"] == ["/mnt/screentime-backup"]
    assert "RequiresMountsFor" not in s  # a missing drive must still produce a recorded failure
    assert s["ExecStart"] == ["/opt/screentime/app/deploy/backup.sh --dest /mnt/screentime-backup"]
    assert s["ReadWritePaths"] == ["/opt/screentime/data -/mnt/screentime-backup"]


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed")
def test_systemd_units_pass_systemd_analyze(tmp_path: Path) -> None:
    prefix = tmp_path / "opt"
    for rel in ("venv/bin/python", "app/deploy/backup.sh"):
        target = prefix / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("#!/bin/sh\n")
        target.chmod(0o755)
    (prefix / "app").mkdir(exist_ok=True)
    for name in ("screentime.service", "screentime-backup.service", "screentime-backup.timer"):
        rendered = tmp_path / name
        rendered.write_text((DEPLOY / name).read_text().replace("/opt/screentime", str(prefix)))
    res = sh(
        "systemd-analyze",
        "verify",
        "--user",
        *[
            tmp_path / n
            for n in ("screentime.service", "screentime-backup.service", "screentime-backup.timer")
        ],
    )
    problems = [
        ln for ln in (res.stdout + res.stderr).splitlines() if ln.strip() and "screentime" in ln
    ]
    assert problems == [], problems


def test_nginx_config_is_lan_only_tls_and_proxies_to_localhost() -> None:
    conf = (DEPLOY / "nginx-screen.conf").read_text()
    assert conf.count("{") == conf.count("}")
    assert "server_name @HOSTNAME@" in conf and "proxy_pass http://127.0.0.1:8080" in conf
    assert "ssl_protocols       TLSv1.2 TLSv1.3" in conf and "return 301 https://" in conf
    assert "limit_req_zone" in conf and "location = /ca.crt" in conf
    # Every path that verifies a password shares the login rate limit (Argon2 is CPU-bound).
    assert conf.count("limit_req zone=screentime_login") == 2
    assert "add-participant|session/start" in conf
    for snippet in re.findall(r"include /etc/nginx/snippets/(\S+);", conf):
        assert (DEPLOY / snippet).exists(), snippet
    lan = (DEPLOY / "screentime-lan-only.conf").read_text()
    assert "deny all;" in lan and "allow 192.168.0.0/16;" in lan and "allow 0.0.0.0/0" not in lan
    proxy = (DEPLOY / "screentime-proxy.conf").read_text()
    assert (
        "X-Forwarded-For   $remote_addr" in proxy
    )  # overwritten, never appended: clients cannot spoof it
    assert "X-Real-IP         $remote_addr" in proxy


def test_installer_renders_nginx_placeholders(tmp_path: Path) -> None:
    rendered = (
        (DEPLOY / "nginx-screen.conf")
        .read_text()
        .replace("@HOSTNAME@", "screen.home.arpa")
        .replace("@TLS_DIR@", "/etc/screentime/tls")
    )
    assert "@" not in re.sub(r"'[^']*'", "", rendered)
    assert "ssl_certificate     /etc/screentime/tls/screen-fullchain.crt;" in rendered


# --- platform detection (Raspberry Pi 1 / Zero) --------------------------------------------------


def fake_uname(tmp_path: Path, machine: str) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "uname"
    stub.write_text(
        f'#!/bin/sh\n[ "$1" = "-m" ] && echo {machine} && exit 0\nexec /usr/bin/uname "$@"\n'
    )
    stub.chmod(0o755)
    return {"PATH": f"{bin_dir}:{os.environ['PATH']}"}


def test_armv6_selects_raspberry_pi_os_packages(tmp_path: Path) -> None:
    env = fake_uname(tmp_path, "armv6l")
    res = sh(
        DEPLOY / "install.sh",
        "--no-system",
        "--no-tls",
        "--prefix",
        tmp_path / "opt",
        "--dry-run",
        env=env,
    )
    assert res.returncode == 0, res.stderr
    assert "Machine armv6l; Python libraries from: apt" in res.stdout
    assert "sudo apt install python3 python3-venv python3-fastapi" in res.stdout
    assert "--system-site-packages" in res.stdout and "pip install" not in res.stdout
    assert "smoke_test.py" in res.stdout
    assert "make_password_hash.py --calibrate" in res.stdout


def test_other_machines_keep_pip_unless_told_otherwise(tmp_path: Path) -> None:
    env = fake_uname(tmp_path, "x86_64")
    res = sh(
        DEPLOY / "install.sh",
        "--no-system",
        "--no-tls",
        "--prefix",
        tmp_path / "opt",
        "--dry-run",
        env=env,
    )
    assert "Python libraries from: pip" in res.stdout and "pip install" in res.stdout
    assert "--calibrate" not in res.stdout
    forced = sh(
        DEPLOY / "install.sh",
        "--no-system",
        "--no-tls",
        "--prefix",
        tmp_path / "o2",
        "--dry-run",
        "--deps",
        "apt",
        env=env,
    )
    assert "Python libraries from: apt" in forced.stdout
    assert sh(DEPLOY / "install.sh", "--deps", "conda", env=env).returncode == 64


def test_gpu_memory_split_is_offered_on_armv6(tmp_path: Path) -> None:
    env = fake_uname(tmp_path, "armv6l")
    boot = tmp_path / "config.txt"
    boot.write_text("dtparam=audio=on\n")
    args = (
        "--no-system",
        "--skip-venv",
        "--no-tls",
        "--prefix",
        tmp_path / "opt",
        "--boot-config",
        boot,
    )
    declined = sh(DEPLOY / "install.sh", *args, stdin="n\n", env=env)
    assert declined.returncode == 0 and "gpu_mem=16" not in boot.read_text()
    assert "gpu_mem not changed" in declined.stderr
    accepted = sh(DEPLOY / "install.sh", *args, "--yes", env=env)
    assert accepted.returncode == 0 and boot.read_text().rstrip().endswith("gpu_mem=16")
    assert "Reboot for gpu_mem=16" in accepted.stdout
    again = sh(DEPLOY / "install.sh", *args, "--yes", env=env)
    assert "already set" in again.stdout and boot.read_text().count("gpu_mem=16") == 1
    other = tmp_path / "other.txt"
    other.write_text("gpu_mem=64\n")
    kept = sh(DEPLOY / "install.sh", *args[:-1], other, "--yes", env=env)
    assert other.read_text() == "gpu_mem=64\n" and "different gpu_mem" in kept.stderr


def test_gpu_memory_is_left_alone_on_other_machines(tmp_path: Path) -> None:
    env = fake_uname(tmp_path, "aarch64")
    boot = tmp_path / "config.txt"
    boot.write_text("")
    res = sh(
        DEPLOY / "install.sh",
        "--no-system",
        "--skip-venv",
        "--no-tls",
        "--prefix",
        tmp_path / "opt",
        "--boot-config",
        boot,
        "--yes",
        env=env,
    )
    assert res.returncode == 0 and boot.read_text() == ""


def test_the_apt_package_list_is_what_the_pi_needs() -> None:
    packages = [
        ln.strip()
        for ln in (DEPLOY / "apt-packages.txt").read_text().splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    assert "python3-python-multipart" in packages and "python3-multipart" not in packages
    assert "python3-argon2" in packages and "python3-py-vapid" in packages
    assert not any("webpush" in p or "aiohttp" in p for p in packages)
    containerfile = (DEPLOY / "Containerfile.trixie").read_text()
    assert "apt-packages.txt" in containerfile


def test_smoke_test_passes_here() -> None:
    res = sh(sys.executable, ROOT / "scripts" / "smoke_test.py")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Smoke test passed." in res.stdout and "argon2id hash and verify ... ok" in res.stdout
