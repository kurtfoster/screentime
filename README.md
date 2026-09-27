# Screen-Time Controller

## Overview

A small, local-first web application that controls recreational screen Internet access for two
children. It runs on a Raspberry Pi (the household's is a **Raspberry Pi 1 Model B+** named
`screentime`: one 700 MHz ARMv6 core, 512 MB, no real-time clock) behind nginx and drives pfSense
runtime firewall tables
(`SCR_ACTIVE`, `SCR_EDU_ALLOW`) over SSH. It keeps a per-child daily allowance across personal
Apple devices and shared TVs, gives parents one- and two-tap controls, and never guesses at
usage: every chargeable minute is an explicit session.

```
 iPhone / iPad / TVs                Raspberry Pi                         pfSense
 ┌────────────────┐   HTTPS   ┌──────────────────────────┐   SSH    ┌──────────────────┐
 │ child / parent │ ────────▶ │ nginx ▶ FastAPI app      │ ───────▶ │ screenctl wrapper│
 │ browser or PWA │           │  SQLite (authoritative)  │  forced  │  pfctl tables:   │
 └────────────────┘           │  timers · reconciler     │  command │  SCR_ACTIVE      │
        ▲                     │  education DNS resolver  │          │  SCR_EDU_ALLOW   │
        └── Web Push ─────────┴──────────────────────────┘          └──────────────────┘
```

Design rules that shape everything: **fail closed** (if pfSense cannot be told, access is never
claimed), **database is authoritative** (pf tables are derived and re-converged every 30 s),
**everything is auditable**, **configuration lives in YAML**, and there is no cloud, no Redis and
no JavaScript framework.

Status: the application, tests and deployment scripts are complete and adapted for the
Raspberry Pi 1 (release 1.1, `../Pi1_Adaptation_Plan.md`). The suite passes against the exact
Raspberry Pi OS Trixie library builds, and the libraries were measured on the Pi itself. The
application has **not** yet run on the Pi, a real pfSense, nginx or an iPhone/iPad; see
[Verification status](#verification-status) for exactly what has and has not been exercised.

## Quick Start

### Try it on your computer (dry-run firewall, no pfSense needed)

```bash
git clone <this repository> screentime && cd screentime
python3 -m venv .venv                        # Python 3.12 or newer
.venv/bin/pip install -e ".[dev]"
.venv/bin/python scripts/make_dev_users.py   # writes config/users.dev.yaml, prints the passwords
SCREENTIME_CONFIG=config/config.dev.yaml SCREENTIME_USERS=config/users.dev.yaml \
  .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080>. Sign in as `child8` / `child12` (password `<name>-dev`) or `parents`
(`parents-dev`). With `make` installed, `make install dev-users run` does the same.

### Run every check (lint, types, tests, coverage)

```bash
bash scripts/check.sh                                  # or: make test
podman build -f deploy/Containerfile.trixie .          # same tests on the Pi's exact library builds
```

### Deploy to the Raspberry Pi

The Pi needs **Raspberry Pi OS Lite (32-bit), Trixie**; a Pi 1 cannot run the 64-bit image. Flash
it with hostname `screentime`, SSH key login and wired Ethernet, then on the Pi:

```bash
sudo apt update && sudo apt full-upgrade -y && sudo apt install -y git
git clone <this repository> screentime && cd screentime
sudo deploy/install.sh --extra-san <the Pi's LAN IP>   # Raspberry Pi OS packages, gpu_mem=16, NTP, smoke test
sudo reboot                                            # only if the installer added gpu_mem=16
# USB backup drive: add the /etc/fstab line the installer printed, then
sudo mount /mnt/screentime-backup && sudo chown screentime: /mnt/screentime-backup && sudo chmod 0700 /mnt/screentime-backup
sudo -u screentime /opt/screentime/venv/bin/python /opt/screentime/app/scripts/make_password_hash.py \
  --config /opt/screentime/config/config.yaml    # once per login
sudo nano /opt/screentime/config/users.yaml      # paste the three hashes
sudo nano /opt/screentime/config/config.yaml     # devices, allowances, pfSense address
cd /opt/screentime/app && sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml \
  SCREENTIME_USERS=/opt/screentime/config/users.yaml \
  /opt/screentime/venv/bin/python -m app --check-config
sudo systemctl start screentime.service screentime-backup.timer
```

Then follow [OPERATIONS.md](OPERATIONS.md) to set up pfSense (aliases, rules, the `screenctl`
wrapper, the SSH key, and its NTP service for the Pi) and to install the local CA on the children's
devices. Leave `firewall.mode: dry_run` until pfSense is ready and the Pi is on the pfSense LAN,
then switch it to `pfsense_ssh`. A Pi 1 takes about a minute to start the service; that is
expected.

## Contents

- [What is enforced](#what-is-enforced)
- [Configuration](#configuration)
- [First-run configuration](#first-run-configuration)
- [Raspberry Pi deployment in detail](#raspberry-pi-deployment-in-detail)
- [Bare-metal restore](#bare-metal-restore)
- [Development](#development)
- [Project layout](#project-layout)
- [Decisions and deviations from the specification](#decisions-and-deviations-from-the-specification)
- [Verification status](#verification-status)

## What is enforced

| Rule | Where it lives | Behaviour |
| --- | --- | --- |
| Daily allowance | `children.<id>.weekday/weekend_allowance_minutes` | Exact seconds are charged. Displayed minutes round down, so the display never overstates what is left. |
| Weekday start time | `children.<id>.weekday_earliest_start` | No new sessions before 09:00 on weekdays. |
| TV cutoff | `devices.<id>.weekday_cutoff` | Kids TV stops at 18:30 on weekdays; a session started at 18:10 for 30 minutes is capped at 18:30. |
| Logical day | `logical_day_reset` | The day rolls at 02:00. Nothing is deleted; every query is keyed to the current logical day, and DST changes are handled. |
| One device at a time | `sessions.max_concurrent_devices_per_child` | A second device is refused with "You are already using …". |
| Device entitlement | `devices.<id>.owner`, `permitted_shared_devices` | Personal devices are usable only by their owner. |
| Session length | `sessions.child_choices_minutes` | 15 / 30 / 60, with 30 preselected. Stopping early charges only elapsed time. |
| Extension | `sessions.child_extension_minutes`, `warning_minutes` | +15 minutes, offered in the last 5 minutes, only if 15 uncommitted minutes remain; re-checked atomically. |
| Parent grants | `parents.allowance_grants_minutes` | +15/+30/+60 adds allowance *and* a parent-override window that lifts the cutoff, start-time rule and day lock. |
| End for today | Parent dashboard | Ends the child's sessions, locks the day, revokes the device and kills its connections. |
| Parent TV | `parents.tv_session_choices_minutes` | 15/30/60 or until stopped (ends at the next 02:00 by default). Never charges a child. |
| Education apps | `always_allowed` | Hostnames resolved (A, AAAA, CNAME chains) into `SCR_EDU_ALLOW`, so they work when no session is running. |

Precedence when rules disagree is exactly as in the specification (section 9): parent override,
parent TV, day lock, device cutoff, start time, allowance, one-device, entitlement. Every denial
carries a machine-readable reason code shown in the UI and written to the audit log.

## Configuration

Everything tunable is in `config/config.example.yaml` (heavily commented); logins are in
`users.example.yaml`. Loading is strict: unknown keys, dangling references, unquoted times such
as `18:30` (which YAML would read as the number 1110) and placeholder password hashes all stop
the service from starting, with every problem listed at once.

```bash
.venv/bin/python -m app --check-config      # validate without starting anything
.venv/bin/python -m app --check-deps        # installed library versions against the minimums
.venv/bin/python scripts/make_password_hash.py    # Argon2id hash for users.yaml
```

`users.yaml` must be mode 0600 (enforced at startup). The database, application secret and Web
Push key live in `storage.data_dir`. Settings added for the Raspberry Pi 1: `security.password_hash`
(Argon2id cost, never below the OWASP minimum), `clock` (refuse grants until NTP has set the
clock), `ui` (dashboard polling), `push.allowed_endpoint_hosts` (which push services a browser
subscription may name), `firewall.ssh_multiplex` and `storage.runtime_dir`.

## First-run configuration

1. **Devices.** Give each managed device a static DHCP mapping on pfSense and put the same
   address in `devices.<id>.ip`. The controller identifies devices by IP address.
2. **Allowances and rules** in `config.yaml`; children's usernames must match `users.yaml`.
3. **Logins.** One hash per user with `make_password_hash.py`.
4. **Validate** with `--check-config`, start the service, and sign in as a parent.
5. **pfSense.** Follow [OPERATIONS.md](OPERATIONS.md). Until then the app runs in dry-run mode
   and nothing on the network changes.
6. **Education allowlist.** Open *Parent, Diagnostics*. Add hostnames under `always_allowed` as
   you learn what each app needs; the page shows what resolves and what does not.
7. **Children's devices.** Install the CA, add the app to the Home Screen and (optionally) turn
   on alerts. Steps are in OPERATIONS.md.

## Raspberry Pi deployment in detail

`deploy/install.sh` is idempotent. It:

- creates the `screentime` system account and `/opt/screentime/{app,config,data,.ssh}` with tight
  permissions (data and SSH directories 0700, `users.yaml` 0600);
- installs the code (root-owned, read-only to the service) and precompiles it, so the service does
  not recompile every module at each start;
- chooses where the Python libraries come from (`--deps`). On an ARMv6 Pi (1 or Zero) it installs
  the Raspberry Pi OS packages in `deploy/apt-packages.txt` and builds the virtualenv with
  `--system-site-packages`, installing nothing from PyPI: those packages are built for ARMv6,
  whereas PyPI and piwheels builds can crash with "Illegal instruction". Elsewhere it installs from
  PyPI (or `--wheelhouse DIR` offline);
- runs `scripts/smoke_test.py`, which imports every library and exercises its native code once,
  **before** it touches systemd, so a wrong-CPU build stops the install rather than the service;
- on an ARMv6 Pi, offers to set `gpu_mem=16` (about 60 MB more for Linux) and prints the benchmark
  command;
- points `systemd-timesyncd` at pfSense first (`--ntp-server`, public pool servers after it),
  bounds the boot-time wait for NTP to 90 s, caps the journal at 64 MB, and warns if the root
  filesystem lacks `noatime`;
- prepares `/mnt/screentime-backup` (`--backup-dest`) for the USB backup drive and prints the
  `/etc/fstab` line to add;
- creates `config.yaml` and `users.yaml` from the examples **only if they do not exist**; use
  `--overwrite-config` (with confirmation) to replace them, which first keeps a `.bak` copy;
- creates a private certificate authority and a server certificate for `screen.home.arpa`
  (`--hostname`, `--extra-san`, `--renew-tls`); the CA is constrained to `home.arpa`;
- installs and validates the nginx site, and the systemd service plus a daily backup timer;
- starts the service only if `--check-config` passes, otherwise tells you what to fix.

It never touches pfSense. Use `--dry-run` to see what it would do and `--no-tls` to supply your
own certificates (paths are in `deploy/nginx-screen.conf`).

The service binds to `127.0.0.1:8080` behind nginx, which listens on the LAN only, refuses
non-private source addresses, rate-limits `/login`, and serves the CA certificate over plain HTTP
at `/ca.crt` (needed to bootstrap trust on iOS). Never port-forward it from the WAN.

Operational detail (logs, upgrades, troubleshooting, certificates): [OPERATIONS.md](OPERATIONS.md).
Threat model and limitations: [SECURITY.md](SECURITY.md).

## Bare-metal restore

Backups are created daily at about 03:15 (`screentime-backup.timer`) or on demand, and the newest
14 are kept on the USB drive mounted at `/mnt/screentime-backup`, never on the SD card that holds
the database. If the drive is missing the backup refuses to run, and the parent Diagnostics page
shows the failure and the time of the last good backup. Each is one 0600 tarball holding a SQLite-consistent
copy of the database (taken with SQLite's online-backup API, so it is safe while the service is
running), `config.yaml`, `users.yaml`, the application secret and the Web Push key. It does not
contain pfSense tables (rebuilt from the database) or the SSH private key.

To rebuild on a fresh Pi:

```bash
# 1. Fresh Raspberry Pi OS Lite (32-bit) Trixie; clone the repository (same release, or newer)
sudo deploy/install.sh --extra-san <LAN IP>          # packages, account, venv, nginx, systemd
# 2. Mount the USB backup drive (see Quick Start), then restore the newest backup from it
sudo deploy/restore.sh /mnt/screentime-backup/screentime-YYYYmmdd-HHMMSS.tar.gz --yes
# 3. New SSH key for pfSense (the old private key is deliberately not in backups)
sudo -u screentime ssh-keygen -t ed25519 -f /opt/screentime/.ssh/id_ed25519 -N ''
#    ...then authorise the new public key on pfSense (OPERATIONS.md, "SSH access")
# 4. Confirm
sudo -u screentime /opt/screentime/venv/bin/python /opt/screentime/app/scripts/admin_cli.py status
```

The restored database is upgraded in place by Alembic when the service starts, so a backup taken
on an older release restores onto a newer one. Because `secret.key` and the Web Push key come back
too, existing logins and push subscriptions keep working. If you restore *without* them, everyone
signs in again and re-enables alerts. Restoring TLS material: re-run `install.sh`; children's
devices trust the CA, so keep `/etc/screentime/tls/ca.key` in your own safe place if you want the
same CA after a rebuild (otherwise reinstall the new `ca.crt` on each device).

## Development

```bash
bash scripts/check.sh            # ruff format, ruff lint, mypy --strict, shell syntax, pytest + coverage
bash scripts/check.sh --fast     # no coverage
bash scripts/check.sh --no-e2e   # skip the browser tests
bash scripts/check.sh --profile trixie   # Python 3.13 + the Raspberry Pi OS library versions
podman build -f deploy/Containerfile.trixie .   # the suite against the Debian builds themselves
.venv/bin/playwright install chromium    # once, for the browser tests (they skip if unavailable)
```

The Pi runs older library versions than PyPI offers (FastAPI 0.115, Starlette 0.46, pydantic 2.10,
argon2-cffi 21.1 and so on; `constraints/trixie.txt`). The `pyproject.toml` minimums are those
versions: fix code that needs something newer rather than raising a minimum. Without Python 3.13
installed, run the trixie profile in a container as the script's error message shows.

Tests are in three tiers: `tests/unit` (calendar, policy, sessions, config, resolver, the pfSense
wrapper against a stub `pfctl`, deployment scripts), `tests/integration` (real FastAPI app over a
temporary SQLite database with a fake clock and the dry-run firewall), and `tests/e2e` (Playwright
against a real server). Coverage is reported on every run and must stay at or above 85%.

Administration without the web UI (also the way to inspect a misbehaving system):

```bash
sudo -u screentime /opt/screentime/venv/bin/python /opt/screentime/app/scripts/admin_cli.py --help
#   status | sessions | audit | grant | end-today | clear-lock | end-session | end-all
#   tv | enable-device | unlock | reconcile [--education] | devices
```

`status` also prints the service's latest resource snapshot: memory, load, timer lag, SSH
latency, last password-check time, clock sync, under-voltage flags and the last backup.

The version shown on the diagnostics page comes from the `VERSION` file.

## Project layout

```
app/                 FastAPI application (config, policy, sessions, enforcement, routes, templates, static)
  firewall/          adapter interface, dry-run and SSH adapters, education resolver
migrations/          Alembic (applied automatically at startup, or: python -m app --init-db)
config/              example configuration and development configuration
deploy/              systemd units, nginx config, install/backup/restore scripts, pfSense wrapper
scripts/             password hashing, admin CLI, smoke test, one-shot reconcile, icons, check.sh
constraints/         trixie.txt: the Raspberry Pi OS library versions, for the parity profile
tests/               unit, integration and e2e tests
README.md  OPERATIONS.md  SECURITY.md  VERSION
```

## Decisions and deviations from the specification

Where the specification was silent, or contradicted itself, these are the choices made. Each is
easy to change.

1. **Sample config conflict.** The specification's sample lists the personal `ipad` under *both*
   children's shared devices, declares child8's `owned_devices` empty although `ipad` is owned by
   child8, and also says personal devices are usable only by their owner. The example config
   lists shared TVs under `permitted_shared_devices` and the iPad under its owner; the loader
   rejects the contradictory form with an explanatory message. For a genuinely shared iPad, give
   it `type: shared_tv` and no `owner`.
2. **Parent overrides bypass rules 3 to 5** (day lock, cutoff, start time). Extra allowance arrives
   as an explicit adjustment, so the allowance rule still measures base plus adjustments. Rules 7
   and 8 (one device, entitlement) are integrity checks and are never bypassed.
3. **Grant window.** +N minutes creates an allowance adjustment of N and an override window from
   now to *now + N minutes + any time the child has already reserved*. It is deliberately exact
   ("permits exactly the intended extension window"): a child who starts 20 minutes after a +30
   grant has only the remaining 10 minutes of window, so grants are best given when the child is
   ready. The unused allowance stays credited for the logical day.
4. **End for Today revokes earlier grant windows**, otherwise an old grant would silently defeat
   the lock the parent has just applied. A grant made *after* End for Today bypasses the lock for
   its window; both records are kept.
5. **Sessions are capped where the next restriction begins.** A 30-minute request at 18:10 on the
   kids' TV ends at 18:30. The same model ends sessions correctly after downtime, charging only
   up to the moment access should have stopped.
6. **A "last minutes" option.** When less time remains than the smallest choice, the child may use
   exactly what is left, so short remainders are not stranded.
7. **Extensions** are offered only in the warning window and cannot cross a cutoff or lock. On a
   shared TV a child may extend for everyone, or, if a sibling lacks time, for themself only.
8. **Sibling verification** uses the sibling's normal password; wrong attempts count toward that
   sibling's lockout.
9. **Login lockout.** Five failures lock a *child* login for 15 minutes; a parent unlocks it from
   the dashboard. The *parent* login is throttled per source address instead, so a child cannot
   lock the parents out.
10. **HTTPS is required for the PWA on iOS**, so the installer creates a private CA. The CA is
    name-constrained to `home.arpa`, so its key cannot be used to impersonate ordinary websites.
11. **Web Push works only while the device can reach its push service.** A device idle outside a
    session is limited to the education allowlist, so alerts are delivered during sessions (when
    the warning fires) but not to an idle, blocked device.
12. **Python 3.12+** and Raspberry Pi OS Trixie (Python 3.13). The installer refuses older Python with
    advice. On the Raspberry Pi 1 the libraries are the Raspberry Pi OS packages, not PyPI.
13. **`replace_active_ips`** in the SSH adapter is implemented as a diff of add/del operations (the
    wrapper has no atomic replace for the active table); the reconciler itself uses add/del plus
    state kills. Education tables are replaced atomically with `pfctl -T replace`.
14. **Scope kept out of v1**, as specified: VLANs, Switch, mobile data, MDM, DoH blocking, traffic
    inference, cloud accounts, multi-household.

Raspberry Pi 1 adaptation (release 1.1; `../Pi1_Adaptation_Plan.md` has the evidence):

15. **Clock gate covers child starts only.** Until NTP has set the clock, nothing is granted and
    child starts are refused with `CLOCK_NOT_SYNCED`, but parent actions are accepted as the plan
    specifies. A parent TV start in that window is recorded and reported as started, yet the TV
    gets no access until the clock is synchronised (the desired set is forced empty), and a parent
    grant is keyed to whatever day the unsynchronised clock shows.
16. **Boot waits up to 90 s for NTP**, then starts anyway and fails closed. Waiting indefinitely
    (the plan's first draft) would leave parents with no controller at all while NTP is down.
17. **Visibility-aware polling lives in `app.js`**, not in an `hx-trigger` filter: filters need
    `eval`, which the CSP and the htmx configuration forbid. An idle child page now polls every
    15 s, so a parent action can take up to 15 s to appear there; enforcement is immediate.
18. **The backup destination is an installer option** (`--backup-dest`, rendered into the backup
    unit), not a `config.yaml` key, so the unit's mount dependency and the script cannot disagree.
19. **SSH multiplexing switches itself off** if the control socket path would exceed the Unix
    socket limit (108 bytes), rather than failing over on every call.

## Verification status

Exercised automatically (about 380 tests plus 12 browser tests, about 93% line coverage,
`mypy --strict` and ruff clean): policy precedence and every acceptance scenario in specification
section 24.3 against the dry-run firewall; DST edges; concurrency (two simultaneous extensions with
room for one); fail-closed behaviour, including an unsynchronised clock; startup catch-up; the SSH
adapter's command construction and its multiplexing fallback against a fake runner; the
`screenctl` wrapper against a stub `pfctl` including injection attempts; the DNS resolver against
a real loopback DNS server; Web Push encryption decrypted as a browser would, and VAPID signatures
verified; the installer, TLS issuance and backup/restore in a temporary prefix; and the critical
browser flows in headless Chromium.

Raspberry Pi 1 evidence (27 September 2026):

- **On the Pi (Gate 0):** every Raspberry Pi OS package installs and imports on ARMv6 with no
  "Illegal instruction"; libraries use 64 MB; Argon2id at the configured cost verifies in 1.41 s;
  importing the libraries takes 41.5 s, which is why start-up was trimmed.
- **Off the Pi (Gate 1):** the whole suite passes on Python 3.13 with the Trixie library versions
  (`check.sh --profile trixie`) and inside Debian Trixie with the Debian builds
  (`deploy/Containerfile.trixie`). The installer ran end to end in that container in apt mode.
- **Against a real OpenSSH server:** multiplexed wrapper calls took 3 ms against 81 ms for a fresh
  connection (workstation figures), and a restarted server was reconnected transparently.

**Not yet exercised**, because it needs your hardware: the application running on the Pi (Gate 2
in the adaptation plan: start-up time, login time, memory, polling cost and tick lag), a real
pfSense (`pfctl` behaviour, the sudo and forced-command setup, multiplexing through the forced
command, table persistence across filter reloads), nginx (validated by `nginx -t` at install time,
not by the test suite), iOS/iPadOS behaviour (CA trust, Home Screen install, Web Push), and
`screenctl` under FreeBSD's `sh` (it is plain POSIX and tested under bash, but not under `dash` or
FreeBSD `sh`). Work through OPERATIONS.md section 9, "Acceptance checklist on real hardware", and
section 10, "Raspberry Pi 1 resources", before relying on it.
