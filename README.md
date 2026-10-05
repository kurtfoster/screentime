# Screen-Time Controller

## Overview

A small, local-first web application that controls recreational screen Internet access for two
children. It runs on a Raspberry Pi (the household's is a **Raspberry Pi 1 Model B+** named
`screentime`: one 700 MHz ARMv6 core, 512 MB, no real-time clock) behind nginx. pfSense pulls the
desired state from it once a minute and applies it to its own firewall tables; the Pi holds no
pfSense credential. It keeps a per-child daily allowance across personal Apple devices and shared
TVs, gives parents one- and two-tap controls on their phones, and never guesses at usage: every
chargeable minute is an explicit session.

```
 iPhone / iPad / TVs                Raspberry Pi                              pfSense
 ┌────────────────┐   HTTPS   ┌──────────────────────────┐  GET desired  ┌─────────────────────┐
 │ child / parent │ ────────▶ │ nginx ▶ FastAPI app      │ ◀──────────── │ screentime-pull     │
 │ browser or PWA │           │  SQLite (authoritative)  │  POST applied │  (Cron, every min)  │
 └────────────────┘           │  timers · publisher      │ ◀──────────── │  pf tables, curfew, │
        ▲                     │  parent alerts           │               │  FQDN education list│
        └── Web Push ─────────┴──────────────────────────┘               └─────────────────────┘
```

Design rules that shape everything: **the database is authoritative** (pfSense applies a lease-based
copy of it), **claims of access are truthful** (a start pfSense does not confirm is refunded),
**everything is auditable**, and there is no cloud, no Redis and no JavaScript framework. Two owner
decisions deviate from the original specification and are recorded in SECURITY.md: pfSense
**fails open** (every device allowed, no curfew) after 10 minutes without the controller, and
passwords may be as short as **4 characters**.

Status: release 1.2 (`../Firewall_Pull_Model_Plan.md`) is complete and passes every automated
check, including WebKit (Safari's engine) for the phone and iPad layouts. It has **not** yet run on
the Pi, a real pfSense or a real iPhone/iPad; see [Verification status](#verification-status).

## Quick Start

### Try it on your computer (dry-run firewall, no pfSense needed)

```bash
git clone <this repository> screentime && cd screentime
python3 -m venv .venv                        # Python 3.12 or newer
.venv/bin/pip install -e ".[dev]"
.venv/bin/python scripts/make_dev_users.py   # seeds logins into ./data, prints the passwords
SCREENTIME_CONFIG=config/config.dev.yaml .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080>. Sign in as `child8` / `child12` or `parent1` / `parent2` (password
`<name>-dev`). With `make` installed, `make install dev-users run` does the same.

### Run every check (lint, types, tests, coverage)

```bash
bash scripts/check.sh                                  # or: make test
scripts/check_webkit.sh                                # phone and iPad layouts in WebKit (container)
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
# USB backup drive: see "USB backup drive" below (UUID, nofail, 90 s device timeout), then
sudo chown screentime: /mnt/screentime-backup && sudo chmod 0700 /mnt/screentime-backup
sudo nano /opt/screentime/config/config.yaml     # children, devices, allowances
cd /opt/screentime/app
sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml \
  /opt/screentime/venv/bin/python -m app --check-config
sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml \
  /opt/screentime/venv/bin/python scripts/admin_cli.py user add-parent <username> --name "<Name>"   # each parent
sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml \
  /opt/screentime/venv/bin/python scripts/admin_cli.py user set-password <child username>          # each child
sudo systemctl restart screentime.service && sudo systemctl start screentime-backup.timer
```

Then follow [OPERATIONS.md](OPERATIONS.md) to set up pfSense (aliases, curfew schedule, the
`screentime-pull` applier and its Cron entry, rules) and to install the local CA on the children's
devices. Leave `firewall.mode: dry_run` until OPERATIONS.md 2.7 switches it to `pfsense_pull`.
A Pi 1 takes about a minute to start the service; that is expected.

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
| Education apps | pfSense alias `SCR_EDU_ALLOW` | Hostnames resolved by pfSense itself; they work when no session is running, even in curfew. |
| Curfew | pfSense schedule `SCR_CURFEW` | Personal devices only (TVs exempt), 06:00 to 21:00 by default, adjustable in the pfSense GUI. Not applied in fail-open. |
| Leases | `firewall.max_lease_seconds` | pfSense grants each device for at most 15 minutes at a time, renewed every poll, timed by its own clock. |
| Start honesty | `firewall.ack_timeout_seconds` | A start is charged at once; if pfSense has not confirmed it within 150 s it is ended and refunded. |
| Fail-open | pfSense `STALE_GRACE`, `STALE_POLICY` | 10 minutes without the controller: every device allowed, no curfew (owner decision); parents see it on the dashboard. |

Precedence when rules disagree is exactly as in the specification (section 9): parent override,
parent TV, day lock, device cutoff, start time, allowance, one-device, entitlement. Every denial
carries a machine-readable reason code shown in the UI and written to the audit log.

## Configuration

Everything tunable is in `config/config.example.yaml` (heavily commented). Logins (usernames,
roles and Argon2id password hashes) live in the database and are managed with
`scripts/admin_cli.py user ...` and, for passwords, in the app itself. Loading is strict: unknown
keys, dangling references and unquoted times such as `18:30` (which YAML would read as the
number 1110) all stop the service from starting, with every problem listed at once.

```bash
.venv/bin/python -m app --check-config      # validate without starting anything
.venv/bin/python -m app --check-deps        # installed library versions against the minimums
.venv/bin/python scripts/admin_cli.py user list    # accounts and whether each has a password
```

The database, application secret, Web Push key and the pfSense token's hash live in
`storage.data_dir`. Notable settings: `security.password_hash` (Argon2id cost, never below the
OWASP minimum), `security.password_min_length` (4), `clock` (refuse starts until NTP has set the
clock), `ui` (dashboard polling), `push.allowed_endpoint_hosts`, and under `firewall`: `mode`
(`dry_run` or `pfsense_pull`), `host` (pfSense's address), `max_lease_seconds`,
`ack_timeout_seconds`, `degraded_after_seconds` and `stale_grace_seconds` (must equal pfSense's
`STALE_GRACE`). Settings v1.2 removed (`always_allowed`, the SSH fields) are rejected with a
message saying where they went.

## First-run configuration

1. **Devices.** Give each managed device a static DHCP mapping on pfSense and put the same
   address in `devices.<id>.ip` **and** in pfSense's `screentime-pull.conf` device map.
   `admin_cli.py firewall-check` compares the two.
2. **Allowances and rules** in `config.yaml`. Each child's login is `children.<id>.username`.
3. **Logins.** `admin_cli.py user add-parent` for each parent (each has their own login), and
   `user set-password` for each child, or later from the parent dashboard.
4. **Validate** with `--check-config`, start the service, and sign in as a parent.
5. **pfSense.** Follow [OPERATIONS.md](OPERATIONS.md). Until then the app runs in dry-run mode
   and nothing on the network changes.
6. **Education allowlist.** The pfSense alias `SCR_EDU_ALLOW`: add hostnames as you learn what
   each app needs (pfSense's firewall log shows what is blocked).
7. **Children's devices.** Install the CA, add the app to the Home Screen and (optionally) turn
   on alerts. Steps are in OPERATIONS.md.

## Raspberry Pi deployment in detail

`deploy/install.sh` is idempotent. It:

- creates the `screentime` system account and `/opt/screentime/{app,config,data}` with tight
  permissions (data 0700, config 0750);
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
- creates `config.yaml` from the example **only if it does not exist**; use
  `--overwrite-config` (with confirmation) to replace it, which first keeps a `.bak` copy;
- creates a private certificate authority and a server certificate for `screen.home.arpa`
  (`--hostname`, `--extra-san`, `--renew-tls`); the CA is constrained to `home.arpa`;
- installs and validates the nginx site (`--firewall-host` is the only address allowed to
  `/firewall/`), removes Debian's stock `default` site when it is exactly Debian's link (it would
  otherwise answer requests for the bare IP with nginx's own page), and installs the systemd
  service plus a daily backup timer;
- starts the service only if `--check-config` passes, otherwise tells you what to fix;
- on a fresh install, prints the exact account commands (`user add-parent`, `user set-password`).

It never touches pfSense. Use `--dry-run` to see what it would do and `--no-tls` to supply your
own certificates (paths are in `deploy/nginx-screen.conf`).

The service binds to `127.0.0.1:8080` behind nginx, which listens on the LAN only, refuses
non-private source addresses, rate-limits every path that checks a password, lets only pfSense
reach `/firewall/`, and serves the CA certificate over plain HTTP at `/ca.crt` (needed to bootstrap
trust on iOS). Never port-forward it from the WAN.

Operational detail (logs, upgrades, troubleshooting, certificates): [OPERATIONS.md](OPERATIONS.md).
Threat model and limitations: [SECURITY.md](SECURITY.md).

### USB backup drive

Nightly backups go to a USB drive mounted at `/mnt/screentime-backup`; `deploy/backup.sh` refuses
to write anywhere that is not a mounted drive, so a missing drive fails visibly (Diagnostics)
instead of filling the SD card. Mount it by UUID with `nofail`, so a missing drive never stops the
Pi booting, and a **90 s** device timeout: a Pi 1's USB can enumerate the drive later than the
10 s once used, and systemd does not retry a mount whose wait has timed out (readiness check R8,
5 October 2026). `nofail` means boot does not wait, so the longer timeout costs nothing.

```bash
UUID=$(sudo blkid -s UUID -o value /dev/sda1); echo "UUID=$UUID"     # must print a UUID; stop if empty
sudo mkdir -p /mnt/screentime-backup
sudo cp -a /etc/fstab /etc/fstab.bak-$(date +%Y%m%d-%H%M)
echo "UUID=$UUID /mnt/screentime-backup ext4 defaults,noatime,nofail,x-systemd.device-timeout=90s 0 2" | sudo tee -a /etc/fstab
sudo systemctl daemon-reload && sudo mount /mnt/screentime-backup && findmnt /mnt/screentime-backup
# once the service account exists (after install.sh):
sudo chown screentime:screentime /mnt/screentime-backup && sudo chmod 0700 /mnt/screentime-backup
```

After a reboot, `findmnt /mnt/screentime-backup` must show `/dev/sda1` without a manual mount,
and `sudo journalctl -b | grep -E 'Timed out waiting|Dependency failed'` must print nothing.
Mount it once only: a second `mount` stacks a second mount on the same path.

## Bare-metal restore

Backups are created daily at about 03:15 (`screentime-backup.timer`) or on demand, and the newest
14 are kept on the USB drive mounted at `/mnt/screentime-backup`, never on the SD card that holds
the database. If the drive is missing the backup refuses to run, and the parent Diagnostics page
shows the failure and the time of the last good backup. Each is one 0600 tarball holding a
SQLite-consistent copy of the database (taken with SQLite's online-backup API, so it is safe while
the service is running; it includes the logins and their password hashes), `config.yaml`, the
application secret, the Web Push key and the pfSense token's SHA-256. It holds no pfSense table
contents: pfSense rebuilds them from the next fetch.

To rebuild on a fresh Pi:

```bash
# 1. Fresh Raspberry Pi OS Lite (32-bit) Trixie; clone the repository (same release, or newer)
sudo deploy/install.sh --extra-san <LAN IP>          # packages, account, venv, nginx, systemd
# 2. Mount the USB backup drive (see "USB backup drive"), then restore the newest backup from it
sudo deploy/restore.sh /mnt/screentime-backup/screentime-YYYYmmdd-HHMMSS.tar.gz --yes
# 3. Confirm, including that pfSense still matches
A="sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml /opt/screentime/venv/bin/python /opt/screentime/app/scripts/admin_cli.py"
$A status && $A firewall-check
```

The restored database is upgraded in place by Alembic when the service starts. Because
`secret.key`, the Web Push key and the token hash come back too, existing logins, push
subscriptions and pfSense's token keep working. Restoring TLS material: re-run `install.sh`;
children's devices and pfSense trust the CA, so keep `/etc/screentime/tls/ca.key` in your own safe
place if you want the same CA after a rebuild (otherwise reinstall the new `ca.crt` on each device
and on pfSense, OPERATIONS.md 2.5).

## Development

```bash
bash scripts/check.sh            # ruff format, ruff lint, mypy --strict, shell syntax, pytest + coverage
bash scripts/check.sh --fast     # no coverage
bash scripts/check.sh --no-e2e   # skip the browser tests
bash scripts/check.sh --profile trixie   # Python 3.13 + the Raspberry Pi OS library versions (and dash)
scripts/check_webkit.sh          # the mobile layout tests in WebKit and Chromium, in Playwright's container
podman build -f deploy/Containerfile.trixie .   # the suite against the Debian builds themselves
.venv/bin/playwright install chromium    # once, for the browser tests (they skip if unavailable)
```

The Pi runs older library versions than PyPI offers (FastAPI 0.115, Starlette 0.46, pydantic 2.10,
argon2-cffi 21.1, cryptography 43 and so on; `constraints/trixie.txt`). The `pyproject.toml`
minimums are those versions: fix code that needs something newer rather than raising a minimum.
Without Python 3.13 installed, run the trixie profile in a container as the script's error message
shows. WebKit (the engine of Safari on iPhone and iPad) cannot run on Fedora, so its tests skip
locally and `scripts/check_webkit.sh` runs them in Playwright's own image.

Tests are in three tiers: `tests/unit` (calendar, policy, sessions, config, password rules, the
firewall protocol, the pfSense applier against stub `pfctl`, `su`, `sysctl` and `lockf` under bash
and dash, deployment scripts), `tests/integration` (real FastAPI app over a temporary SQLite
database with a fake clock, in dry-run and pull mode), and `tests/e2e` (Playwright against a real
server, including the mobile viewport audit of plan 8.3). Coverage is reported on every run and
must stay at or above 85%.

Administration without the web UI (also the way to inspect a misbehaving system):

```bash
sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml \
  /opt/screentime/venv/bin/python /opt/screentime/app/scripts/admin_cli.py --help
#   status | sessions | audit | grant | end-today | clear-lock | end-session | end-all
#   tv | enable-device | unlock | reconcile | devices | firewall-check
#   user list | add-parent | set-password | disable | enable
#   firewall-token rotate
```

`status` also prints the service's latest resource snapshot: memory, load, timer lag, pfSense's
last fetch, last password-check time, clock sync, under-voltage flags and the last backup.

The version shown on the diagnostics page comes from the `VERSION` file.

## Project layout

```
app/                 FastAPI application (config, accounts, policy, sessions, enforcement, routes, templates, static)
  firewall/          adapter contract, dry-run and pull adapters, document protocol, token, alerts
migrations/          Alembic (applied automatically at startup, or: python -m app --init-db)
config/              example configuration and development configuration
deploy/              systemd units, nginx config, install/backup/restore scripts, pfSense applier and its example config
scripts/             admin CLI, dev logins, smoke test, one-shot reconcile, icons, check.sh, check_webkit.sh
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
   rejects the contradictory form with an explanatory message.
2. **Parent overrides bypass rules 3 to 5** (day lock, cutoff, start time). Extra allowance arrives
   as an explicit adjustment, so the allowance rule still measures base plus adjustments. Rules 7
   and 8 (one device, entitlement) are integrity checks and are never bypassed.
3. **Grant window.** +N minutes creates an allowance adjustment of N and an override window from
   now to *now + N minutes + any time the child has already reserved*.
4. **End for Today revokes earlier grant windows**, otherwise an old grant would silently defeat
   the lock the parent has just applied.
5. **Sessions are capped where the next restriction begins.** A 30-minute request at 18:10 on the
   kids' TV ends at 18:30.
6. **A "last minutes" option.** When less time remains than the smallest choice, the child may use
   exactly what is left.
7. **Extensions** are offered only in the warning window and cannot cross a cutoff or lock.
8. **Sibling verification** uses the sibling's normal password; wrong attempts count toward that
   sibling's lockout.
9. **Login lockout.** Five failures lock a *child* login for 15 minutes; the *parent* logins are
   throttled per source address instead, so a child cannot lock a parent out.
10. **HTTPS is required for the PWA on iOS**, so the installer creates a private CA,
    name-constrained to `home.arpa`.
11. **Web Push works only while the device can reach its push service.**
12. **Python 3.12+** and Raspberry Pi OS Trixie (Python 3.13); on the Pi 1 the libraries are the
    Raspberry Pi OS packages, not PyPI.
13. **Scope kept out**, as specified: VLANs, Switch, mobile data, MDM, DoH blocking, traffic
    inference, cloud accounts, multi-household.

Raspberry Pi 1 adaptation (release 1.1; `../Pi1_Adaptation_Plan.md` has the evidence):

14. **Boot waits up to 90 s for NTP**, then starts anyway; child starts stay refused until the clock
    is set.
15. **Visibility-aware polling lives in `app.js`**, not in an `hx-trigger` filter: filters need
    `eval`, which the CSP and the htmx configuration forbid.
16. **The backup destination is an installer option** (`--backup-dest`), so the unit's mount
    dependency and the script cannot disagree.

Release 1.2 (`../Firewall_Pull_Model_Plan.md`; owner decisions D1 to D13):

17. **pfSense pulls; the Pi holds no credential** (D1). SSH, `screenctl`, the education resolver
    and `always_allowed` are gone; the education allowlist is a pfSense FQDN alias.
18. **Start immediately, refund if unconfirmed** (D2, plan 5.1): no pending state; the UI says
    "the Internet turns on within a minute".
19. **Clock gate (plan 5.5):** while the clock is unsynchronised the controller publishes nothing
    and answers pfSense with 503; pfSense keeps its leases and, after its grace, fails open.
20. **The acknowledgement grammar is extended** beyond plan 6.3 with optional
    `stale <grace> <policy>` and `known <id> <ip> <type>` lines and a `fail-closed` mode. Without
    them the controller could not check its grace period and device list against pfSense (C9),
    nor word its alerts correctly under `STALE_POLICY=closed`.
21. **The applier's grace also counts from its first run** on a pfSense box, not only from the
    last good fetch or boot: otherwise a fresh install on a long-running pfSense would fail open
    at once.
22. **No `users.yaml` migration path.** v1.1 was never installed (D12), so `import-yaml`, the
    legacy restore path and the `users.yaml` warning were not built.
23. **The Account menu (M2)** arrived with the password screens (PULL-10), because the header could
    not hold another link at 375 px.

## Verification status

Exercised automatically (about 540 tests locally, including about 60 browser tests in Chromium,
plus the same mobile audit in WebKit in Playwright's container; about 94% line coverage;
`mypy --strict` and ruff clean): policy precedence and the specification's acceptance scenarios
against the dry-run firewall; DST edges; concurrency; the pull routes (token, source, 503,
malformed acknowledgements, the session/CSRF allowlist); the three parent alert states,
fail-open episodes and their dismissal, and the controller-outage note; accounts (password rules,
re-authentication, session revocation, rehash on login, audit without passwords); the pfSense
applier under bash and dash with stub commands (grammar, leases, grace, fail-open and recovery,
reboots, lock contention, the exact unprivileged fetch, configuration ownership); the installer,
TLS issuance, nginx site and backup/restore in a temporary prefix; and the daily screens at six
viewports for overflow, 44 px targets, text size and what is visible without scrolling.

The whole suite also passes on Python 3.13 with the Trixie library versions
(`check.sh --profile trixie`, which also runs the applier under dash).

**Not yet exercised**, because it needs your hardware: the application on the Pi (Gate 2
measurements), the applier under FreeBSD's `sh` on pfSense (`screentime-pull --self-test` at
Gate B), real `pfctl`, Cron and Kea behaviour, nginx's access rules (validated by `nginx -t` at
install time), and iOS/iPadOS (CA trust, Home Screen install, Web Push, real Safari rendering).
Work through OPERATIONS.md section 9, "Acceptance checklist on real hardware", and section 10,
"Raspberry Pi 1 resources", before relying on it.
