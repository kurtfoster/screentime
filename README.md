# Screen-Time Controller

## Overview

A small, local-first web application that controls recreational screen Internet access for two
children. It runs on a Raspberry Pi behind nginx and drives pfSense runtime firewall tables
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

Status: the application, tests and deployment scripts are complete. It has **not** yet been run
against a real pfSense, a real Raspberry Pi, nginx, or an iPhone/iPad; see
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
bash scripts/check.sh        # or: make test
```

### Deploy to the Raspberry Pi

```bash
# On the Pi (Raspberry Pi OS Trixie, Python 3.12+), from a checkout of this repository:
sudo apt install -y nginx python3-venv openssl
sudo deploy/install.sh --extra-san <the Pi's LAN IP>
sudo -u screentime /opt/screentime/venv/bin/python /opt/screentime/app/scripts/make_password_hash.py   # once per login
sudo nano /opt/screentime/config/users.yaml      # paste the three hashes
sudo nano /opt/screentime/config/config.yaml     # devices, allowances, pfSense address
cd /opt/screentime/app && sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml \
  SCREENTIME_USERS=/opt/screentime/config/users.yaml \
  /opt/screentime/venv/bin/python -m app --check-config
sudo systemctl start screentime.service screentime-backup.timer
```

Then follow [OPERATIONS.md](OPERATIONS.md) to set up pfSense (aliases, rules, the `screenctl`
wrapper, the SSH key) and to install the local CA on the children's devices. Leave
`firewall.mode: dry_run` until pfSense is ready, then switch it to `pfsense_ssh`.

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
.venv/bin/python scripts/make_password_hash.py    # Argon2id hash for users.yaml
```

`users.yaml` must be mode 0600 (enforced at startup). The database, application secret and Web
Push key live in `storage.data_dir`.

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

- creates the `screentime` system account and `/opt/screentime/{app,config,data,backups,.ssh}`
  with tight permissions (data and SSH directories 0700, `users.yaml` 0600);
- installs the code (root-owned, read-only to the service) and builds a virtualenv, installing
  dependencies from PyPI (or `--wheelhouse DIR` for an offline install);
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
14 are kept in `/opt/screentime/backups`. Each is one 0600 tarball holding a SQLite-consistent
copy of the database (taken with SQLite's online-backup API, so it is safe while the service is
running), `config.yaml`, `users.yaml`, the application secret and the Web Push key. It does not
contain pfSense tables (rebuilt from the database) or the SSH private key.

To rebuild on a fresh Pi:

```bash
# 1. Fresh Raspberry Pi OS Trixie; clone the repository (same release, or newer)
sudo apt install -y nginx python3-venv openssl
sudo deploy/install.sh --extra-san <LAN IP>          # creates the account, venv, nginx, systemd
# 2. Copy your latest backup onto the Pi, then restore it
sudo deploy/restore.sh /path/to/screentime-YYYYmmdd-HHMMSS.tar.gz --yes
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
.venv/bin/playwright install chromium    # once, for the browser tests (they skip if unavailable)
```

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

The version shown on the diagnostics page comes from the `VERSION` file.

## Project layout

```
app/                 FastAPI application (config, policy, sessions, enforcement, routes, templates, static)
  firewall/          adapter interface, dry-run and SSH adapters, education resolver
migrations/          Alembic (applied automatically at startup, or: python -m app --init-db)
config/              example configuration and development configuration
deploy/              systemd units, nginx config, install/backup/restore scripts, pfSense wrapper
scripts/             password hashing, admin CLI, one-shot reconcile, icon generation, check.sh
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
12. **Python 3.12+** and Raspberry Pi OS Trixie. The installer refuses older Python with advice.
13. **`replace_active_ips`** in the SSH adapter is implemented as a diff of add/del operations (the
    wrapper has no atomic replace for the active table); the reconciler itself uses add/del plus
    state kills. Education tables are replaced atomically with `pfctl -T replace`.
14. **Scope kept out of v1**, as specified: VLANs, Switch, mobile data, MDM, DoH blocking, traffic
    inference, cloud accounts, multi-household.

## Verification status

Exercised automatically (297 tests, about 93% line coverage, `mypy --strict` and ruff clean):
policy precedence and every acceptance scenario in specification section 24.3 against the dry-run
firewall; DST edges; concurrency (two simultaneous extensions with room for one); fail-closed
behaviour; startup catch-up; the SSH adapter's command construction against a fake runner; the
`screenctl` wrapper against a stub `pfctl` including injection attempts; the DNS resolver against
a real loopback DNS server; the installer, TLS issuance and backup/restore in a temporary prefix;
and the critical browser flows in headless Chromium.

**Not yet exercised**, because it needs your hardware: a real pfSense (`pfctl` behaviour, the sudo
and forced-command setup, table persistence across filter reloads), a real Raspberry Pi and
systemd install, nginx (its configuration is validated by `nginx -t` at install time, not by the
test-suite), iOS/iPadOS behaviour (CA trust, Home Screen install, Web Push), and `screenctl` under
FreeBSD's `sh` (it is plain POSIX and tested under bash, but not under `dash` or FreeBSD `sh`).
Run through OPERATIONS.md section 9, "Acceptance checklist on real hardware", before relying on it.
