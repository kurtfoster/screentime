# Operations guide

## Overview

This guide covers everything outside the code: setting up pfSense to obey the controller,
trusting the controller's certificate on the children's devices, and running the system day to
day. It assumes the layout from `deploy/install.sh` (`/opt/screentime`) and a LAN of
`192.168.12.0/24` as in the example configuration; substitute your own addresses.

The controller host is a Raspberry Pi 1 Model B+ named `screentime`, reached by clients as
`screen.home.arpa` through a pfSense DNS override. Its limits (one slow core, no real-time clock,
an SD card) shape several procedures here; section 10 covers them.

Contents: 1 Quick checks · 2 pfSense setup · 3 Children's devices · 4 Everyday tasks ·
5 Logs · 6 Upgrades · 7 Certificates · 8 Troubleshooting · 9 Acceptance checklist on real hardware ·
10 Raspberry Pi 1 resources

## 1. Quick checks

Run these on the Pi. `A` is shorthand for the admin CLI.

```bash
A="sudo -u screentime /opt/screentime/venv/bin/python /opt/screentime/app/scripts/admin_cli.py"
systemctl status screentime.service        # running?
curl -s http://127.0.0.1:8080/health/ready # {"status":"ready",...}; 503: database, firewall or clock trouble
$A status                                  # resources, then allowance, day locks, overrides, sessions per child
$A reconcile --education                   # converge pfSense on the database right now
```

The parent **Diagnostics** page shows the same, plus the desired and actual `SCR_ACTIVE`
contents, the last successful pfSense contact, every allowlist hostname with its addresses,
resources and timing (section 10), the last backup and the installed library versions.

## 2. pfSense setup

Do this with `firewall.mode: dry_run`, then switch to `pfsense_ssh` at the end (step 2.8).

### 2.1 Static addresses

*Services, DHCP Server, LAN, DHCP Static Mappings* (reference P4): add a mapping for every
managed device (iPad, iPhone, Kids TV, Lounge TV) and for the Pi (192.168.12.20 in the
Implementation Plan), using the addresses in `config.yaml`. Check the Pi really is on the pfSense
LAN: `ip -4 addr show eth0; ip route` on the Pi must show 192.168.12.0/24 and a default route via
192.168.12.1. (During Gate 0 it was on 192.168.127.0/24, behind the Orbi.) Consider *Deny unknown clients* so a new device cannot simply appear unmanaged.
On iPhone/iPad, set *Wi-Fi, (i), Private Wi-Fi Address* to **Fixed** or **Off** for your network;
with **Rotating**, the device's MAC address changes and it would drift off its static mapping.

The Orbi 850 must be in **access-point mode** so pfSense (not the Orbi) hands out addresses and
sees each device's own IP.

### 2.2 Aliases

*Firewall, Aliases* (reference P2). Create **Host(s)** aliases:

| Alias | Contents | Purpose |
| --- | --- | --- |
| `SCR_ACTIVE` | leave empty | Filled at runtime by the controller: devices allowed full Internet right now |
| `SCR_EDU_ALLOW` | leave empty | Filled at runtime: destination addresses of the education allowlist |
| `SCR_KIDS_DEVICES` | all four device IPs | Every managed device |
| `SCR_EDU_DEVICES` | iPad and iPhone IPs | Devices with `education_allowlist: true` |
| `SCR_CONTROLLER` | the Pi's IP | Where the app lives |

Runtime edits to a table are lost when pfSense reloads its filter (for example after saving any
firewall change). That is by design: the controller re-converges `SCR_ACTIVE` within
`firewall.reconcile_seconds` (30 s) and `SCR_EDU_ALLOW` within
`firewall.education_dns_refresh_seconds` (300 s; lower it, minimum 30, if that gap matters).
Watch tables under *Diagnostics, Tables* (reference P1).

### 2.3 LAN rules

*Firewall, Rules, LAN*, in this order (first match wins; reference P3 for states):

| # | Action | Source | Destination | Notes |
| --- | --- | --- | --- | --- |
| 1 | Pass | `SCR_KIDS_DEVICES` | `SCR_CONTROLLER` TCP 80, 443 | Devices can always reach the controller, so parents never depend on a child grant |
| 2 | Pass | `SCR_KIDS_DEVICES` | *This firewall* TCP/UDP 53, UDP 123 | DNS and NTP from pfSense |
| 3 | Pass | `SCR_ACTIVE` | any | **Active sessions**: full access |
| 4 | Pass | `SCR_EDU_DEVICES` | `SCR_EDU_ALLOW` | **Education apps** while no session runs |
| 5 | Block (log) | `SCR_KIDS_DEVICES` | any | Everything else is blocked |
| 6 | Pass | LAN net | any | Parents and other devices, as before |

Because rule 5 sits above the general pass, a managed device is limited to what rules 1 to 4
allow. Removing an address from `SCR_ACTIVE` blocks *new* connections; the controller also kills
existing states (`screenctl kill-states`) so a running stream stops immediately.

Force devices to use pfSense for DNS: add a rule blocking outbound TCP/UDP 53 and TCP 853 from
`SCR_KIDS_DEVICES` to anything but pfSense. DNS-over-HTTPS cannot be blocked this way (see
SECURITY.md).

### 2.4 Name for the controller

*Services, DNS Resolver, Host Overrides*: host `screen`, domain `home.arpa`, IP = the Pi.
Devices then use `https://screen.home.arpa/`.

### 2.5 SSH access for the controller

1. *System, Advanced, Admin Access*: enable **Secure Shell**, authentication method **Public Key
   Only**. Restrict the SSH listener/rule to the Pi's address.
2. *System, Package Manager*: install **sudo**.
3. *System, User Manager*: add user `screentime`, no password, and grant the privilege
   **User - System: Shell account access**. Then, on the Pi:

   ```bash
   sudo -u screentime ssh-keygen -t ed25519 -N '' -f /opt/screentime/.ssh/id_ed25519
   sudo cat /opt/screentime/.ssh/id_ed25519.pub
   ```

4. Paste the public key into the user's **Authorized SSH Keys**, prefixed with a forced command
   and restrictions, on one line:

   ```
   command="sudo /usr/local/sbin/screenctl --ssh",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... screentime@pi
   ```

   With this, the key can run *only* the wrapper, whatever the client asks for.
5. Allow the user to run only the wrapper (*sudo* package settings, or `visudo`):

   ```
   screentime ALL=(root) NOPASSWD: /usr/local/sbin/screenctl
   ```

6. Verify the restriction really took effect (it must **not** print a shell prompt or `id` output):

   ```bash
   sudo -u screentime ssh -i /opt/screentime/.ssh/id_ed25519 screentime@192.168.12.1 id
   ```

   Expect `screenctl: operation not permitted` (or similar). If you get `uid=...`, the forced
   command is not active; fix that before continuing. Even then, the sudoers rule and the
   wrapper's own validation still limit what can be done.

### 2.6 Install the wrapper

```bash
scp /opt/screentime/app/deploy/pfsense-screenctl.sh admin@192.168.12.1:/tmp/screenctl
ssh admin@192.168.12.1
  install -o root -g wheel -m 0755 /tmp/screenctl /usr/local/sbin/screenctl
  cat > /usr/local/etc/screenctl.conf <<'EOF'
MANAGED_SUBNET=192.168.12.0/24
ALLOWED_IPS="192.168.12.30 192.168.12.31 192.168.12.40 192.168.12.41"
EOF
  chown root:wheel /usr/local/etc/screenctl.conf && chmod 0644 /usr/local/etc/screenctl.conf
```

`ALLOWED_IPS` must list exactly your managed devices; the wrapper then refuses any other address
even if the Pi were compromised. Keep a copy of both files: a pfSense reinstall may remove
files outside its configuration backup. The wrapper is POSIX `sh` and needs `pfctl`, `awk`,
`sed`, `mktemp` (all in the base system).

### 2.7 First contact

```bash
sudo -u screentime ssh -i /opt/screentime/.ssh/id_ed25519 screentime@192.168.12.1 \
     sudo /usr/local/sbin/screenctl health        # answers "ok"; accepts the host key (first use)
```

The controller pins the host key in `/opt/screentime/.ssh/known_hosts` from this first connection
(`StrictHostKeyChecking=accept-new`). If pfSense is ever reinstalled, remove the old line.

### 2.8 Switch on enforcement

Edit `firewall.mode: pfsense_ssh` in `config.yaml`, then `sudo systemctl restart screentime`.
Check *Diagnostics* shows "Enforcement: Healthy", start a session for yourself as a child, and
watch the address appear in *pfSense, Diagnostics, Tables, SCR_ACTIVE*.

### 2.9 Time server for the Pi

The Pi has no battery-backed clock. Until NTP has set its clock after a restart, the controller
grants nothing and refuses child starts, so pfSense should serve time on the LAN and the Pi should
not depend on the Internet for it. *Services, NTP*: select the **LAN** interface and save. The
installer already points the Pi at 192.168.12.1 first (`--ntp-server`), with public servers after
it. The Pi sits outside `SCR_KIDS_DEVICES`, so no rule change is needed. Check from the Pi:
`timedatectl timesync-status` shows `Server: 192.168.12.1`.

### 2.10 IPv6

The controller enforces on **IPv4 source addresses**. If your LAN also hands out IPv6, a managed
device can bypass the rules over IPv6. Either disable IPv6 on the LAN (simplest), or add a rule
above rule 3 blocking IPv6 from the LAN to any for the managed devices. The education resolver
records AAAA addresses too (`include_ipv6_in_education`), which only matters if you allow IPv6.

## 3. Children's devices

1. **Install the CA.** In Safari on the device open `http://screen.home.arpa/ca.crt`, tap
   *Allow*, then *Settings, General, VPN & Device Management*, tap the downloaded profile,
   *Install*. Then *Settings, General, About, Certificate Trust Settings*, and enable full trust
   for "Screen Time Local CA". (This is the one step that needs a parent's passcode. The CA is
   restricted to `home.arpa`.)
2. Open `https://screen.home.arpa/`, sign in, then *Share, Add to Home Screen*.
3. **Alerts (optional).** Open the Home Screen app, tap *Turn on alerts*, allow notifications.
   Requires iOS/iPadOS 16.4 or later and the Home Screen app. Alerts arrive while a session is
   running; an idle, blocked device cannot reach Apple's push service.
4. Parents do the same on their own phones.

If a child's Screen Time restrictions block installing profiles or website access, allow
`screen.home.arpa` in *Screen Time, Content & Privacy, Web Content*.

## 4. Everyday tasks

| Task | Parent dashboard | CLI (`$A`, see section 1) |
| --- | --- | --- |
| Give extra time | **+15 / +30 / +60** | `$A grant child8 30` |
| Stop a child now | **END NOW** | `$A end-session ID` |
| Finish the day | **END TODAY** (confirm) | `$A end-today child8` |
| Undo it | **CLEAR DAY LOCK** | `$A clear-lock child8` |
| TV for the parents | **15 / 30 / 60 / UNTIL STOPPED** | `$A tv kids_tv 60` or `$A tv kids_tv until-stopped` |
| Unlock a child login | **Unlock** under *Locked logins* | `$A unlock child8` |
| Cancel a grant window | **Cancel** under *Active overrides* | (revoke via dashboard) |
| Everything off | | `$A end-all` |

Change passwords: generate a new hash (`make_password_hash.py`), replace it in `users.yaml`,
`sudo systemctl restart screentime`. Change rules: edit `config.yaml`, `--check-config`, restart.
Restarting is safe at any time: on start the app closes anything that expired, then reconciles pf
from the database. On the Pi 1 a restart takes about a minute; `curl` on `/health/ready` shows when
it is back.

## 5. Logs

```bash
journalctl -u screentime -f                    # JSON lines: app, audit, firewall, resolver, push
journalctl -u screentime | grep '"logger": "screentime.audit"'
journalctl -u screentime | grep -E '"level": "(ERROR|CRITICAL)"'
```

The audit trail is also in the database (parent Diagnostics, or `$A audit`): every login, grant,
lock, session start/stop/extension, policy rejection and firewall failure, with actor and result.
Passwords, cookies, private keys and push keys are never logged. Firewall operations (add, remove,
replace, kill; duration; success or error) are stored for 30 days. On the pfSense side the wrapper
logs each operation to syslog under the tag `screenctl`.

## 6. Upgrades

**Operating system, monthly.** The libraries come from Raspberry Pi OS, so an OS upgrade can change
them. Do it outside screen-time hours (apt briefly needs 100 to 200 MB of memory), then prove the
libraries still meet the minimums before restarting:

```bash
sudo apt update && sudo apt full-upgrade -y
cd /opt/screentime/app && /opt/screentime/venv/bin/python -m app --check-deps
/opt/screentime/venv/bin/python scripts/smoke_test.py      # catches a package built for the wrong CPU
sudo systemctl restart screentime
```

If `--check-deps` or the smoke test fails, do not restart: the running service still has the old
libraries loaded. See the R1 fallbacks in section 10.

**Application.**

```bash
cd /path/to/checkout && git pull
sudo deploy/install.sh          # replaces code, keeps config/data, re-checks libraries, restarts if config is valid
```

Database migrations run automatically at start, and only when the schema is behind. Take a backup
first if you like: `sudo systemctl start screentime-backup.service`. Roll back by checking out the
previous release and re-running `install.sh` (restore a backup only if a migration must be undone).

Update `screenctl` on pfSense whenever `deploy/pfsense-screenctl.sh` changes (section 2.6).

## 7. Certificates

The server certificate is valid for 800 days and `install.sh` reissues it automatically when
fewer than 30 days remain (re-run it, or `--renew-tls` to force). Clients keep trusting it because
the CA is unchanged. The CA lasts 10 years; replacing it means reinstalling `ca.crt` on every
device. Keep `/etc/screentime/tls/ca.key` safe: it is what makes the certificates trustworthy.

## 8. Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| Red "Enforcement degraded" banner; children can't start | The Pi cannot run `screenctl` on pfSense. `$A reconcile` prints the error. Check SSH key, sudoers, `known_hosts`, that pfSense is up. It recovers on its own within 30 s once fixed. Running sessions keep running until their planned end (pf cannot be told to stop them while unreachable); the moment contact returns they are revoked. |
| Start works but the device still has no Internet | pfSense rules out of order (section 2.3); alias named differently; device IP differs from `config.yaml` (check the static mapping); IPv6 in use. Look at *Diagnostics, Tables, SCR_ACTIVE*. |
| Device keeps Internet after a session ends | The address is still in `SCR_ACTIVE` (see Diagnostics: desired vs actual), or the kill of existing states failed (look for `kill_states` errors). `$A reconcile` retries. |
| An education app does not work when idle | It needs hostnames that are not on the allowlist. Find them (pfSense *Status, System Logs, Firewall* shows blocked destinations, or a DNS log), add to `always_allowed`, restart. Expect some trial and error: destination-IP allowlists cannot perfectly describe CDN-backed apps. |
| Parent Diagnostics lists "unresolved" hostnames | DNS name is wrong or the Pi's resolver cannot answer; the last known addresses are kept while a name goes stale. |
| A child is locked out of signing in | Five wrong passwords lock the login for 15 minutes. Parent dashboard, *Unlock*, or `$A unlock`. |
| Service will not start | `journalctl -u screentime -n 50` shows the configuration errors (all at once). Fix and `--check-config`. |
| Times look wrong | Confirm `timedatectl` (NTP synchronised) and `timezone` in config. Everything is stored in UTC and shown in that timezone. |
| Red "clock is not synchronised" banner; children get `CLOCK_NOT_SYNCED`; nothing has Internet | The Pi restarted and NTP has not answered yet. Normal for up to a minute or two after boot. If it persists: `timedatectl timesync-status`; check pfSense *Services, NTP* serves the LAN (2.9) and that `systemd-timesyncd` is enabled. Grants resume within 30 s of synchronisation. |
| Install stops with "Illegal instruction" | A package was built for a newer ARM CPU than the Pi 1's. The smoke test's last line names it. Nothing in systemd was changed. Follow the R1 fallbacks in section 10. |
| Diagnostics: "Last backup: failed ... not a mounted drive" | The USB drive is unplugged, or missing from `/etc/fstab`. Plug it in and `sudo mount /mnt/screentime-backup`, then `sudo systemctl start screentime-backup.service`. The service itself is unaffected. |
| Service takes a minute to start, or systemd reports a start timeout | About a minute is normal on a Pi 1 (library imports alone take about 40 s). The unit allows 300 s. Longer than that: check `journalctl -u screentime -b` and the load on the Pi. |
| iPhone says the certificate is not trusted | Step 3.1, including *Certificate Trust Settings*. Confirm the address you typed is `screen.home.arpa` (or an IP you gave `--extra-san`). |
| No alerts on the iPad | Must be the installed Home Screen app on iOS 16.4+, alerts allowed, and the device must be inside a session. Alerts are a courtesy: sessions always end on time regardless. |
| `nginx -t` fails during install | The installer stops and prints nginx's message; fix, then re-run. |

If everything is on fire: `$A end-all`, then in pfSense empty `SCR_ACTIVE` by hand
(*Diagnostics, Tables*), and the children are locked to education-only until you fix it.

## 9. Acceptance checklist on real hardware

Work through this once, in dry-run mode first and again with `pfsense_ssh`. Tick each box.

- [ ] `--check-config` passes; service starts on boot (`systemctl is-enabled screentime`).
- [ ] From an iPhone: `https://screen.home.arpa/` loads without a warning; Add to Home Screen works.
- [ ] Child signs in and lands on their dashboard only; `/parent` shows "not available".
- [ ] Parent signs in; +15, End Today, Clear Day Lock, TV 15 min all work with one or two taps.
- [ ] Child starts 15 minutes on the iPad: the address appears in `SCR_ACTIVE`; YouTube/Netflix work.
- [ ] Child presses **STOP NOW**: the address leaves `SCR_ACTIVE`; a video that was playing stops within seconds.
- [ ] Child ignores expiry: the session ends at the planned time and the stream is cut.
- [ ] Idle device: Duolingo/Khan/Reading Eggs/Sora work; unrelated sites and streaming do not.
- [ ] Kids TV at 18:30 stops on a weekday; a parent +30 at 18:31 permits exactly until 19:01.
- [ ] Two children on Kids TV: TV stays on until the *last* one stops; a parent TV session keeps it on.
- [ ] Unplug the Pi's cable to pfSense for a minute: banner appears, new starts are refused; plug back in: recovers.
- [ ] In pfSense, save any firewall change (filter reload): within 30 s the active table is restored.
- [ ] Reboot the Pi during a session: after boot the session continues or has been closed correctly.
- [ ] `sudo -u screentime /opt/screentime/app/deploy/backup.sh` produces an archive; restore it on a spare machine.
- [ ] Alerts arrive on a Home Screen app at the five-minute warning.
- [ ] Every target in section 10.3 is met and recorded.
- [ ] With pfSense NTP blocked, reboot the Pi: no device is granted, a child start shows the clock message; unblock: it recovers.
- [ ] Pull the power during an active session and restore it: the service recovers, the session is correct, pf is reconciled.
- [ ] Unplug the USB backup drive and run a backup: it fails visibly on Diagnostics; the service is unaffected.

## 10. Raspberry Pi 1 resources

The Pi 1 has one 700 MHz ARMv6 core, 512 MB of memory shared with the GPU, no real-time clock and
an SD card. Memory is not the constraint (about 300 MB stays free); CPU time is, most of all at
start-up and at login. These procedures turn "is the Pi good enough?" into measurements.

### 10.1 Resource benchmark (Gate 0)

Run on the Pi over SSH, on a fresh card or after changing hardware. Stop and record the step if
anything prints `Illegal instruction`.

```bash
# 1. Give the GPU the minimum memory (the installer offers this too), then reboot
grep -q '^gpu_mem=16' /boot/firmware/config.txt || echo 'gpu_mem=16' | sudo tee -a /boot/firmware/config.txt
sudo reboot
# 2. Memory Linux can use: expect 470 or more
awk '/^MemTotal:/ {printf "memtotal_mb=%d\n", $2/1024}' /proc/meminfo
# 3. Idle system, at least 5 minutes after boot: expect used 120 MB or less, available 330 MB or more
free -m | awk '/^Mem:/ {printf "idle_used_mb=%d idle_available_mb=%d\n", $3, $7}'
ps -eo rss=,comm= --sort=-rss | head -10 | awk '{printf "%6d MB  %s\n", $1/1024, $2}'
# 4. Libraries and native code, then password cost at candidate settings
cd /opt/screentime/app && /opt/screentime/venv/bin/python scripts/smoke_test.py
/opt/screentime/venv/bin/python scripts/make_password_hash.py --calibrate
```

Measured on 27 September 2026: 474 MB total, 107 MB used idle, 64 MB for the libraries, 41.5 s
to import them, and 1.41 s per password check at m=19456, t=2, p=1 (7.08 s at v1.0's
m=65536, t=3, p=4).

### 10.2 With the service running (Gate 2)

After at least 10 minutes in dry-run mode, with a parent and a child dashboard open and one login:

```bash
PID=$(systemctl show -p MainPID --value screentime)
grep -E '^(VmRSS|VmHWM):' /proc/$PID/status
free -m | awk '/^Mem:/ {printf "running_used_mb=%d running_available_mb=%d\n", $3, $7}'
time curl -s -o /dev/null http://127.0.0.1:8080/health/ready
sudo systemctl restart screentime; time (until curl -sf http://127.0.0.1:8080/health/ready >/dev/null; do sleep 2; done)
```

The *Resources and timing* section of Diagnostics (and `$A status`) shows the rest: timer lag,
SSH latency, last password-check time, clock sync, under-voltage and the last backup.

### 10.3 Targets

| Measure | Target |
| --- | --- |
| Service restart to ready | 90 s or less |
| Cold boot to ready | 3 minutes or less |
| Login (password check plus page) | 2 s or less |
| Child Start to access granted (pfsense_ssh) | 1.5 s or less |
| Planned end to access removed | 15 s or less |
| App memory, steady | 90 MB or less (peak 110 MB) |
| System memory available, steady | 200 MB or more |
| Timer lag, worst in an hour | 5 s or less (a warning is logged above this) |
| Four idle dashboards, average CPU over 10 minutes | 5% or less |

### 10.4 When to replace the Pi

Reopen the hardware decision if any one of these holds for a week of normal use: child Start
slower than 3 s, or revocation later than 30 s; timer lag above 10 s more than once a day;
available memory below 100 MB at steady state; a required package with no ARMv6-safe build; or a
household rule that would have to be dropped. A Raspberry Pi Zero 2 W or 3B is the cheapest
remedy and uses the same install. Debian 13 is expected to be the last release that supports
ARMv6 (security support until about mid-2028), so plan the replacement before then anyway.

**R1 fallbacks** (a Raspberry Pi OS package is missing or crashes with "Illegal instruction"), in
order: a Bookworm-built package of a compatible version; a wheel built for ARMv6 on another machine
(QEMU with `QEMU_CPU=arm1176`) installed with `install.sh --wheelhouse DIR`; piwheels, only after
the smoke test passes with it.

### 10.5 Power, SD card and backups

- Use an official 5 V 2 A supply. Under-voltage is the commonest cause of SD card corruption on a
  Pi 1; Diagnostics shows the firmware's under-voltage and throttling flags, and the service logs a
  warning while they are active. `vcgencmd get_throttled` should print `throttled=0x0`.
- Use a high-endurance (A1 or better) microSD card. The database commits with
  `synchronous=FULL`, so a completed grant survives a power cut; the journal is capped at 64 MB.
- Backups go to the USB drive at `/mnt/screentime-backup` (`ext4`, `nofail` in `/etc/fstab`). The
  Pi 1 cannot boot from USB, so the database stays on the SD card.

**Restore drill** (twice a year, and after changing the drive): on a spare machine or a spare SD
card with the same release installed,

```bash
sudo deploy/restore.sh /mnt/screentime-backup/screentime-YYYYmmdd-HHMMSS.tar.gz --yes --no-service
sudo -u screentime /opt/screentime/venv/bin/python /opt/screentime/app/scripts/admin_cli.py status
```

and confirm that the children, allowances and today's sessions are as expected.
