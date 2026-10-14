# Operations guide

## Overview

This guide covers everything outside the code: setting up pfSense so that it pulls its
instructions from the controller, trusting the controller's certificate on the children's devices,
and running the system day to day. It assumes the layout from `deploy/install.sh`
(`/opt/screentime`) and a LAN of `192.168.12.0/24` as in the example configuration; substitute your
own addresses.

The controller host is a Raspberry Pi 1 Model B+ named `screentime`, reached by clients as
`screen.home.arpa` through a pfSense DNS override. Its limits (one slow core, no real-time clock,
an SD card) shape several procedures here; section 10 covers them.

**How enforcement works (v1.2, the pull model).** pfSense runs a small applier,
`/usr/local/sbin/screentime-pull`, once a minute from the Cron package. It fetches the desired
state from `https://screen.home.arpa/firewall/v1/desired` (devices that may use the Internet, each
with a lease in seconds), applies it with its own device map and clock, and acknowledges what it
applied. The Pi holds no pfSense credential and cannot reach pfSense's management ports. If
pfSense hears nothing valid for `STALE_GRACE` (600 s), it **fails open**: every managed device is
allowed, with no curfew (owner decisions D3 and D4). Parents see that on the dashboard; pfSense
sends no alerts (D13).

Contents: 1 Quick checks · 1a Readiness checks · 2 pfSense setup · 3 Children's devices ·
4 Everyday tasks · 5 Logs · 6 Upgrades · 7 Certificates · 8 Troubleshooting ·
9 Acceptance checklist on real hardware · 10 Raspberry Pi 1 resources

## Quick Start

1. Install the controller on the Pi (README, "Deploy to the Raspberry Pi") and leave
   `firewall.mode: dry_run`.
2. Run the readiness checks in section 1a.
3. Set up pfSense with section 2, steps 2.1 to 2.10, in order. Gate B (2.9) runs with no rule
   using the tables, so nobody's Internet changes.
4. Wire the rules (2.11) and run the acceptance checklist (section 9).

## 1. Quick checks

Run these on the Pi. `A` is shorthand for the admin CLI.

```bash
A="sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml /opt/screentime/venv/bin/python /opt/screentime/app/scripts/admin_cli.py"
systemctl status screentime.service        # running?
curl -s http://127.0.0.1:8080/health/ready # {"status":"ready",...}; 503: database, firewall, clock or no parent login
$A status                                  # resources, then allowance, day locks, overrides, sessions per child
$A firewall-check                          # config.yaml against pfSense's device map and grace period
$A reconcile                               # recompute and publish the desired state now
```

The parent **Diagnostics** page shows the same, plus pfSense's last fetch and acknowledgement,
the desired and applied devices, the drift check, resources and timing (section 10), the last
backup and the installed library versions.

## 1a. Readiness checks

Run before the first install, and again (R3, R5, R6, R9, R10) after it. Each block only reads
state. Save the output with your change notes.

**[Pi]**, as your own user over SSH:

```bash
echo "== R1 os";        . /etc/os-release; echo "$PRETTY_NAME"; uname -m
echo "== R2 network";   ip -4 -br addr show eth0; ip route show default
echo "== R3 time";      timedatectl show -p NTPSynchronized --value; timedatectl timesync-status 2>/dev/null | grep -E 'Server|Offset'
echo "== R4 dns";       getent hosts screen.home.arpa || echo "screen.home.arpa does not resolve"
echo "== R5 service";   systemctl is-active screentime nginx; curl -s --max-time 5 http://127.0.0.1:8080/health/live; echo; cat /opt/screentime/app/VERSION 2>/dev/null
echo "== R6 tls";       sudo openssl x509 -in /etc/screentime/tls/screen.crt -noout -subject -ext subjectAltName -enddate
echo "== R7 resources"; free -m; df -h / /mnt/screentime-backup
echo "== R8 usb";       findmnt /mnt/screentime-backup; grep -n screentime-backup /etc/fstab || echo "no fstab entry"
echo "== R9 creds";     sudo ls -la /opt/screentime/data /opt/screentime/.ssh 2>&1
echo "== R10 fw mode";  sudo grep -nE '^\s*mode:' /opt/screentime/config/config.yaml
```

| Check | Expected | If not |
| --- | --- | --- |
| R1 | `Raspbian GNU/Linux 13 (trixie)`, `armv6l` | Stop: the Pi needs Raspberry Pi OS Lite (32-bit) Trixie. |
| R2 | `192.168.12.20/24`, `default via 192.168.12.1` | Check the pfSense DHCP static mapping for the Pi (2.1). |
| R3 | `yes`, `Server: 192.168.12.1` | Before the install the public pool is normal; `install.sh` makes pfSense the first server. |
| R4 | `192.168.12.20 screen.home.arpa` | pfSense host override (2.4). Blocks Gates B and C. |
| R5 | `active active`, `{"status":"ok","version":"1.2.0"}` | Not installed yet, or `sudo journalctl -u screentime -n 50`. |
| R6 | SAN contains `DNS:screen.home.arpa`; expiry more than a year away | `sudo deploy/install.sh --extra-san 192.168.12.20` reissues the leaf from the same CA. |
| R7 | At least 150 MB available; at least 1 GB free on `/` | `sudo apt clean; sudo journalctl --vacuum-size=50M` |
| R8 | `/dev/sda1` on `/mnt/screentime-backup`, an fstab line by UUID with `nofail,x-systemd.device-timeout=90s` | README, "USB backup drive". |
| R9 | `data` is 0700 and owned by `screentime`; `firewall-token.sha256` 0600 once rotated; **no `.ssh` directory** | v1.2 uses no SSH key. If `.ssh/id_ed25519` exists and was ever authorised on pfSense, delete it and remove that key from pfSense. |
| R10 | `mode: dry_run` until Gate B, then `mode: pfsense_pull` | Section 2.7. |

**[pfSense shell]**: *Diagnostics › Command Prompt › Execute Shell Command*. It runs as root and
is not interactive. Paste **one line per Execute**: the web prompt has garbled a multi-line paste
before.

```sh
cat /etc/version; uname -r
for t in curl lockf su php pfctl host; do printf '%s: ' $t; command -v $t || echo MISSING; done; curl --version | head -1
pkg info | grep -Ei 'cron|pfblocker|sudo|shellcmd'
pfctl -sr | grep -i 'anti-lockout' || echo "no anti-lockout rule"
sockstat -4 -l | grep ':123 '
ps axww -o command | grep -E '[k]ea-dhcp4|[d]hcpd'
su -m nobody -c 'id'
grep -E '<(aliasesresolveinterval|schedule_states|noantilockout)>' /cf/conf/config.xml || echo "none set (defaults)"
grep -A4 '<ssh>' /cf/conf/config.xml | head -6; grep -c '<name>screentime</name>' /cf/conf/config.xml
for h in www.duolingo.com www.khanacademy.org; do host -t A "$h" 127.0.0.1 | tail -2; done
```

| Check | Expected | If not |
| --- | --- | --- |
| Version | `2.9.0-RELEASE` | Record it; the applier needs only base tools and curl. |
| Tools | every tool found; curl reports OpenSSL | The applier requires curl (there is no `fetch` fallback). |
| Packages | `pfSense-pkg-Cron` present | *System › Package Manager › Available Packages › Cron*. |
| Anti-lockout | listed for 443 and 80 | Normal until step 2.11 replaces it with rule 0. |
| NTP | ntpd listening on 192.168.12.1:123 | *Services › NTP*: select **LAN**, Save. |
| DHCP | `kea-dhcp4` (Kea) | Record it: it decides the static-ARP step (2.1). |
| `su -m nobody` | `uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)`, nothing else | Stop and report: the applier's fetch depends on it. |
| Config flags | `schedule_states` absent | *System › Advanced › Miscellaneous*: untick **Schedule States**, so states are killed when the curfew starts. |
| SSH | no `<ssh>` section; `0` users named `screentime` | Section 2.10 removes an old SSH account. |
| Education names | real addresses, not `10.10.10.1` | If pfBlockerNG DNSBL sinkholes an education host, whitelist it there; otherwise the alias would allow the sinkhole. |

## 2. pfSense setup

Start with the controller in `firewall.mode: dry_run`. Steps 2.1 to 2.10 change nothing about
anyone's Internet access; step 2.11 switches enforcement on.

### 2.1 Static addresses and the Pi's ARP entry

*Services › DHCP Server › LAN › Static Mappings* (Kea): one mapping for every managed device
(iPad .30, iPhone .31, Kids TV .40, Lounge TV .41) and for the Pi (.20), using the addresses in
`config.yaml`. Consider *Deny unknown clients*. On iPhone and iPad set *Wi-Fi › (i) › Private Wi-Fi
Address* to **Fixed** or **Off**; with **Rotating** the device drifts off its mapping.

On the Pi's mapping, tick **ARP Table Static Entry** if the page offers it. A static entry stops
another device impersonating the Pi's address, which could otherwise make pfSense fail open
(assumption A6). If the Kea page does not offer it, record that and accept it: the fetch is
protected by TLS against the Pi's own CA, so impersonation can cause staleness but cannot forge a
grant. Do not add a hand-made `arp -S` boot script.

The Orbi must be in **AP Mode** so that pfSense hands out addresses and sees each device's IP.

### 2.2 Aliases

*Firewall › Aliases › IP*, each as type **Host(s)**:

| Alias | Contents | Filled by |
| --- | --- | --- |
| `SCR_ACTIVE_PERSONAL` | leave empty | The applier: personal devices with a lease |
| `SCR_ACTIVE_TV` | leave empty | The applier: TVs with a lease |
| `SCR_FAILOPEN` | leave empty | The applier, only in fail-open: every managed device |
| `SCR_EDU_ALLOW` | the education **hostnames** (below) | pfSense `filterdns`, every resolve interval (300 s) |
| `SCR_EDU_SEEN` | `192.0.2.1` (placeholder) | `screentime-edu-seen`: every address those hostnames resolved to in the last 4 hours (2.5a) |
| `SCR_KIDS_DEVICES` | 192.168.12.30, .31, .40, .41 | Static |
| `SCR_EDU_DEVICES` | 192.168.12.30, .31 | Static: devices allowed education apps while idle |
| `SCR_CONTROLLER` | 192.168.12.20 | Static |
| `SCR_ADMIN_HOSTS` | the parents' admin laptop(s) | Static: who may reach the pfSense GUI (rule 0) |

`SCR_EDU_ALLOW` holds names, not addresses (an FQDN alias): for example `www.duolingo.com`,
`duolingo.com`, `www.khanacademy.org`, `cdn.kastatic.org`, `www.readingeggs.com`,
`readingeggs.com`, and your school's Sora library host. pfSense resolves them itself; check the
result in *Diagnostics › Tables › SCR_EDU_ALLOW* and compare with `host <name>` (A4). Expect some
trial and error: CDN-backed apps use names you only find in pfSense's firewall log.

A filter reload (saving any firewall change) empties the runtime tables. The applier replaces all
three on every run, so they are back within a minute (C7). `screentime-edu-seen` rebuilds
`SCR_EDU_SEEN` from its own history within 20 seconds.

Why `SCR_EDU_SEEN` exists: the education CDNs answer with TTLs of 10 to 60 seconds, but `filterdns`
re-resolves only every 300 seconds. When a CDN moves a name, a device can be handed the new address
before `SCR_EDU_ALLOW` has it, and the app is blocked until the next resolve. `SCR_EDU_SEEN`
resolves the same names through the same Unbound cache three times a minute and keeps each address
for four hours after it was last seen, so an address once handed out stays allowed. It never holds
LAN, loopback or reserved addresses, even if a name resolves to one (DNS rebinding).

### 2.3 Curfew schedule

*Firewall › Schedules › Add*: name **`SCR_CURFEW`**, description "Personal devices allowed",
one time range for every day of the week, **06:00 to 21:00**. The schedule says when the rule that
uses it is active, so personal devices are allowed only inside it. Adjust the hours here at any
time; no code change is needed. pfSense kills a scheduled rule's states when the range ends,
provided *Schedule States* is unticked (section 1a).

### 2.4 Name for the controller

*Services › DNS Resolver › Host Overrides*: host `screen`, domain `home.arpa`, IP 192.168.12.20.
Devices then use `https://screen.home.arpa/`. The applier does not depend on it: it pins the name
to the Pi's address itself (`--resolve`).

### 2.5 Put the applier on pfSense (no SSH)

SSH on pfSense stays off. Files go up through the web interface and are installed with
`install`, so owner and mode are exact.

1. **[Workstation]** Get the two files: `deploy/pfsense-screentime-pull.sh` from this repository,
   and the controller's CA certificate, from `http://screen.home.arpa/ca.crt` (save it as
   `screentime-ca.crt`).
2. **[pfSense GUI]** *Diagnostics › Command Prompt*, section **Upload File**: upload
   `pfsense-screentime-pull.sh`, then `screentime-ca.crt`. Both land in `/tmp`.
3. **[pfSense shell]**, one line per Execute:

   ```sh
   install -o root -g wheel -m 0755 /tmp/pfsense-screentime-pull.sh /usr/local/sbin/screentime-pull
   install -o root -g wheel -m 0644 /tmp/screentime-ca.crt /usr/local/etc/screentime-ca.crt
   install -o root -g wheel -m 0600 /dev/null /usr/local/etc/screentime-pull.conf
   rm -f /tmp/pfsense-screentime-pull.sh /tmp/screentime-ca.crt; ls -l /usr/local/sbin/screentime-pull /usr/local/etc/screentime-ca.crt /usr/local/etc/screentime-pull.conf
   ```

   Expect `-rwxr-xr-x root wheel`, `-rw-r--r-- root wheel` and `-rw------- root wheel` (size 0).
   The configuration file is created empty and private **before** it holds the token, so it is
   never world-readable.
4. **[Pi]** Create the token pfSense will present. It is printed once; only its SHA-256 is kept:

   ```bash
   cd /opt/screentime/app && sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml \
     /opt/screentime/venv/bin/python scripts/admin_cli.py firewall-token rotate
   ```

5. **[pfSense GUI]** *Diagnostics › Edit File*: path `/usr/local/etc/screentime-pull.conf`,
   **Load**. Paste the contents of `deploy/screentime-pull.conf.example`, set `TOKEN=` to the
   token from step 4 and make the `DEVICE_` lines match `config.yaml`, then **Save**. Use Edit File,
   never *Execute Shell Command*, for the token: the command box keeps a history in the browser
   (CWE-532).
6. **[pfSense shell]** Prove the file is still private and complete, without printing the token:

   ```sh
   ls -l /usr/local/etc/screentime-pull.conf; grep -c '^DEVICE_' /usr/local/etc/screentime-pull.conf; grep -E '^(PI_URL|PI_ADDRESS|CA_FILE|STALE_GRACE|STALE_POLICY)=' /usr/local/etc/screentime-pull.conf
   ```

   Expect `-rw------- root wheel`, the number of devices (4), and the five settings. The applier
   refuses to run if the file is not root-owned 0600.

### 2.5a The education address history (screentime-edu-seen)

It needs nothing from the Pi and can be installed before the applier (Setup Phase B does).

1. **[pfSense GUI]** *Firewall › Aliases › IP › Add*: name `SCR_EDU_SEEN`, type **Host(s)**, one
   host `192.0.2.1` (placeholder; the script replaces it). **Save**, **Apply Changes**.
2. Upload `deploy/pfsense-screentime-edu-seen.sh` as in 2.5, then **[pfSense shell]**:

   ```sh
   install -o root -g wheel -m 0755 /tmp/pfsense-screentime-edu-seen.sh /usr/local/sbin/screentime-edu-seen
   su -m nobody -c '/usr/local/sbin/screentime-edu-seen --self-test'
   /usr/local/sbin/screentime-edu-seen; /usr/local/sbin/screentime-edu-seen --status
   ```

   Expect `self-test passed`, then the `SCR_EDU_ALLOW` hostnames and a non-zero address count. The
   hostnames come from `/var/etc/filterdns.conf`, which pfSense writes from the alias: there is no
   second list to maintain.
3. *Services › Cron › Add*: every field `*`, user **root**, command
   `/usr/local/sbin/screentime-edu-seen`. **Save**. Each run makes three passes 20 seconds apart.

### 2.6 Self-test and a TLS check

**[pfSense shell]**:

```sh
su -m nobody -c '/usr/local/sbin/screentime-pull --self-test'
```

Expect a column of `PASS` lines and `self-test passed`. This is the first proof under FreeBSD's
own `sh`; it runs unprivileged with built-in stubs and touches no table. Then prove pfSense can
reach the Pi over TLS with the pinned CA (A8):

```sh
curl -sS --max-time 5 --cacert /usr/local/etc/screentime-ca.crt --resolve screen.home.arpa:443:192.168.12.20 https://screen.home.arpa/health/live; echo
```

Expect `{"status":"ok","version":"1.2.0"}`.

### 2.7 Switch the controller to pull, then run the applier once by hand

1. **[Pi]** Edit `firewall.mode: pfsense_pull` in `/opt/screentime/config/config.yaml`, then
   `sudo systemctl restart screentime`. Until pfSense fetches, the parent dashboard warns that
   pfSense is not checking in and child starts are refused; that is expected for the next few
   minutes.
2. **[pfSense shell]**:

   ```sh
   /usr/local/sbin/screentime-pull; echo "exit=$?"; cat /var/db/screentime-pull/mode; cat /var/db/screentime-pull/generation
   ```

   Expect `exit=0`, `normal` and a generation number. If the mode is `grace`, read
   `/var/db/screentime-pull/fetch.err` (and the Pi's journal for `firewall request rejected`):
   usually the token or a device line. The applier's grace period starts at its first run, so a
   new installation never fails open straight away.
3. **[Pi]** `$A firewall-check` prints "config.yaml matches pfSense". Diagnostics shows the fetch
   and the acknowledgement.

### 2.8 Cron entry

*Services › Cron › Add*: minute `*`, hour `*`, day of month `*`, month `*`, day of week `*`, user
**root**, command `/usr/local/sbin/screentime-pull`. **Save**. The entry is stored in
`config.xml`, so it survives reboots and upgrades (A1: check it is still listed after the next
pfSense reboot). Overlapping runs simply exit (`lockf`).

### 2.9 Gate B: watch it work, with no rule using the tables

1. Start a session as a child: within a minute the iPad appears in *Diagnostics › Tables ›
   SCR_ACTIVE_PERSONAL* on pfSense, and the child's page stops saying "switching on". Stop it:
   it leaves the table, and `grep screentime-pull /var/log/system.log | tail` shows
   `states killed for 192.168.12.30`.
2. Pull the Pi's network cable for 11 minutes: after 600 s every device appears in
   `SCR_FAILOPEN`. Reconnect: `SCR_FAILOPEN` empties and the parent dashboard shows "Every device
   was allowed from … to …" with the right times (±1 min). Dismiss it.
3. Break the fetch with the Pi up (`firewall-token rotate` on the Pi only): the dashboard shows
   "not checked in" at 3 minutes and "probably allowed" at 10. Put the new token in pfSense's
   configuration (2.5 step 5): the episode banner appears.

No rule uses the tables yet, so nobody's Internet changes during Gate B.

### 2.10 Remove what v1.1 would have needed

Nothing here should exist (v1.1 was never installed, D12), but check: *System › User Manager*:
delete any `screentime` user. If nothing else uses SSH, *System › Advanced › Admin Access*:
untick **Secure Shell**. *System › Advanced › Notifications*: tick **Disable SMTP** and leave
Telegram, Pushover, Slack and Discord off (D13: the parent dashboard is the alert channel).

### 2.11 LAN rules (Gate C: enforcement on)

*Firewall › Rules › LAN*, in this order (first match wins):

| # | Action | Source | Destination | Schedule | Notes |
| --- | --- | --- | --- | --- | --- |
| 0 | Pass | `SCR_ADMIN_HOSTS` | *This firewall* TCP 443 | | Added and tested **before** disabling anti-lockout |
| 1 | Pass | `SCR_KIDS_DEVICES` | `SCR_CONTROLLER` TCP 80, 443 | | Devices can always reach the controller |
| 2 | Pass | `SCR_KIDS_DEVICES`, `SCR_CONTROLLER` | *This firewall* TCP/UDP 53, UDP 123 | | DNS and NTP (two rules if the GUI takes one source each) |
| 2a | Block (log) | `SCR_CONTROLLER` | *This firewall* any | | The Pi cannot reach pfSense's management |
| 3a | Pass | `SCR_ACTIVE_TV` | any | | TVs: no curfew |
| 3b | Pass | `SCR_FAILOPEN` | any | | Fail-open: no curfew (D4) |
| 3c | Pass | `SCR_ACTIVE_PERSONAL` | any | `SCR_CURFEW` | Personal devices, normal operation |
| 4 | Pass | `SCR_EDU_DEVICES` | `SCR_EDU_ALLOW` TCP 443 | | Education while idle, curfew or not |
| 4b | Pass | `SCR_EDU_DEVICES` | `SCR_EDU_SEEN` TCP 443 | | The same, for addresses seen in the last 4 hours (2.2) |
| 5 | Block (log) | `SCR_KIDS_DEVICES` | any | | Everything else |
| 6 | Pass | LAN net | any | | Parents and other devices, as before |

Then, from the admin laptop, confirm the GUI still loads through rule 0, and only then tick
*System › Advanced › Admin Access › Disable webConfigurator anti-lockout rule*. A child device must
now fail to reach pfSense on 443 (C10).

Force DNS through pfSense: block outbound TCP/UDP 53 and TCP 853 from `SCR_KIDS_DEVICES` to
anything but pfSense. DNS-over-HTTPS cannot be blocked this way (SECURITY.md).

The applier's own fetch is traffic from the firewall itself, which pfSense passes by default (A8).

### 2.12 Time server for the Pi

The Pi has no battery-backed clock. Until NTP has set it, the controller answers pfSense with
503 and publishes nothing, so pfSense keeps the leases it has and, after its grace period, fails
open (plan 5.5). *Services › NTP*: select the **LAN** interface. The installer points the Pi at
192.168.12.1 first. Check from the Pi: `timedatectl timesync-status` shows `Server: 192.168.12.1`.

### 2.13 IPv6

Enforcement is on IPv4 source addresses. Keep LAN IPv6 off (as it is now), or block IPv6 from the
managed devices.

### 2.14 Reinstalling pfSense

Restoring `config.xml` brings back the aliases, schedule, rules, static mappings and the Cron
entry. Files outside it do not come back: repeat 2.5 (applier, CA certificate, configuration file),
2.5a step 2 (`screentime-edu-seen`) and 2.6. Rotate the token on the Pi if you did not keep the old configuration file. Until the
applier is back, pfSense applies nothing: devices without a static rule are blocked (fail
closed), which is the safe direction.

## 3. Children's devices

1. **Install the CA.** In Safari on the device open `http://screen.home.arpa/ca.crt`, tap
   *Allow*, then *Settings › General › VPN & Device Management*, tap the downloaded profile,
   *Install*. Then *Settings › General › About › Certificate Trust Settings*, and enable full trust
   for "Screen Time Local CA". (This is the one step that needs a parent's passcode. The CA is
   restricted to `home.arpa`.)
2. Open `https://screen.home.arpa/`, sign in, then *Share › Add to Home Screen*.
3. **Alerts (optional).** Open the Home Screen app, tap *Turn on alerts*, allow notifications.
   Requires iOS/iPadOS 16.4 or later and the Home Screen app.
4. Parents do the same on their own phones. Parents with alerts on also get the pfSense
   "not checking in" and fail-open alerts as a push.

If a child's Screen Time restrictions block installing profiles or website access, allow
`screen.home.arpa` in *Screen Time › Content & Privacy › Web Content*.

## 4. Everyday tasks

| Task | Parent dashboard | CLI (`$A`, see section 1) |
| --- | --- | --- |
| Give extra time | child card: **+15 min / +30 min / +60 min** | `$A grant child8 30` |
| Stop something now | *Right now*: **Stop** | `$A end-session ID` |
| Finish the day | child card › **More** › **End today** (confirm) | `$A end-today child8` |
| Undo it | child card: **Clear day lock** | `$A clear-lock child8` |
| TV for the parents | *TV access*: **15 min / 30 min / 60 min / Until stopped** | `$A tv kids_tv 60` or `$A tv kids_tv until-stopped` |
| Unlock a child login | child card: **Unlock** | `$A unlock child8` |
| Set a child's password | child card › **More** › **Set password** (your own password confirms it) | `$A user set-password child8` |
| Change your own password | **Account › Change password** | |
| Reset the other parent's password | **Account › Parents › Reset password** | `$A user set-password <username>` |
| Add or remove a parent login | | `$A user add-parent <username> --name "<Name>"`, `$A user disable <username>` |
| Dismiss a fail-open alert | *Right now*: **Dismiss** | |
| Everything off | | `$A end-all` |

Change rules: edit `config.yaml`, `--check-config`, restart. Restarting is safe at any time: on
start the app closes anything that expired and publishes the desired state; pfSense picks it up
at its next poll. On the Pi 1 a restart takes about a minute, which is well inside pfSense's
grace period.

A device change (new address, new device) must be made in **both** `config.yaml` and pfSense's
`/usr/local/etc/screentime-pull.conf` (and the static aliases). `$A firewall-check` says what
differs. A device that is in `config.yaml` but missing from pfSense's map makes pfSense reject
every desired state that includes it, so check after every change.

## 5. Logs

```bash
journalctl -u screentime -f                    # JSON lines: app, audit, firewall, push
journalctl -u screentime | grep '"logger": "screentime.audit"'
journalctl -u screentime | grep -E '"level": "(ERROR|CRITICAL)"'
```

The audit trail is also in the database (parent Diagnostics, or `$A audit`): every login,
password change, grant, lock, session start/stop/extension, policy rejection, firewall state
change and fail-open episode, with actor and result. Passwords, tokens, cookies, private keys and
push keys are never logged. Firewall publications are stored when their generation changes, for
30 days.

On pfSense the applier logs to syslog under the tag `screentime-pull` (changes of mode, fetch
failures when the mode changes, state kills, a new boot): *Status › System Logs › General*, or
`grep screentime-pull /var/log/system.log | tail -20` in the shell.

## 6. Upgrades

**Operating system, monthly.** The libraries come from Raspberry Pi OS, so an OS upgrade can change
them. Do it outside screen-time hours, then prove the libraries still meet the minimums before
restarting:

```bash
sudo apt update && sudo apt full-upgrade -y
cd /opt/screentime/app && /opt/screentime/venv/bin/python -m app --check-deps
/opt/screentime/venv/bin/python scripts/smoke_test.py      # catches a package built for the wrong CPU
sudo systemctl restart screentime
```

**Application.**

```bash
cd /path/to/checkout && git pull
sudo deploy/install.sh          # replaces code, keeps config/data, re-checks libraries, restarts if config is valid
```

Database migrations run automatically at start. Take a backup first if you like:
`sudo systemctl start screentime-backup.service`. Roll back by checking out the previous release and
re-running `install.sh`.

When `deploy/pfsense-screentime-pull.sh` changes, repeat 2.5 steps 1 to 3 for the applier only,
then 2.6. The configuration file and the state in `/var/db/screentime-pull/` stay.

## 7. Certificates

The server certificate is valid for 800 days and `install.sh` reissues it automatically when
fewer than 30 days remain (re-run it, or `--renew-tls` to force). Clients and pfSense keep
trusting it because the CA is unchanged (pfSense pins the CA, not the leaf). The CA lasts 10
years; replacing it means reinstalling `ca.crt` on every device **and on pfSense** (2.5). Keep
`/etc/screentime/tls/ca.key` safe.

## 8. Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| Amber "pfSense has not checked in for N min"; children can't start | pfSense is not fetching. On pfSense: `grep screentime-pull /var/log/system.log | tail`; run `/usr/local/sbin/screentime-pull` by hand and look at `/var/db/screentime-pull/fetch.err`. Common causes: token rotated on the Pi only; Cron entry missing; CA changed; the Pi's address changed. |
| Red "every device is probably allowed" | Ten minutes without a fetch: pfSense has failed open. Fix as above; the next fetch restores control and the episode is recorded. |
| Red "Every device was allowed from … to …" | A past episode pfSense reported. Read it, then **Dismiss**. |
| "The controller was off from … to …" | The Pi itself was off longer than the grace period. pfSense's next acknowledgement says whether it failed open. |
| Diagnostics drift check lists a mismatch | `config.yaml` and pfSense's map differ. Fix one of them; `$A firewall-check` must say "matches". A device missing from pfSense's map makes every document be rejected. |
| Start works, Internet does not come on within a minute | The session is refunded after 150 s ("The Internet did not turn on"). Check the rules (2.11), that the device's address matches its mapping, and *Diagnostics › Tables*. |
| Device keeps Internet after a session ends | Up to a minute is normal (the next poll). Longer: is the device in `SCR_FAILOPEN` (fail-open), or in another pass rule above rule 5? |
| An education app does not work when idle | It needs a hostname not in `SCR_EDU_ALLOW`. Find it in *Status › System Logs › Firewall* (blocked destinations) and add it to the alias. `screentime-edu-seen --status` must list the new name within a minute. |
| `SCR_EDU_SEEN` holds only `192.0.2.1` or nothing | `screentime-edu-seen` is not running or finds no names: check the Cron entry, `grep screentime-edu-seen /var/log/system.log`, and `screentime-edu-seen --status`. |
| A child is locked out of signing in | Five wrong passwords lock the login for 15 minutes. Child card **Unlock**, setting a new password, or `$A unlock`. |
| "No password set for Child 8" | Child card › More › **Set password**. |
| Service will not start | `journalctl -u screentime -n 50` shows every configuration error at once. Old v1.1 settings (`always_allowed`, SSH fields) are rejected with where they went. |
| Red "clock is not synchronised" banner; children get `CLOCK_NOT_SYNCED` | The Pi restarted and NTP has not answered yet. Normal for a minute or two. If it persists: `timedatectl timesync-status`; check pfSense *Services › NTP*. pfSense keeps its leases meanwhile. |
| Install stops with "Illegal instruction" | A package was built for a newer ARM CPU. The smoke test names it. Follow the R1 fallbacks (10.4). |
| Diagnostics: "Last backup: failed … not a mounted drive" | Plug the USB drive in, `sudo mount /mnt/screentime-backup`, `sudo systemctl start screentime-backup.service`. |
| `http://192.168.12.20/` shows the nginx welcome page | Debian's default site is still enabled and is not the stock link, so the installer left it (it says so). Remove `/etc/nginx/sites-enabled/default` yourself if you do not need it. |
| iPhone says the certificate is not trusted | Step 3.1, including *Certificate Trust Settings*. |

If everything is on fire: `$A end-all`. If the Pi is beyond repair, pfSense fails open after 10
minutes; to force fail-closed instead, set `STALE_POLICY=closed` in pfSense's configuration file.

## 9. Acceptance checklist on real hardware

Gate C in `Firewall_Pull_Model_Plan.md` 10.3. Tick each box.

- [ ] C1: a child Start is charged from Start; the device is on within 90 s; the UI says "within a minute".
- [ ] C2: a Stop or planned end removes the device and kills its states within 90 s.
- [ ] C3: reboot the Pi mid-session: no fail-open; the session ends on its lease; reboot-to-first-fetch is at most 300 s (record it).
- [ ] C4: unplug the Pi for more than 600 s: every device is open, including in curfew hours. No alert anywhere (accepted).
- [ ] C5: reconnect: streams on devices without a grant are cut; the dashboard shows the episode with its times, on iPhone and iPad.
- [ ] C6: from a child's device, `https://screen.home.arpa/firewall/v1/desired` gives 403 from nginx.
- [ ] C7: save any pfSense firewall change: the tables are back within 70 s.
- [ ] C8: from the Pi, `nc -z -w 3 192.168.12.1 443` and port 22 both fail; DNS and NTP work.
- [ ] C9: `$A firewall-check` matches; change one address in pfSense's map and it reports the mismatch.
- [ ] C10: anti-lockout disabled: the admin laptop reaches the GUI; a child device cannot reach pfSense on 443 or 22.
- [ ] C11: an education app works while idle, during curfew.
- [ ] C12: a personal device with a granted session is blocked during curfew; the TV is unaffected.
- [ ] C13: each parent signs in with their own login and changes their password; a child changes theirs; a parent resets a child's. Works on iPhone and iPad; other sessions are signed out; the audit shows who did what.
- [ ] The household's real iPad and an iPhone, in Safari and as a Home Screen app: sign-in, Start, Stop, +15 min, a TV start and a password change all work.
- [ ] Every target in section 10.3 is met and recorded.

## 10. Raspberry Pi 1 resources

The Pi 1 has one 700 MHz ARMv6 core, 512 MB of memory shared with the GPU, no real-time clock and
an SD card. Memory is not the constraint (about 300 MB stays free); CPU time is, most of all at
start-up and at login.

### 10.1 Resource benchmark (Gate 0)

```bash
grep -q '^gpu_mem=16' /boot/firmware/config.txt || echo 'gpu_mem=16' | sudo tee -a /boot/firmware/config.txt
sudo reboot
awk '/^MemTotal:/ {printf "memtotal_mb=%d\n", $2/1024}' /proc/meminfo
free -m | awk '/^Mem:/ {printf "idle_used_mb=%d idle_available_mb=%d\n", $3, $7}'
cd /opt/screentime/app && /opt/screentime/venv/bin/python scripts/smoke_test.py
sudo -u screentime env SCREENTIME_CONFIG=/opt/screentime/config/config.yaml /opt/screentime/venv/bin/python -m app --calibrate-hash
```

Measured on 27 September 2026: 474 MB total, 107 MB used idle, 64 MB for the libraries, 41.5 s to
import them, and 1.41 s per password check at m=19456, t=2, p=1.

### 10.2 With the service running (Gate 2, on v1.2.0)

After at least 10 minutes, with a parent and a child dashboard open and one login:

```bash
PID=$(systemctl show -p MainPID --value screentime)
grep -E '^(VmRSS|VmHWM):' /proc/$PID/status
free -m | awk '/^Mem:/ {printf "running_used_mb=%d running_available_mb=%d\n", $3, $7}'
time curl -s -o /dev/null http://127.0.0.1:8080/health/ready
sudo systemctl restart screentime; time (until curl -sf http://127.0.0.1:8080/health/ready >/dev/null; do sleep 2; done)
```

The *Resources and timing* section of Diagnostics (and `$A status`) shows the rest: timer lag,
pfSense's last fetch, last password-check time, clock sync, under-voltage and the last backup.

### 10.3 Targets

| Measure | Target |
| --- | --- |
| Service restart to ready | 90 s or less |
| Cold boot to ready | 3 minutes or less |
| Reboot to first pfSense fetch | 300 s or less (half of `STALE_GRACE`) |
| Login (password check plus page) | 2 s or less |
| Child Start to device on (C1) | 90 s or less |
| Stop or planned end to device off (C2) | 90 s or less |
| App memory, steady | 90 MB or less (peak 110 MB) |
| System memory available, steady | 200 MB or more |
| Timer lag, worst in an hour | 5 s or less (a warning is logged above this) |
| Four idle dashboards, average CPU over 10 minutes | 5% or less |

### 10.4 When to replace the Pi

Reopen the hardware decision if any one of these holds for a week of normal use: timer lag above
10 s more than once a day; available memory below 100 MB at steady state; a reboot that takes
pfSense near its grace period; a required package with no ARMv6-safe build. A Raspberry Pi Zero 2 W
or 3B is the cheapest remedy and uses the same install. Debian 13 is expected to be the last
release that supports ARMv6, so plan the replacement before about mid-2028 anyway.

**R1 fallbacks** (a Raspberry Pi OS package is missing or crashes with "Illegal instruction"), in
order: a Bookworm-built package of a compatible version; a wheel built for ARMv6 on another machine
(QEMU with `QEMU_CPU=arm1176`) installed with `install.sh --wheelhouse DIR`; piwheels, only after
the smoke test passes with it.

### 10.5 Power, SD card and backups

- Use an official 5 V 2 A supply; `vcgencmd get_throttled` should print `throttled=0x0`.
- Use a high-endurance (A1 or better) microSD card. The database commits with
  `synchronous=FULL`; the journal is capped at 64 MB.
- Backups go nightly to the USB drive at `/mnt/screentime-backup` (README, "USB backup drive").
  The archive holds the database (with the login hashes), `config.yaml`, the application secret,
  the Web Push key and the pfSense token's hash.

**Restore drill** (twice a year): on a spare machine or SD card with the same release installed,

```bash
sudo deploy/restore.sh /mnt/screentime-backup/screentime-YYYYmmdd-HHMMSS.tar.gz --yes --no-service
sudo -u screentime /opt/screentime/venv/bin/python /opt/screentime/app/scripts/admin_cli.py status
```

and confirm that the children, allowances, logins and today's sessions are as expected.
