# Operations guide

## Overview

This guide covers everything outside the code: setting up pfSense to obey the controller,
trusting the controller's certificate on the children's devices, and running the system day to
day. It assumes the layout from `deploy/install.sh` (`/opt/screentime`) and a LAN of
`192.168.12.0/24` as in the example configuration; substitute your own addresses.

Contents: 1 Quick checks · 2 pfSense setup · 3 Children's devices · 4 Everyday tasks ·
5 Logs · 6 Upgrades · 7 Certificates · 8 Troubleshooting · 9 Acceptance checklist on real hardware

## 1. Quick checks

Run these on the Pi. `A` is shorthand for the admin CLI.

```bash
A="sudo -u screentime /opt/screentime/venv/bin/python /opt/screentime/app/scripts/admin_cli.py"
systemctl status screentime.service        # running?
curl -s http://127.0.0.1:8080/health/ready # {"status":"ready",...}; 503 means database or firewall trouble
$A status                                  # allowance, day locks, overrides, active sessions per child
$A reconcile --education                   # converge pfSense on the database right now
```

The parent **Diagnostics** page shows the same, plus the desired and actual `SCR_ACTIVE`
contents, the last successful pfSense contact, and every allowlist hostname with its addresses.

## 2. pfSense setup

Do this with `firewall.mode: dry_run`, then switch to `pfsense_ssh` at the end (step 2.8).

### 2.1 Static addresses

*Services, DHCP Server, LAN, DHCP Static Mappings* (reference P4): add a mapping for every
managed device (iPad, iPhone, Kids TV, Lounge TV) and for the Pi, using the addresses in
`config.yaml`. Consider *Deny unknown clients* so a new device cannot simply appear unmanaged.
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

### 2.9 IPv6

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
from the database.

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

```bash
cd /path/to/checkout && git pull
sudo deploy/install.sh          # replaces code, keeps config/data, refreshes venv, restarts if config is valid
```

Database migrations run automatically at start. Take a backup first if you like:
`sudo -u screentime /opt/screentime/app/deploy/backup.sh`. Roll back by checking out the previous
release and re-running `install.sh` (restore a backup only if a migration must be undone).

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
