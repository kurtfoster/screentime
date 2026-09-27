# Security notes and threat model

## Overview

This system decides whether children's devices may reach the Internet, and it holds an SSH key
that can change firewall tables. The people it must resist are curious, capable children on the
home LAN, not remote attackers. It is designed to a household standard (OWASP Top 10, the
relevant ASVS controls, the CWE Top 25 classes that apply to a small web service), with an honest
list of what it cannot do. Read [Known limitations](#known-limitations) before relying on it.

## Trust boundaries

```
 Children's devices ─┐                       ┌── pfSense (root-owned screenctl, sudo rule,
 Parents' phones ────┼─ LAN ─ nginx ─ app ───┤    forced SSH command, only 2 tables touched)
                     │  (TLS, LAN-only)      └── SQLite + secrets on the Pi (user `screentime`)
 Internet ───────────┘  never reaches the app
```

| Boundary | Trusted side | Untrusted side | Main control |
| --- | --- | --- | --- |
| Browser to nginx | nginx | Any LAN device, including the children's | TLS; source restricted to private addresses; login rate limit |
| nginx to app | App on 127.0.0.1 | nginx-supplied headers | App trusts `X-Real-IP` only from loopback |
| App to pfSense | pfSense wrapper | The Pi | Key-only SSH, forced command, sudoers, wrapper validates every argument |
| App to push services | Apple, Google, Mozilla, Microsoft push hosts | Endpoint URLs supplied by browsers (so by any signed-in user) | Allowlist of push service hosts; https only; no IP literals, credentials or odd ports; redirects not followed |
| Wrapper to pf | pf | Wrapper input | Fixed operations, literal IPs inside the managed subnet and known-device list |
| Operator to files | Root on the Pi | The `screentime` service account | Root-owned code, service can write only its data directory |

The Pi is the crown jewel: whoever controls the app (or the SSH key) controls the children's
Internet. Keep the children away from its shell, its SD card and its power.

## Assets and controls

| Asset | Threat | Control |
| --- | --- | --- |
| Parent and child passwords | Theft, guessing, replay | Argon2id hashes only, in a 0600 file refused at startup if broader; no plaintext anywhere, never logged; constant-time verification with a dummy hash for unknown users (created on first use, not at import); cost from `security.password_hash`, which cannot go below the OWASP minimum (see below) |
| Login | Brute force, CPU exhaustion | Per-child lockout (5 in 15 minutes, 15-minute lock, parent reset); the parent login is throttled per source address so a child cannot lock the parents out; nginx `limit_req` on `/login` and on the sibling-password endpoints; bounded lockout table (unknown names are keyed by address); one password check at a time across the process, so a burst of logins queues rather than multiplying memory |
| Sessions | Fixation, theft, CSRF | Random 256-bit token, HMAC-signed cookie, only a SHA-256 stored server-side; new session on every login; `HttpOnly`, `SameSite=Lax`, `Secure` when HTTPS; server-side expiry; per-session CSRF token required on every state-changing API call, and a signed one-time token on the login form; logout requires the CSRF token |
| Authorisation | A child calling parent endpoints or another child's sessions | Role checked server-side on every route (page and API); children can act only on their own sessions (others return 404, not 403); parent pages return 403 to children |
| Input | Injection, malformed values | Strict Pydantic models with `extra=forbid`; identifiers and durations validated against configuration; no string-built SQL (SQLAlchemy); Jinja autoescaping; addresses parsed as IP literals |
| Firewall control | Command injection, abuse of the key | Only the SSH adapter runs `ssh`; operations from a fixed set; IPs validated in the app **and** the wrapper; forced command; sudoers limited to the wrapper; wrapper accepts only the two configured tables, IPv4 devices inside the managed subnet and in `ALLOWED_IPS`, and only literal IPs for the education table |
| SSH control socket | Use of the shared pfSense connection by another local user | The multiplexing socket grants the same pfSense access as the private key, so it gets the same protection: a 0700 directory (`data/ssh-mux`) owned by the service account, under `ProtectSystem=strict`. Every call through it still runs the forced command. `firewall.ssh_multiplex: false` turns it off |
| Outbound requests | Server-side request forgery (CWE-918) through push subscriptions | Without a check, any signed-in child could make the Pi POST to an arbitrary address, including the pfSense web interface. Endpoints must be https on `push.allowed_endpoint_hosts` (or a subdomain), with no IP literal, credentials or non-standard port; checked at subscription and again before every send; redirects are never followed |
| Time | A wrong clock after a power cut (the Pi has no RTC) | Sessions that ended could look current, and new ones would be keyed to the wrong day. Until `systemd-timesyncd` has synchronised, nothing is granted and child starts are refused (see Fail-closed behaviour) |
| Audit trail | Tampering, gaps | Append-oriented table (no update/delete paths in the app), actor, action, subject, result for grants, locks, session lifecycle, rejections, logins and lockouts; firewall operations recorded with duration and error; wrapper logs to pfSense syslog |
| Secrets at rest | Disclosure | Directories 0700, files 0600; SSH key and Web Push key never logged; push subscription keys encrypted in the database; backup archives 0600 in a 0700 directory on a separate USB drive; SSH private key excluded from backups |
| Transport | Sniffing on the LAN | TLS 1.2+ from a private CA constrained to `home.arpa` (it cannot vouch for other domains, tested); HTTP serves only the CA certificate and a redirect |
| Browser | XSS, clickjacking, caching | Strict CSP (`script-src 'self'`, no inline scripts or styles), `nosniff`, `X-Frame-Options: DENY`, no referrer, `Cache-Control: no-store` on all non-static responses, service worker never caches session pages or API responses, htmx configured with eval and script tags off |
| Availability of administration | Parents blocked by a firewall fault | Parent access to the app depends on LAN rule 1, not on any child grant; restart is safe; admin CLI works without the web UI |
| Correctness | Race conditions, double charging | Policy check and write in one `BEGIN IMMEDIATE` transaction; idempotency keys against double taps; exact-second accounting; database authoritative and pf converged idempotently |
| Process | Compromise of the service | Runs as an unprivileged account, `NoNewPrivileges`, read-only filesystem except the data and SSH directories and its own `/run/screentime`, no capabilities, restricted address families, private `/tmp` |

### Password hashing cost

Argon2id runs at m=19 MiB, t=2, p=1: the minimum in the OWASP Password Storage Cheat Sheet, which
ASVS V2.4 defers to. On the Raspberry Pi 1 that costs 1.41 s per check (measured); v1.0's
m=64 MiB, t=3, p=4 cost 7.08 s and 64 MB per login, with a login blocking a worker for all of it.
Going higher would buy offline-cracking resistance for a file that is 0600 on a LAN-only host, at a
cost the household would feel at every login. Configuration below the minimum is refused, so the
floor stays auditable. `--check-config` flags `users.yaml` hashes made with other parameters
(they still work) and prints the command to regenerate them. Use a long passphrase for the parent
account.

## Fail-closed behaviour

- A child session is granted only after pfSense has actually accepted the change. If it cannot,
  the session is marked `enforcement_failed`, nothing is charged, and the child is told honestly.
- While the firewall cannot be reached, new child sessions are refused and parents see a banner
  and (if enabled) a push alert.
- Until the system clock has been synchronised after a restart, the controller grants nothing: the
  set of devices that should have access is treated as empty, so pf is emptied, child starts are
  refused with `CLOCK_NOT_SYNCED`, `/health/ready` reports not ready and parents see a banner.
  Parent actions are still accepted, but grant nothing until the clock is right.
- Revocation cannot be delivered while pfSense is unreachable. Running sessions stay open until the
  controller regains contact; the database still records them as ended on time, so nobody is
  overcharged, and the next reconcile revokes them and kills their connections.

## Known limitations

These are inherent to the chosen architecture or explicitly out of scope, and they matter:

1. **Encrypted DNS and DNS over HTTPS.** Blocking port 53 does not stop a device that speaks DoH
   (iOS supports DNS profiles and browsers can enable it). This does not defeat the IP-based
   firewall for entertainment traffic, but it lets a device *resolve* names the resolver would
   have hidden, and it can defeat any DNS-level filtering you add on top.
2. **Mobile data.** A device with a SIM can leave the Wi-Fi. The controller cannot see it.
3. **Native offline content.** Downloaded videos, games and offline apps use no network. Only the
   device's own Screen Time controls can limit those.
4. **VPNs, iCloud Private Relay, proxies and Tor.** Traffic to an allowed education address that is
   in fact a shared CDN, or any tunnel a child can establish while a session is active, is not
   distinguishable by destination address. Disable Private Relay on managed devices. An IP-based
   allowlist for CDN-hosted services is necessarily approximate.
5. **Device identity is the IPv4 address.** A child who changes their device's address (static
   IP settings, MAC randomisation with DHCP) escapes the managed set unless pfSense assigns
   addresses by MAC with *Deny unknown clients*, and unknown devices land in a restricted pool.
   Configure pfSense that way; see OPERATIONS.md 2.1.
6. **IPv6** is not enforced (OPERATIONS.md 2.10). Disable it on the LAN or block it for managed devices.
7. **Shared credentials.** A child who learns a sibling's or a parent's password gains that
   person's powers. There is one parent login by design. Use a strong, unshared parent password.
8. **The Pi is a single point of trust.** Physical access to the Pi or its SD card yields the SSH
   key and the database. The forced command and wrapper limit what the key can do to two pf tables
   and only for known device addresses, but a stolen key can still open or close those devices.
9. **Web Push** depends on Apple and the device's reachability, and is a courtesy only; nothing in
   enforcement waits on it.
10. **pfSense semantics.** Runtime table edits vanish on a filter reload (repaired by reconciliation
    within 30 seconds; the education table within 5 minutes); behaviour was written against the
    documented `pfctl` interface and has not been run on your pfSense version. Re-check after major
    pfSense upgrades.
11. **Not verified on hardware.** See "Verification status" in README.md. In particular, the
    wrapper is tested under bash with a stub `pfctl`, not under FreeBSD's `sh`, and nginx and iOS
    behaviour have not been exercised.
12. **A finite platform.** Debian 13 is expected to be the last release that supports the Pi 1's
    ARMv6 CPU; security updates end around mid-2028. Replace the hardware before then
    (OPERATIONS.md 10.4).
13. **SD card and power.** A power cut can corrupt an SD card. Committed data is written with
    `synchronous=FULL` and backed up nightly to a separate drive, but use a good power supply.

## Household hardening checklist

- [ ] Static DHCP mappings for every managed device; *Deny unknown clients* enabled; Private Wi-Fi Address set to Fixed/Off.
- [ ] LAN rules exactly as in OPERATIONS.md 2.3; DNS forced to pfSense; IPv6 disabled or blocked.
- [ ] SSH to pfSense key-only, restricted to the Pi's address; forced command verified (2.5 step 6).
- [ ] `screenctl.conf` lists exactly the managed devices in `ALLOWED_IPS`.
- [ ] Strong, unique parent password; children's passwords not shared with each other.
- [ ] Private Relay off and no VPN profiles on managed devices (device Screen Time can lock this).
- [ ] The Pi is physically out of reach; SD card and backups stored safely; `ca.key` copied somewhere safe.
- [ ] Backups verified by a trial restore (README, Bare-metal restore).
- [ ] Nothing forwards ports 80, 443 or 22 from the WAN to the Pi or pfSense management.

## Reporting and maintenance

This is a private household system. On the Pi, dependencies are Raspberry Pi OS packages: keep
them current with a monthly `apt full-upgrade`, then `python -m app --check-deps` and the smoke
test before restarting (OPERATIONS.md section 6). Re-run `deploy/install.sh` after upgrading the
code. Review the audit log occasionally for repeated login failures or unexpected grants.
