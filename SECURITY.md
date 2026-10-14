# Security notes and threat model

## Overview

This system decides whether children's devices may reach the Internet. The people it must resist
are curious, capable children on the home LAN, not remote attackers. It is designed to a household
standard (OWASP Top 10, the relevant ASVS controls, the CWE Top 25 classes that apply to a small web
service), with an honest list of what it cannot do and of two owner decisions that deviate from
that standard (fail-open, and 4-character passwords). Read [Known limitations](#known-limitations)
and [Recorded deviations](#recorded-deviations) before relying on it.

Since v1.2 the controller holds **no pfSense credential**. pfSense pulls a small, strictly
formatted desired state from the controller once a minute and applies it with its own device map
and clock.

## Quick Start

The security-relevant setup, in order: OPERATIONS.md 1a (readiness checks), 2.1 (static mappings
and the Pi's static ARP entry), 2.5 (applier installed root-owned, configuration 0600, token never
typed into the command box), 2.11 (rules, with rule 2a blocking the Pi from pfSense and rule 0
replacing anti-lockout), then the [Household hardening checklist](#household-hardening-checklist).

## Trust boundaries

```
 Children's devices ─┐                      ┌──────────── pfSense 2.9.0 ─────────────┐
 Parents' phones ────┼─ LAN ── nginx ── app │ Cron (root, every minute)              │
                     │         (Pi)    ▲    │  screentime-pull                       │
                     │                 │    │   ├ fetch as `nobody` (curl)  ◀────────┼─ HTTPS GET /firewall/v1/desired
                     │                 │    │   ├ strict parse, own device map       │   (bearer token, private CA)
                     │                 └────┼───┤ pfctl -T replace (root)            │
                     │   POST /firewall/v1/applied └ ack, incl. fail-open history    │
                     │                      │ filterdns → SCR_EDU_ALLOW (FQDN alias) │
                     │                      │ edu-seen → SCR_EDU_SEEN (4 h history)  │
 Pi ─────────────────┴── blocked from pfSense management; DNS and NTP only ──────────┘
```

| Boundary | Trusted side | Untrusted side | Main control |
| --- | --- | --- | --- |
| Browser to nginx | nginx | Any LAN device, including the children's | TLS; private source addresses only; rate limits on every path that checks a password |
| nginx to app | App on 127.0.0.1 | nginx-supplied headers | App trusts `X-Real-IP` only from loopback |
| pfSense to Pi (fetch) | pfSense applier | The Pi's response | TLS to `screen.home.arpa` verified against the Pi's private CA (`--cacert`, `--resolve` to the Pi's address); fetch runs as `nobody` with a clean environment; at most 4 KiB; strict grammar, whole document or nothing; device IDs mapped only through pfSense's own map; leases capped at `MAX_LEASE` and timed by pfSense's clock |
| Pi to pfSense | pfSense | The Pi | **No path.** Rule 2a blocks the Pi from pfSense except DNS and NTP. No account or credential exists |
| LAN hosts to `/firewall/*` | App | Children's devices | nginx `allow <pfSense>; deny all`; the app checks the source again and a bearer token (SHA-256 stored, constant-time compare) |
| App to push services | Apple, Google, Mozilla, Microsoft push hosts | Endpoint URLs supplied by browsers | Allowlist of push hosts; https only; no IP literals, credentials or odd ports; redirects not followed |
| Operator to files | Root on the Pi | The `screentime` service account | Root-owned code; the service writes only its data directory |

**What a compromised Pi can still do:** enable or disable *known* devices, or stop answering so that
pfSense fails open after 600 s. It cannot supply addresses, touch other tables, rules or
configuration, or bypass the curfew except through staleness. No design can stop a compromised
controller granting the managed devices access: that is the product's function. pfSense bounds it.

The CA is pinned rather than the server's leaf key, so a routine certificate renewal does not break
fetches; a broken fetch causes fail-open, so a fragile pin would itself be a weakness.

## Assets and controls

| Asset | Threat | Control |
| --- | --- | --- |
| Parent and child passwords | Theft, guessing, replay | Argon2id hashes in the database only, never logged or audited; NFC-normalised; constant-time verification with a dummy hash for unknown users and for accounts without a password; cost from `security.password_hash`, never below the OWASP minimum, and old hashes upgraded at the next sign-in |
| Password choice | Guessable short passwords (D9) | Minimum `security.password_min_length` (default 4, see deviations); at most 128 characters (bounds Argon2 work); refuses the username, one repeated character, straight sequences and about 250 common passwords and PINs, including every year from 1950 to 2030 |
| Password changes | A stolen session changing a password; an attacker locking someone out | The current password for your own change, and the parent's own password before setting anyone else's (re-authentication); wrong passwords count toward the lockout; every change revokes all of that user's sessions (yours is rotated), clears their lockout and is audited with actor and subject; children cannot reach the endpoint (403) |
| Login | Brute force, CPU exhaustion | Per-child lockout (5 in 15 minutes, 15-minute lock, parent reset); parent logins throttled per source address so a child cannot lock a parent out; nginx `limit_req` on `/login`, the sibling-password endpoints and the password-change endpoints; one password check at a time across the process |
| Parent accounts | A child using a parent's login | One login per parent (D8), each audited with the source device; the parent dashboard shows "Last parent sign-in: name, time, device" |
| Sessions | Fixation, theft, CSRF | Random 256-bit token, HMAC-signed cookie, only a SHA-256 stored; new session on every login and password change; `HttpOnly`, `SameSite=Lax`, `Secure`; per-session CSRF token on every state-changing call; logout needs the CSRF token. Only `/firewall/v1/*` is exempt, by an explicit allowlist guarded by a test |
| Authorisation | A child calling parent endpoints | Role checked server-side on every route; children act only on their own sessions; fail-open alerts are never shown to children |
| pfSense token | Disclosure | Generated by `firewall-token rotate`, printed once, stored on the Pi only as SHA-256 (0600). On pfSense it lives in a root-owned 0600 file the applier refuses to read otherwise, reaches curl on stdin (never in the process list, CWE-214), and is entered through *Edit File*, not the command box whose history the browser keeps (CWE-532). Never logged |
| Firewall control | Abuse by a compromised Pi | pfSense decides addresses (its own map) and times leases (its own clock); the grammar admits only known device IDs and bounded seconds; the applier runs the fetch unprivileged and parses as root only a validated, size-capped document; table names fixed in its root-only configuration |
| Input | Injection, malformed values | Strict Pydantic models with `extra=forbid`; acknowledgements parsed by a whole-document grammar; no string-built SQL; Jinja autoescaping |
| Outbound requests | SSRF (CWE-918) through push subscriptions | Endpoints must be https on `push.allowed_endpoint_hosts`, with no IP literal, credentials or odd port; checked again before every send |
| Time | A wrong clock after a power cut (no RTC) | Until NTP has synchronised, child starts are refused and nothing is published; pfSense gets 503, keeps its leases and times them itself (plan 5.5) |
| Audit trail | Tampering, gaps | Append-oriented table: logins, password changes and resets, grants, locks, session lifecycle, rejections, firewall state changes, fail-open episodes and their dismissal, token rotation |
| Secrets at rest | Disclosure | Directories 0700, files 0600; push subscription keys encrypted in the database; backups 0600 on a separate USB drive, holding the token only as its hash |
| Transport | Sniffing on the LAN | TLS 1.2+ from a private CA constrained to `home.arpa` (it cannot vouch for other domains, tested); HTTP serves only the CA certificate and a redirect; both nginx servers are `default_server` and hide the nginx version |
| Browser | XSS, clickjacking, caching | Strict CSP (`script-src 'self'`, no inline scripts or styles), `nosniff`, `X-Frame-Options: DENY`, no referrer, `Cache-Control: no-store`, service worker never caches session pages |
| pfSense management | Children or the Pi reaching the GUI | Rule 0 lets only `SCR_ADMIN_HOSTS` reach the GUI, then anti-lockout is disabled (W5); rule 2a blocks the Pi (W6); SSH on pfSense is off |
| Process | Compromise of the service | Unprivileged account, `NoNewPrivileges`, read-only filesystem except its data directory and `/run/screentime`, no capabilities, private `/tmp` |

### Password hashing cost

Argon2id runs at m=19 MiB, t=2, p=1: the minimum in the OWASP Password Storage Cheat Sheet, which
ASVS V2.4 defers to. On the Raspberry Pi 1 that costs 1.41 s per check (measured). Configuration
below the minimum is refused. A hash made with other parameters still verifies and is re-hashed
with the configured ones at the user's next successful sign-in.

## Recorded deviations

### Fail-open after 600 s (owner decisions D3, D4)

If pfSense has had no valid document from the controller for longer than `STALE_GRACE` (600 s),
measured with pfSense's own clock, it allows **every managed device, unrestricted, with no
curfew**. The specification's principle "fail closed for recreational child access" is
**amended, not met**.

**Dissent, for the record.** Fail-open inverts the cheapest attack. Before, a child had to
compromise the Pi to get unrestricted Internet. Now they only need to make it unavailable for 10
minutes: pull its power or cable, flood its single core, impersonate its address (which cannot
forge a grant, because of TLS, but can cause staleness), or wait for an SD card failure. The owner
accepted this explicitly: the children are supervised by people, not only by the system.

**Controls kept:** the 600 s grace (a Pi reboot, about 3 minutes plus up to 90 s of NTP wait, does
not open the network); leases held during the grace (running sessions end on time, nothing new
opens early); the grace counts from the later of the last good fetch, pfSense's boot and the
applier's first run; the parent dashboard shows "not checking in" at 3 minutes, "probably allowed"
at 10, and each episode with its times afterwards (D13: pfSense sends no alerts, and nothing alerts
anyone while the Pi itself is off); a static ARP entry for the Pi where Kea offers one;
`STALE_POLICY=closed` restores fail-closed with one line on pfSense and no code change.

### 4-character minimum password length (owner decision D9)

ASVS 4.0.3 V2.1.1 requires at least 12 characters for user-set passwords. The owner chose 4 for
every account because the app is reachable only from the home LAN.

**Why the risk is not online guessing.** Parent logins are throttled per source address. A child
with two devices gets about 20 guesses an hour, which covers a 4-digit space in roughly 3 weeks at
worst. That is slow but not impossible.

**The realistic risk is that children learn parents' codes** by watching them being typed on a
phone, or by guessing birthdays and family numbers. A 4-character code is easy to observe in one
glance. A parent account grants unlimited time, so this is the most likely way the system will
actually be bypassed, and an easier one than fail-open.

**Compensating controls:** the common-password list and the sequence and repeat rejection; every
parent login audited with the source device, and "Last parent sign-in" on the parent dashboard; the
minimum is configurable (`security.password_min_length`), so it can be raised without a code change.

**Advice (not enforced):** parents should use something longer than 4 characters. Nothing in the
app prevents it.

## Fail-closed behaviour (while the controller is reachable)

- A child's session starts and is charged at once (D2); pfSense applies it at its next poll.
  If pfSense has not acknowledged the device within 150 s, the session is ended as
  `enforcement_failed`, the time is given back and the child is told "The Internet did not turn
  on". The app never claims a grant that did not happen.
- While pfSense has not fetched for 180 s, new child starts are refused and parents see why.
- Until the system clock is synchronised, child starts are refused and nothing is published
  (pfSense keeps its leases, timed by its clock; after the grace it treats the controller as broken).
- Revocation (stop, expiry, End today) reaches pfSense at its next poll; pfSense kills the
  connections of every device that leaves its tables.

## Known limitations

1. **Fail-open is a bypass.** See the recorded deviation above.
2. **Encrypted DNS and DNS over HTTPS.** Blocking port 53 does not stop a device that speaks DoH. It
   does not defeat the IP-based rules for entertainment traffic, but it lets a device resolve names
   that DNS-level filtering would hide.
3. **Mobile data.** A device with a SIM can leave the Wi-Fi.
4. **Native offline content.** Downloaded videos and offline games use no network; only the
   device's own Screen Time controls can limit those.
5. **VPNs, iCloud Private Relay, proxies and Tor**, and CDN-shared addresses behind the education
   allowlist. Disable Private Relay on managed devices; an address-based allowlist for CDN-hosted
   services is necessarily approximate. Measured on 14 Oct 2026: none of 30 popular sites resolved
   to the education CDN addresses. `SCR_EDU_SEEN` widens the set to every address seen in the last
   4 hours (still only the allowlisted names' own answers), and refuses LAN, loopback and reserved
   addresses so a name cannot be pointed at the LAN (DNS rebinding).
6. **Device identity is the IPv4 address.** Use static mappings by MAC, *Deny unknown clients*, and
   Fixed (not Rotating) private Wi-Fi addresses (OPERATIONS.md 2.1).
7. **IPv6** is not enforced. Keep it off on the LAN.
8. **Latency.** Changes reach pfSense within about a minute (D2): a child can lose up to a minute
   at Start and gain up to a minute after Stop.
9. **The Pi is a single point of trust.** Physical access to the Pi or its SD card yields the
   database and the CA key. It does not yield any pfSense credential.
10. **Device addresses are kept twice**, in `config.yaml` and pfSense's map. `firewall-check` and
    the diagnostics page compare them; a device missing from pfSense's map makes pfSense reject
    every document (and so, eventually, fail open).
11. **Not verified on hardware.** See "Verification status" in README.md. The applier is tested
    under bash and dash with stubs; FreeBSD's `sh` runs it first at Gate B (`--self-test`).
12. **A finite platform.** Debian 13 is expected to be the last release that supports the Pi 1's
    ARMv6 CPU (security updates until about mid-2028).
13. **SD card and power.** A power cut can corrupt an SD card; use a good supply.

## Household hardening checklist

- [ ] Static DHCP mappings for every managed device; *Deny unknown clients*; Private Wi-Fi Address Fixed/Off.
- [ ] Static ARP entry for the Pi on pfSense, if the Kea page offers it (A6).
- [ ] LAN rules exactly as in OPERATIONS.md 2.11, including rule 2a; anti-lockout replaced by rule 0; DNS forced to pfSense; IPv6 off.
- [ ] SSH on pfSense off; no `screentime` user on pfSense; remote notifications off (D13).
- [ ] `/usr/local/etc/screentime-pull.conf` root 0600; `firewall-check` matches.
- [ ] Each parent has their own login, with a password longer than 4 characters; children's passwords not shared.
- [ ] Private Relay off and no VPN profiles on managed devices.
- [ ] The Pi is physically out of reach; `ca.key` copied somewhere safe; backups verified by a trial restore.
- [ ] Nothing forwards ports 80, 443 or 22 from the WAN to the Pi or pfSense management.

## Reporting and maintenance

This is a private household system. Keep Raspberry Pi OS current monthly, then
`python -m app --check-deps` and the smoke test before restarting (OPERATIONS.md 6). Re-run
`deploy/install.sh` after upgrading the code, and re-install the applier on pfSense when
`deploy/pfsense-screentime-pull.sh` changes. Review the audit log occasionally for repeated
login failures, unexpected grants, password resets and fail-open episodes.
