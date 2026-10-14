#!/bin/sh
# screentime-edu-seen: keeps SCR_EDU_SEEN holding every public IPv4 address the education
# hostnames resolved to in the last four hours.
#
# Why: SCR_EDU_ALLOW is an FQDN alias that pfSense's filterdns re-resolves every 300 s, but the
# education CDNs answer with TTLs of 10 to 60 s. When a CDN moves a name, a child's device can be
# handed the new address up to 300 s before filterdns puts it in the table, and the app is
# blocked in the meantime. This script resolves the same names through the same Unbound cache
# the devices use, three times a minute, and remembers each address for KEEP_SECONDS, so an
# address the CDN hands out stays allowed after the CDN has moved on. Rule "4b education seen"
# passes SCR_EDU_DEVICES to SCR_EDU_SEEN on TCP 443, beside rule 4 for SCR_EDU_ALLOW.
#
# Install root-owned 0755 as /usr/local/sbin/screentime-edu-seen; run every minute as root from
# a Cron package entry. No configuration file: the hostnames come from the SCR_EDU_ALLOW lines
# pfSense writes to /var/etc/filterdns.conf, so the alias stays the single source.
# State: /var/db/screentime-edu-seen/ (root, 0700); the history survives filter reloads and
# reboots, and every pass rewrites the whole table, so a reload that resets it heals in 20 s.
#
#   screentime-edu-seen               one run (PASSES_PER_MINUTE passes), as cron does
#   screentime-edu-seen --status      print the hostnames, the table and the oldest entry
#   screentime-edu-seen --self-test   built-in tests with stub commands; run as a NON-root user

set -eu
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
LC_ALL=C
export LC_ALL

FILTERDNS_CONF=/var/etc/filterdns.conf
STATE_DIR=/var/db/screentime-edu-seen
PFCTL=/sbin/pfctl
DRILL=/usr/bin/drill
LOCKF=/usr/bin/lockf
LOGGER=/usr/bin/logger
NOW_OVERRIDE=""
PASSES_PER_MINUTE=3

SOURCE_ALIAS=SCR_EDU_ALLOW
TABLE=SCR_EDU_SEEN
RESOLVER=127.0.0.1         # pfSense's Unbound: the cache the devices themselves use
KEEP_SECONDS=14400         # four hours (owner decision)
MAX_ENTRIES=2048           # bounds the table if a name starts answering with many addresses
MAX_NAMES=200

log() {
    "$LOGGER" -t screentime-edu-seen "$1" 2>/dev/null || true
}

die() {
    printf 'screentime-edu-seen: %s\n' "$1" >&2
    log "refused: $1"
    exit "${2:-1}"
}

MODE=run
case "${1:-}" in
    '') ;;
    --status) MODE=status ;;
    --self-test) MODE=self-test ;;
    *) die "usage: screentime-edu-seen [--status | --self-test]" 64 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    # Unprivileged runs can only do what that user could do anyway, so the test-suite and
    # --self-test may point the script at stubs, a private state directory and a fixed clock.
    # As root the environment is never trusted.
    FILTERDNS_CONF=${SCREENTIME_SEEN_FILTERDNS:-$FILTERDNS_CONF}
    STATE_DIR=${SCREENTIME_SEEN_STATE:-$STATE_DIR}
    PFCTL=${SCREENTIME_SEEN_PFCTL:-$PFCTL}
    DRILL=${SCREENTIME_SEEN_DRILL:-$DRILL}
    LOCKF=${SCREENTIME_SEEN_LOCKF:-$LOCKF}
    LOGGER=${SCREENTIME_SEEN_LOGGER:-$LOGGER}
    NOW_OVERRIDE=${SCREENTIME_SEEN_NOW:-}
    PASSES_PER_MINUTE=${SCREENTIME_SEEN_PASSES:-$PASSES_PER_MINUTE}
elif [ "$MODE" = self-test ]; then
    die "--self-test must not run as root: su -m nobody -c '/usr/local/sbin/screentime-edu-seen --self-test'" 64
fi

now() {
    if [ -n "$NOW_OVERRIDE" ]; then printf '%s\n' "$NOW_OVERRIDE"; else date +%s; fi
}

# The state directory is written as root, so only root may be able to change it. Checked as
# root only; unprivileged test runs cannot be root-owned (same rule as screentime-pull).
check_state_dir() {
    [ -d "$STATE_DIR" ] || mkdir -m 0700 -p "$STATE_DIR"
    [ "$(id -u)" -eq 0 ] || return 0
    ls -ld "$STATE_DIR" | awk '{ exit !($3 == "root" && substr($1, 1, 10) == "drwx------") }' ||
        die "$STATE_DIR must be owned by root with mode drwx------" 78
}

# The SCR_EDU_ALLOW hostnames, one per line, lower case, deduplicated. filterdns lines start
# with "pf" followed by the host and the table; either order is accepted so a pfSense change in
# field order cannot silently empty the list. Anything that is not a plain DNS name is skipped.
hostnames() {
    [ -r "$FILTERDNS_CONF" ] || return 0
    awk -v t="$SOURCE_ALIAS" '
        $1 == "pf" && NF >= 3 { if ($3 == t) print $2; else if ($2 == t) print $3 }' "$FILTERDNS_CONF" |
        tr 'A-Z' 'a-z' |
        awk 'length($0) <= 253 && $0 ~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/' |
        sort -u | head -n "$MAX_NAMES"
}

# The A records in the answer section (CNAME chains are followed by Unbound; their A records
# are part of the answer). drill gives up after its own retries, so a dead resolver cannot hang
# a pass for long; cron's next run is serialised by lockf in any case.
resolve() {  # name
    "$DRILL" "$1" @"$RESOLVER" A 2>/dev/null |
        awk '/^;; ANSWER SECTION:/ { a = 1; next } /^;;/ { a = 0 } a && $4 == "A" { print $5 }'
}

# Keeps only lines whose first field is a well-formed public IPv4 address. A hostile or
# misconfigured name answering with a LAN, loopback or reserved address must not open that
# address to the children (DNS rebinding). Also re-validates the history file on every read, so
# a damaged file cannot inject an address.
public_ipv4() {
    awk '
        {
            n = split($1, o, ".")
            if (n != 4) next
            for (i = 1; i <= 4; i++) if (o[i] !~ /^(0|[1-9][0-9]?[0-9]?)$/ || o[i] + 0 > 255) next
            a = o[1] + 0; b = o[2] + 0; c = o[3] + 0
            if (a == 0 || a == 10 || a == 127 || a >= 224) next
            if (a == 100 && b >= 64 && b <= 127) next
            if (a == 169 && b == 254) next
            if (a == 172 && b >= 16 && b <= 31) next
            if (a == 192 && b == 168) next
            if (a == 192 && b == 0 && (c == 0 || c == 2)) next
            if (a == 198 && (b == 18 || b == 19)) next
            if (a == 198 && b == 51 && c == 100) next
            if (a == 203 && b == 0 && c == 113) next
            print $0
        }'
}

state_flag() {  # name value: logs only on a change, so cron does not flood the system log
    old=$(cat "$STATE_DIR/$1" 2>/dev/null || true)
    [ "$old" = "$2" ] && return 1
    printf '%s\n' "$2" > "$STATE_DIR/$1"
    return 0
}

one_pass() {
    t=$(now)
    names=$(hostnames)
    if [ -z "$names" ]; then
        # Never empty the table on a missing source: keep what is there until it expires.
        state_flag source missing && log "no $SOURCE_ALIAS hostnames in $FILTERDNS_CONF; table left as it is"
        return 0
    fi
    state_flag source ok && log "reading $(printf '%s\n' "$names" | wc -l | tr -d ' ') $SOURCE_ALIAS hostnames"

    fresh=$(mktemp "$STATE_DIR/fresh.XXXXXX")
    for name in $names; do resolve "$name"; done | public_ipv4 | sort -u > "$fresh"
    if [ -s "$fresh" ]; then
        state_flag resolver ok && log "resolving through $RESOLVER works"
    else
        state_flag resolver failing && log "no addresses from $RESOLVER; keeping the history until it expires"
    fi

    # Merge: "address last-seen", newest wins; drop entries older than KEEP_SECONDS; keep the
    # MAX_ENTRIES most recent.
    merged=$(mktemp "$STATE_DIR/seen.XXXXXX")
    {
        [ -f "$STATE_DIR/seen" ] && cat "$STATE_DIR/seen"
        awk -v t="$t" '{ print $1, t }' "$fresh"
    } | awk -v cutoff=$(( t - KEEP_SECONDS )) '
            NF == 2 && $2 ~ /^[0-9]+$/ && $2 + 0 >= cutoff { if (!($1 in last) || $2 + 0 > last[$1]) last[$1] = $2 + 0 }
            END { for (ip in last) print ip, last[ip] }' |
        public_ipv4 |
        sort -k2,2nr -k1,1 | head -n "$MAX_ENTRIES" > "$merged"
    mv -f "$merged" "$STATE_DIR/seen"
    rm -f "$fresh"

    if [ -s "$STATE_DIR/seen" ]; then
        list=$(mktemp "$STATE_DIR/table.XXXXXX")
        cut -d' ' -f1 "$STATE_DIR/seen" | sort > "$list"
        "$PFCTL" -t "$TABLE" -T replace -f "$list" >/dev/null 2>&1 || log "could not replace $TABLE"
        rm -f "$list"
    else
        "$PFCTL" -t "$TABLE" -T flush >/dev/null 2>&1 || log "could not flush $TABLE"
    fi
}

status() {
    names=$(hostnames)
    printf 'hostnames from %s (%s): %s\n' "$SOURCE_ALIAS" "$FILTERDNS_CONF" "$(printf '%s\n' "$names" | grep -c . || true)"
    [ -z "$names" ] || printf '  %s\n' $names
    count=$("$PFCTL" -t "$TABLE" -T show 2>/dev/null | grep -c . || true)
    printf 'addresses in %s: %s\n' "$TABLE" "$count"
    if [ -s "$STATE_DIR/seen" ]; then
        oldest=$(sort -k2,2n "$STATE_DIR/seen" | head -n 1 | cut -d' ' -f2)
        printf 'history: %s addresses, oldest last seen %s minutes ago (kept %s minutes)\n' \
            "$(wc -l < "$STATE_DIR/seen" | tr -d ' ')" $(( ($(now) - oldest) / 60 )) $(( KEEP_SECONDS / 60 ))
    else
        printf 'history: empty\n'
    fi
}

run_passes() {
    i=1
    while :; do
        one_pass
        [ "$i" -lt "$PASSES_PER_MINUTE" ] || break
        i=$(( i + 1 ))
        sleep $(( 60 / PASSES_PER_MINUTE ))
    done
}

# --- self-test (unprivileged, stub commands; run on pfSense to prove FreeBSD sh and awk) ----

self_test() {
    work=$(mktemp -d "${TMPDIR:-/tmp}/screentime-edu-seen-test.XXXXXX")
    trap 'rm -rf "$work"' EXIT HUP INT TERM
    mkdir "$work/state"
    cat > "$work/filterdns.conf" <<'EOF'
pf soraapp.com SCR_EDU_ALLOW
pf SCR_EDU_ALLOW api.readingeggs.com
pf other.example.com SOME_OTHER_ALIAS
pf bad_name!.com SCR_EDU_ALLOW
EOF
    cat > "$work/pfctl" <<'EOF'
#!/bin/sh
echo "$*" >> "$STUB/pfctl.log"
case "$*" in
  *"-T replace -f "*) cp "$6" "$STUB/table" ;;
  *"-T flush") : > "$STUB/table" ;;
  *"-T show") cat "$STUB/table" 2>/dev/null ;;
esac
exit 0
EOF
    cat > "$work/drill" <<'EOF'
#!/bin/sh
echo "$1" >> "$STUB/drill.log"
[ -f "$STUB/dns.$1" ] || exit 0
echo ';; ANSWER SECTION:'
cat "$STUB/dns.$1"
echo ''
echo ';; AUTHORITY SECTION:'
echo 'x. 60 IN A 9.9.9.9'
EOF
    printf '#!/bin/sh\necho "$*" >> "$STUB/syslog"\n' > "$work/logger"
    chmod 0755 "$work/pfctl" "$work/drill" "$work/logger"
    failures=0
    run() {  # time
        STUB=$work SCREENTIME_SEEN_FILTERDNS=$work/filterdns.conf SCREENTIME_SEEN_STATE=$work/state \
            SCREENTIME_SEEN_PFCTL=$work/pfctl SCREENTIME_SEEN_DRILL=$work/drill \
            SCREENTIME_SEEN_LOGGER=$work/logger SCREENTIME_SEEN_NOW=$1 SCREENTIME_SEEN_PASSES=1 \
            SCREENTIME_SEEN_LOCKED=1 sh "$0"
    }
    check() {  # description command...
        what=$1; shift
        if "$@"; then echo "PASS $what"; else echo "FAIL $what"; failures=$((failures + 1)); fi
    }
    printf 'soraapp.com. 60 IN A 13.224.181.65\nsoraapp.com. 60 IN A 192.168.12.20\n' > "$work/dns.soraapp.com"
    printf 'api.readingeggs.com. 300 IN CNAME x.cloudfront.net.\nx.cloudfront.net. 60 IN A 18.64.49.96\n' > "$work/dns.api.readingeggs.com"
    run 100000
    check "both filterdns field orders are read" grep -qx api.readingeggs.com "$work/drill.log"
    check "other aliases and bad names are ignored" test "$(wc -l < "$work/drill.log" | tr -d ' ')" -eq 2
    check "public answers enter the table" grep -qx 13.224.181.65 "$work/table"
    check "CNAME chains are followed" grep -qx 18.64.49.96 "$work/table"
    check "LAN answers are refused" sh -c "! grep -q 192.168.12.20 '$work/table'"
    check "other sections are ignored" sh -c "! grep -q 9.9.9.9 '$work/table'"
    printf 'soraapp.com. 60 IN A 13.224.181.94\n' > "$work/dns.soraapp.com"
    run 110000
    check "an address seen 2h 46m ago is kept" grep -qx 13.224.181.65 "$work/table"
    : > "$work/table"
    run 114500
    check "a reset table is rebuilt from the history" grep -qx 13.224.181.94 "$work/table"
    check "an address unseen for over 4 hours is removed" sh -c "! grep -q 13.224.181.65 '$work/table'"
    : > "$work/filterdns.conf"
    run 114560
    check "no hostnames: the table is left alone" grep -qx 13.224.181.94 "$work/table"
    check "no hostnames: logged" grep -q "no SCR_EDU_ALLOW hostnames" "$work/syslog"
    if [ "$failures" -eq 0 ]; then echo "self-test passed"; return 0; fi
    echo "self-test FAILED ($failures)"; return 1
}

# --- entry point ----------------------------------------------------------------------------

case "$MODE" in
    self-test) self_test; exit $? ;;
    status) status; exit 0 ;;
esac

check_state_dir

if [ -z "${SCREENTIME_SEEN_LOCKED:-}" ]; then
    # One run at a time: an overlapping run (a slow resolver) just exits.
    SCREENTIME_SEEN_LOCKED=1
    export SCREENTIME_SEEN_LOCKED
    rc=0
    "$LOCKF" -s -t 0 "$STATE_DIR/lock" sh "$0" || rc=$?
    [ "$rc" -ne 75 ] || exit 0
    exit "$rc"
fi

run_passes
