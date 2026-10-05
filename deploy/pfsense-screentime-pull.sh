#!/bin/sh
# screentime-pull: pfSense fetches the Screen-Time controller's desired state and applies it.
#
# Install root-owned 0755 as /usr/local/sbin/screentime-pull; run every minute as root from a
# Cron package entry. Configuration: /usr/local/etc/screentime-pull.conf (root-owned, 0600).
# State: /var/db/screentime-pull/ (root, 0700). See OPERATIONS.md section 2.
#
#   screentime-pull               one run (POLLS_PER_MINUTE polls), as cron does
#   screentime-pull --self-test   built-in tests with stub commands; run as a NON-root user
#
# Each poll:
#   1. fetches GET <PI_URL>/firewall/v1/desired as `nobody` (su -m nobody, env -i, curl -q),
#      with the token and options on curl's stdin, never in the process list;
#   2. parses it strictly: any unexpected line, size or device rejects the whole document;
#   3. chooses the mode: normal after a good fetch; "grace" (keep leases) for STALE_GRACE
#      seconds after the later of the last good fetch and boot; then fail-open (every mapped
#      device allowed, no curfew) or, with STALE_POLICY=closed, nothing allowed;
#   4. replaces SCR_ACTIVE_PERSONAL, SCR_ACTIVE_TV and SCR_FAILOPEN in full, and kills the
#      states of devices that left all three;
#   5. acknowledges with POST <PI_URL>/firewall/v1/applied (best effort), reporting each
#      ended fail-open episode for 7 days. It never calls the pfSense notifier (D13).
#
# The controller decides only which known devices are on and for how long. Addresses come
# from this file's device map; leases are timed with this machine's clock.
#
# Configuration file (KEY=VALUE, one per line, values may be double-quoted):
#   PI_URL=https://screen.home.arpa          required: https and the controller's name
#   PI_ADDRESS=192.168.12.20                 required: the controller's LAN address
#   TOKEN=...                                required: from admin_cli.py firewall-token rotate
#   CA_FILE=/usr/local/etc/screentime-ca.crt required: the controller's CA (root, 0644)
#   MANAGED_SUBNET=192.168.12.0/24           required
#   DEVICE_<id>="<ipv4> personal|tv"         one per managed device (id: a-z 0-9 _)
#   MAX_LEASE=900  STALE_GRACE=600  STALE_POLICY=open|closed  POLLS_PER_MINUTE=1
#   TABLE_PERSONAL=SCR_ACTIVE_PERSONAL  TABLE_TV=SCR_ACTIVE_TV  TABLE_FAILOPEN=SCR_FAILOPEN

set -eu
umask 077
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
LC_ALL=C
export LC_ALL

CONF=/usr/local/etc/screentime-pull.conf
STATE_DIR=/var/db/screentime-pull
PFCTL=/sbin/pfctl
SU=/usr/bin/su
SYSCTL=/sbin/sysctl
LOCKF=/usr/bin/lockf
LOGGER=/usr/bin/logger
NOW_OVERRIDE=""

PI_URL=""
PI_ADDRESS=""
TOKEN=""
CA_FILE=""
MANAGED_SUBNET=""
DEVICES=""                 # "id:ip:kind id:ip:kind ..."
MAX_LEASE=900
STALE_GRACE=600
STALE_POLICY=open
POLLS_PER_MINUTE=1
TABLE_PERSONAL=SCR_ACTIVE_PERSONAL
TABLE_TV=SCR_ACTIVE_TV
TABLE_FAILOPEN=SCR_FAILOPEN
EPISODE_REPORT_SECONDS=604800   # report an ended fail-open episode for 7 days
MAX_DOCUMENT=4096
# The exact unprivileged fetch (plan 6.4, F8). Kept literal so a test can compare it.
FETCH='env -i PATH=/bin:/usr/bin /usr/local/bin/curl -q -K -'

log() {
    "$LOGGER" -t screentime-pull "$1" 2>/dev/null || true
}

die() {
    printf 'screentime-pull: %s\n' "$1" >&2
    log "refused: $1"
    exit "${2:-1}"
}

# --- environment: stubs only for unprivileged runs ------------------------------------------

if [ "${1:-}" = "--self-test" ]; then
    SELF_TEST=1
else
    SELF_TEST=0
fi

if [ "$(id -u)" -ne 0 ]; then
    # Unprivileged runs can only do what that user could do anyway, so the test-suite and
    # --self-test may point the script at stub commands, a private config and state, and a
    # fixed clock. As root the environment is never trusted.
    CONF=${SCREENTIME_PULL_CONF:-$CONF}
    STATE_DIR=${SCREENTIME_PULL_STATE:-$STATE_DIR}
    PFCTL=${SCREENTIME_PULL_PFCTL:-$PFCTL}
    SU=${SCREENTIME_PULL_SU:-$SU}
    SYSCTL=${SCREENTIME_PULL_SYSCTL:-$SYSCTL}
    LOCKF=${SCREENTIME_PULL_LOCKF:-$LOCKF}
    LOGGER=${SCREENTIME_PULL_LOGGER:-$LOGGER}
    NOW_OVERRIDE=${SCREENTIME_PULL_NOW:-}
elif [ "$SELF_TEST" -eq 1 ]; then
    die "--self-test must not run as root: su -m nobody -c '/usr/local/sbin/screentime-pull --self-test'" 64
fi

now() {
    if [ -n "$NOW_OVERRIDE" ]; then printf '%s\n' "$NOW_OVERRIDE"; else date +%s; fi
}

# --- validation (moved from pfsense-screenctl.sh) -------------------------------------------

valid_ipv4() {
    # Digits and dots only: rejects empty input, whitespace and embedded newlines outright.
    case "$1" in ''|*[!0-9.]*) return 1 ;; esac
    printf '%s' "$1" | awk -F. '
        NF != 4 { exit 1 }
        { for (i = 1; i <= 4; i++) {
              if ($i !~ /^(0|[1-9][0-9]*)$/ || length($i) > 3 || $i + 0 > 255) exit 1
          } }
        END { }' 2>/dev/null
}

valid_cidr() {
    ip=${1%/*}
    bits=${1#*/}
    [ "$ip" != "$1" ] || return 1
    valid_ipv4 "$ip" || return 1
    case "$bits" in ''|*[!0-9]*) return 1 ;; esac
    [ "$bits" -ge 8 ] && [ "$bits" -le 32 ]
}

in_subnet() {
    awk -v ip="$1" -v cidr="$MANAGED_SUBNET" '
        function toint(a,   p) { split(a, p, "."); return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }
        BEGIN {
            split(cidr, c, "/")
            size = 2 ^ (32 - c[2])
            base = toint(c[1]); base = base - (base % size)
            v = toint(ip)
            exit !(v >= base && v < base + size)
        }'
}

is_number() {  # value min max
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#1}" -le 9 ] && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]
}

valid_device_id() {
    case "$1" in ''|*[!a-z0-9_]*) return 1 ;; esac
    [ "${#1}" -le 32 ]
}

# The file is read as root, so only root may be able to change it: owner root, mode 0600
# (it holds the token). Checked as root only; unprivileged test runs cannot be root-owned.
check_root_only() {  # path mode-string
    owner=root
    if [ "$(id -u)" -ne 0 ]; then
        # Tests can have the same check applied with themselves as the owner.
        [ "${SCREENTIME_PULL_ENFORCE_OWNER:-}" = 1 ] || return 0
        owner=$(id -un)
    fi
    ls -ld "$1" 2>/dev/null | awk -v want="$2" -v owner="$owner" '{ ok = ($3 == owner && substr($1, 1, 10) == want); exit !ok }' ||
        die "$1 must exist, be owned by $owner and have mode $2" 78
}

load_config() {
    check_root_only "$CONF" "-rw-------"
    [ -r "$CONF" ] || die "cannot read $CONF" 78
    while IFS='=' read -r key value || [ -n "$key" ]; do
        case "$key" in ''|'#'*) continue ;; esac
        value=$(printf '%s' "$value" | sed -e 's/^"//' -e 's/"$//')
        case "$value" in *[!A-Za-z0-9_./:\ -]*) die "unsupported characters in $key" 78 ;; esac
        case "$key" in
            PI_URL) PI_URL=$value ;;
            PI_ADDRESS) PI_ADDRESS=$value ;;
            TOKEN) TOKEN=$value ;;
            CA_FILE) CA_FILE=$value ;;
            MANAGED_SUBNET) MANAGED_SUBNET=$value ;;
            MAX_LEASE) MAX_LEASE=$value ;;
            STALE_GRACE) STALE_GRACE=$value ;;
            STALE_POLICY) STALE_POLICY=$value ;;
            POLLS_PER_MINUTE) POLLS_PER_MINUTE=$value ;;
            TABLE_PERSONAL) TABLE_PERSONAL=$value ;;
            TABLE_TV) TABLE_TV=$value ;;
            TABLE_FAILOPEN) TABLE_FAILOPEN=$value ;;
            DEVICE_*)
                id=${key#DEVICE_}
                valid_device_id "$id" || die "device id in $key must be a-z, 0-9 or _ (at most 32)" 78
                set -f
                # shellcheck disable=SC2086
                set -- $value
                set +f
                [ "$#" -eq 2 ] || die "$key must be \"<ipv4> personal|tv\"" 78
                case "$2" in personal|tv) ;; *) die "$key: type must be personal or tv" 78 ;; esac
                DEVICES="$DEVICES $id:$1:$2"
                ;;
            *) die "unknown configuration key $key" 78 ;;
        esac
    done < "$CONF"

    [ -n "$MANAGED_SUBNET" ] || die "MANAGED_SUBNET is required in $CONF" 78
    valid_cidr "$MANAGED_SUBNET" || die "MANAGED_SUBNET is not a valid IPv4 CIDR" 78
    case "$PI_URL" in
        https://*) host=${PI_URL#https://}
            case "$host" in ''|*[!a-z0-9.-]*) die "PI_URL must be https://<host name>, nothing more" 78 ;; esac ;;
        *) die "PI_URL must start with https://" 78 ;;
    esac
    PI_HOST=$host
    valid_ipv4 "$PI_ADDRESS" && in_subnet "$PI_ADDRESS" || die "PI_ADDRESS must be an address in MANAGED_SUBNET" 78
    case "$TOKEN" in ''|*[!A-Za-z0-9_-]*) die "TOKEN is missing or malformed" 78 ;; esac
    [ "${#TOKEN}" -ge 20 ] && [ "${#TOKEN}" -le 128 ] || die "TOKEN is missing or malformed" 78
    case "$CA_FILE" in /*) ;; *) die "CA_FILE must be an absolute path" 78 ;; esac
    [ -r "$CA_FILE" ] || die "cannot read CA_FILE $CA_FILE" 78
    check_root_only "$CA_FILE" "-rw-r--r--"
    is_number "$MAX_LEASE" 180 3600 || die "MAX_LEASE must be 180 to 3600 seconds" 78
    is_number "$STALE_GRACE" 120 86400 || die "STALE_GRACE must be 120 to 86400 seconds" 78
    is_number "$POLLS_PER_MINUTE" 1 6 || die "POLLS_PER_MINUTE must be 1 to 6" 78
    case "$STALE_POLICY" in open|closed) ;; *) die "STALE_POLICY must be open or closed" 78 ;; esac
    case "$TABLE_PERSONAL$TABLE_TV$TABLE_FAILOPEN" in *[!A-Za-z0-9_]*) die "table names must be alphanumeric" 78 ;; esac
    [ -n "$DEVICES" ] || die "no DEVICE_<id> entries in $CONF" 78
    seen=""
    for entry in $DEVICES; do
        ip=${entry#*:}; ip=${ip%:*}
        valid_ipv4 "$ip" && in_subnet "$ip" || die "device address $ip is not an IPv4 address in MANAGED_SUBNET" 78
        case " $seen " in *" $ip "*) die "device address $ip is listed twice" 78 ;; esac
        seen="$seen $ip"
    done
}

device_field() {  # id field(2=ip, 3=kind); empty if the id is not mapped
    for entry in $DEVICES; do
        case "$entry" in "$1":*) printf '%s\n' "$entry" | cut -d: -f"$2"; return 0 ;; esac
    done
    return 1
}

# --- state ------------------------------------------------------------------------------------

state_get() {  # name default
    if [ -f "$STATE_DIR/$1" ]; then cat "$STATE_DIR/$1"; else printf '%s\n' "$2"; fi
}

state_put() {  # name value
    printf '%s\n' "$2" > "$STATE_DIR/$1.new" && mv -f "$STATE_DIR/$1.new" "$STATE_DIR/$1"
}

boot_time() {
    "$SYSCTL" -n kern.boottime | sed -n 's/^{ *sec *= *\([0-9][0-9]*\),.*/\1/p'
}

# --- fetch, parse, acknowledge ------------------------------------------------------------

curl_config() {  # path [data]  -- written to curl's stdin; the token never reaches argv
    printf 'url = "%s%s"\n' "$PI_URL" "$1"
    printf 'header = "Authorization: Bearer %s"\n' "$TOKEN"
    printf 'proto = "=https"\ntlsv1.2\n'
    printf 'cacert = "%s"\n' "$CA_FILE"
    printf 'resolve = "%s:443:%s"\n' "$PI_HOST" "$PI_ADDRESS"
    printf 'max-time = 10\nmax-filesize = %s\nfail\nsilent\nshow-error\n' "$MAX_DOCUMENT"
    if [ "$#" -ge 2 ]; then
        printf 'header = "Content-Type: text/plain; charset=us-ascii"\n'
        printf 'data-binary = "%s"\n' "$2"
    fi
}

fetch() {  # output-file
    curl_config /firewall/v1/desired | "$SU" -m nobody -c "$FETCH" > "$1" 2>"$STATE_DIR/fetch.err"
}

# Validate the desired document; on success print "generation N" and one "id seconds" per line.
parse_desired() {  # file
    size=$(wc -c < "$1" | tr -d ' ')
    [ "$size" -le "$MAX_DOCUMENT" ] || return 1
    # Printable US-ASCII, newlines and CR (only as part of CRLF, checked below).
    [ "$(tr -d '\n\r\040-\176' < "$1" | wc -c | tr -d ' ')" -eq 0 ] || return 1
    known=""
    for entry in $DEVICES; do known="$known ${entry%%:*}"; done
    # CRLF is accepted; a CR anywhere else rejects the document. (awk, not sed: FreeBSD sed
    # has no \r escape.)
    awk -v known="$known" -v max_lease="$MAX_LEASE" '
        BEGIN { n = split(known, k, " "); for (i = 1; i <= n; i++) mapped[k[i]] = 1; state = 0 }
        { sub(/\r$/, ""); if ($0 ~ /\r/) { bad = 1; exit } }
        state == 0 { if ($0 != "screentime-desired v1") { bad = 1; exit } state = 1; next }
        state == 1 {
            if (NF != 2 || $1 != "generation" || $2 !~ /^[0-9]+$/ || length($2) > 18 || $0 != $1 " " $2) { bad = 1; exit }
            gen = $2; state = 2; next
        }
        state == 2 && $0 == "end" { state = 3; next }
        state == 2 {
            if (NF != 3 || $1 != "device" || $0 != $1 " " $2 " " $3) { bad = 1; exit }
            if ($2 !~ /^[a-z0-9_]+$/ || length($2) > 32 || !($2 in mapped)) { bad = 1; exit }
            if ($3 !~ /^[0-9]+$/ || length($3) > 9 || $3 + 0 < 1 || $3 + 0 > max_lease + 0) { bad = 1; exit }
            if ($2 in seen) { bad = 1; exit }
            seen[$2] = 1; out[++count] = $2 " " $3; next
        }
        state == 3 { bad = 1; exit }
        END {
            if (bad || state != 3) exit 1
            print "generation " gen
            for (i = 1; i <= count; i++) print out[i]
        }' "$1"
}

acknowledge() {  # generation mode now
    body="screentime-applied v1\\ngeneration $1\\nmode $2\\nstale $STALE_GRACE $STALE_POLICY\\n"
    episode=$(state_get last_episode "")
    if [ -n "$episode" ]; then
        start=${episode% *}; end=${episode#* }
        if [ $(( $3 - end )) -le "$EPISODE_REPORT_SECONDS" ]; then
            body="${body}last-failopen $(( $3 - start )) $(( end - start ))\\n"
        fi
    fi
    if [ -s "$STATE_DIR/leases" ]; then
        for id in $(cut -d' ' -f1 "$STATE_DIR/leases"); do body="${body}device $id\\n"; done
    fi
    for entry in $DEVICES; do
        id=${entry%%:*}; rest=${entry#*:}
        body="${body}known $id ${rest%%:*} ${rest#*:}\\n"
    done
    body="${body}end\\n"
    if curl_config /firewall/v1/applied "$body" | "$SU" -m nobody -c "$FETCH" >/dev/null 2>"$STATE_DIR/ack.err"; then
        [ "$(state_get ack_ok 1)" = 1 ] || log "acknowledgements reach the controller again"
        state_put ack_ok 1
    else
        [ "$(state_get ack_ok 1)" = 0 ] || log "acknowledgement failed: $(head -c 200 "$STATE_DIR/ack.err" | tr -cd '\040-\176')"
        state_put ack_ok 0
    fi
}

# --- apply ------------------------------------------------------------------------------------

replace_table() {  # table ips...
    table=$1
    shift
    if [ "$#" -eq 0 ]; then
        "$PFCTL" -t "$table" -T flush >/dev/null 2>&1 || log "could not flush $table"
        return 0
    fi
    list=$(mktemp "$STATE_DIR/table.XXXXXX")
    for ip in "$@"; do printf '%s\n' "$ip" >> "$list"; done
    "$PFCTL" -t "$table" -T replace -f "$list" >/dev/null 2>&1 || log "could not replace $table"
    rm -f "$list"
}

apply() {  # mode now
    personal=""; tv=""; failopen=""
    if [ -s "$STATE_DIR/leases" ]; then
        while read -r id expiry; do
            ip=$(device_field "$id" 2) || continue
            case "$(device_field "$id" 3)" in
                personal) personal="$personal $ip" ;;
                tv) tv="$tv $ip" ;;
            esac
        done < "$STATE_DIR/leases"
    fi
    if [ "$1" = fail-open ]; then
        for entry in $DEVICES; do ip=${entry#*:}; failopen="$failopen ${ip%:*}"; done
    fi
    # shellcheck disable=SC2086
    replace_table "$TABLE_PERSONAL" $personal
    # shellcheck disable=SC2086
    replace_table "$TABLE_TV" $tv
    # shellcheck disable=SC2086
    replace_table "$TABLE_FAILOPEN" $failopen
    now_on=" $personal $tv $failopen "
    for ip in $(state_get applied ""); do
        case "$now_on" in
            *" $ip "*) ;;
            *)  # Left every table: cut its existing connections, both directions.
                "$PFCTL" -k "$ip" >/dev/null 2>&1 || true
                "$PFCTL" -k 0.0.0.0/0 -k "$ip" >/dev/null 2>&1 || true
                log "states killed for $ip"
                ;;
        esac
    done
    # shellcheck disable=SC2086
    state_put applied "$(printf '%s\n' $personal $tv $failopen | sort -u | tr '\n' ' ')"
}

poll() {
    t=$(now)
    boot=$(boot_time)
    [ -n "$boot" ] || boot=0
    # Leases are timed by this boot's clock; after a reboot the tables are empty anyway.
    if [ "$(state_get boot "$boot")" != "$boot" ]; then
        rm -f "$STATE_DIR/leases"
        log "new boot: leases from the previous boot discarded"
    fi
    state_put boot "$boot"

    previous=$(state_get mode normal)
    generation=$(state_get generation 0)
    doc=$(mktemp "$STATE_DIR/desired.XXXXXX")
    parsed=$(mktemp "$STATE_DIR/parsed.XXXXXX")
    if fetch "$doc" && parse_desired "$doc" > "$parsed"; then
        generation=$(sed -n '1s/^generation //p' "$parsed")
        sed '1d' "$parsed" | while read -r id seconds; do
            printf '%s %s\n' "$id" $(( t + seconds ))
        done > "$STATE_DIR/leases.new"
        mv -f "$STATE_DIR/leases.new" "$STATE_DIR/leases"
        state_put last_good "$t"
        state_put generation "$generation"
        mode=normal
    else
        reason=$(head -c 200 "$STATE_DIR/fetch.err" 2>/dev/null | tr -cd '\040-\176')
        [ -n "$reason" ] || reason="the document was rejected"
        last_good=$(state_get last_good 0)
        reference=$last_good
        [ "$boot" -gt "$reference" ] && reference=$boot
        if [ $(( t - reference )) -le "$STALE_GRACE" ]; then
            mode=grace
        elif [ "$STALE_POLICY" = open ]; then
            mode=fail-open
        else
            mode=fail-closed
            rm -f "$STATE_DIR/leases"
        fi
        [ "$previous" = "$mode" ] || log "fetch failed: $reason"
    fi
    rm -f "$doc" "$parsed"

    # Expire leases that have passed.
    if [ -s "$STATE_DIR/leases" ]; then
        awk -v t="$t" '$2 > t' "$STATE_DIR/leases" > "$STATE_DIR/leases.new"
        mv -f "$STATE_DIR/leases.new" "$STATE_DIR/leases"
    fi

    # Fail-open episodes: opened when fail-open starts, closed at the next good fetch (also
    # after a reboot, so the time pfSense was down counts as uncontrolled).
    if [ "$mode" = fail-open ] && [ ! -f "$STATE_DIR/failopen_start" ]; then
        state_put failopen_start "$t"
    fi
    if [ "$mode" = normal ] && [ -f "$STATE_DIR/failopen_start" ]; then
        state_put last_episode "$(state_get failopen_start "$t") $t"
        rm -f "$STATE_DIR/failopen_start"
    fi
    if [ "$previous" != "$mode" ]; then
        log "mode $previous -> $mode"
        state_put mode "$mode"
    fi

    apply "$mode" "$t"
    acknowledge "$generation" "$mode" "$t"
}

run_polls() {
    i=1
    while :; do
        poll
        [ "$i" -lt "$POLLS_PER_MINUTE" ] || break
        i=$(( i + 1 ))
        sleep $(( 60 / POLLS_PER_MINUTE ))
    done
}

# --- self-test (unprivileged, stub commands; Gate B on pfSense) ---------------------------

self_test() {
    work=$(mktemp -d "${TMPDIR:-/tmp}/screentime-pull-test.XXXXXX")
    trap 'rm -rf "$work"' EXIT HUP INT TERM
    mkdir "$work/state"
    : > "$work/ca.crt"
    cat > "$work/conf" <<EOF
PI_URL=https://screen.home.arpa
PI_ADDRESS=192.168.12.20
TOKEN=selftest-token-selftest-token
CA_FILE=$work/ca.crt
MANAGED_SUBNET=192.168.12.0/24
DEVICE_ipad="192.168.12.30 personal"
DEVICE_kids_tv="192.168.12.40 tv"
EOF
    cat > "$work/pfctl" <<'EOF'
#!/bin/sh
echo "$*" >> "$STUB/pfctl.log"
case "$*" in *"-T replace -f "*) cp "$6" "$STUB/table.$2" ;; *"-T flush") : > "$STUB/table.$2" ;; esac
exit 0
EOF
    cat > "$work/su" <<'EOF'
#!/bin/sh
cat > "$STUB/curl.in"
if grep -q '/desired"' "$STUB/curl.in"; then cat "$STUB/response"; else cat "$STUB/curl.in" > "$STUB/ack.in"; fi
EOF
    printf '#!/bin/sh\necho "{ sec = $BOOT, usec = 0 } Mon Oct  5 10:00:00 2026"\n' > "$work/sysctl"
    printf '#!/bin/sh\necho "$*" >> "$STUB/syslog"\n' > "$work/logger"
    chmod 0755 "$work/pfctl" "$work/su" "$work/sysctl" "$work/logger"
    failures=0
    run() {  # time
        STUB=$work BOOT=${BOOT:-1000} SCREENTIME_PULL_CONF=$work/conf SCREENTIME_PULL_STATE=$work/state \
            SCREENTIME_PULL_PFCTL=$work/pfctl SCREENTIME_PULL_SU=$work/su \
            SCREENTIME_PULL_SYSCTL=$work/sysctl SCREENTIME_PULL_LOGGER=$work/logger \
            SCREENTIME_PULL_NOW=$1 SCREENTIME_PULL_LOCKED=1 sh "$0"
    }
    check() {  # description command...
        what=$1; shift
        if "$@"; then echo "PASS $what"; else echo "FAIL $what"; failures=$((failures + 1)); fi
    }
    export STUB BOOT
    printf 'screentime-desired v1\ngeneration 7\ndevice ipad 600\nend\n' > "$work/response"
    run 2000
    check "valid document enables the iPad" grep -qx 192.168.12.30 "$work/table.SCR_ACTIVE_PERSONAL"
    check "acknowledged generation 7, normal" grep -q 'generation 7\\nmode normal' "$work/ack.in"
    check "token only on curl's stdin" grep -q 'Bearer selftest-token' "$work/curl.in"
    printf 'screentime-desired v1\ngeneration 8\ndevice ipad 600\n' > "$work/response"
    run 2060
    check "truncated document: grace keeps the lease" grep -qx 192.168.12.30 "$work/table.SCR_ACTIVE_PERSONAL"
    check "mode grace reported" grep -q 'mode grace' "$work/ack.in"
    run 2700
    check "beyond STALE_GRACE: every device in SCR_FAILOPEN" grep -qx 192.168.12.40 "$work/table.SCR_FAILOPEN"
    printf 'screentime-desired v1\ngeneration 9\nend\n' > "$work/response"
    run 2760
    check "recovery flushes SCR_FAILOPEN" test ! -s "$work/table.SCR_FAILOPEN"
    check "recovery kills the iPad's states" grep -q -- '-k 192.168.12.30' "$work/pfctl.log"
    check "the episode is reported" grep -q 'last-failopen 60 60' "$work/ack.in"
    BOOT=5000
    printf 'screentime-desired v1\ngeneration 10\ndevice ipad 600\nend\n' > "$work/response"
    run 5100
    printf 'screentime-desired v1\ngeneration 11\nbogus\nend\n' > "$work/response"
    BOOT=9000
    run 9100
    check "reboot: old leases discarded, grace from boot" grep -q 'mode grace' "$work/ack.in"
    check "reboot: no lease survives" test ! -s "$work/table.SCR_ACTIVE_PERSONAL"
    if [ "$failures" -eq 0 ]; then echo "self-test passed"; return 0; fi
    echo "self-test FAILED ($failures)"; return 1
}

# --- entry point ----------------------------------------------------------------------------

if [ "$SELF_TEST" -eq 1 ]; then
    self_test
    exit $?
fi
[ "$#" -eq 0 ] || die "usage: screentime-pull [--self-test]" 64

load_config
[ -d "$STATE_DIR" ] || mkdir -m 0700 -p "$STATE_DIR"
check_root_only "$STATE_DIR" "drwx------"

if [ -z "${SCREENTIME_PULL_LOCKED:-}" ]; then
    # One run at a time: an overlapping run (a slow fetch, several polls a minute) just exits.
    SCREENTIME_PULL_LOCKED=1
    export SCREENTIME_PULL_LOCKED
    rc=0
    "$LOCKF" -s -t 0 "$STATE_DIR/lock" sh "$0" || rc=$?
    [ "$rc" -ne 75 ] || exit 0
    exit "$rc"
fi

run_polls
