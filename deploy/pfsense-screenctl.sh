#!/bin/sh
# screenctl: the only door from the Screen-Time controller into pfSense.
#
# Install root-owned on pfSense as /usr/local/sbin/screenctl (mode 0755) with its
# configuration in /usr/local/etc/screenctl.conf (root-owned, not group/other writable).
#
#   screenctl health
#   screenctl show-active
#   screenctl add-active   <ipv4>
#   screenctl del-active   <ipv4>
#   screenctl kill-states  <ipv4>
#   screenctl replace-edu  -            # addresses, one per line, on stdin
#
# Safety properties:
#   * A fixed set of operations; anything else is refused.
#   * Every address is validated as a literal IP. Device addresses must also lie inside the
#     managed subnet (and inside ALLOWED_IPS if that list is set).
#   * Only the two configured pf tables are ever touched; arguments never reach a shell.
#   * With `--ssh` (for an authorized_keys forced command) the requested operation is taken
#     from $SSH_ORIGINAL_COMMAND after a strict character check.
#
# Suggested authorized_keys line for the screentime user's key (one line):
#   command="sudo /usr/local/sbin/screenctl --ssh",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... screentime@pi
#
# Configuration file (KEY=VALUE, one per line):
#   MANAGED_SUBNET=192.168.12.0/24     required
#   ACTIVE_TABLE=SCR_ACTIVE            optional
#   EDU_TABLE=SCR_EDU_ALLOW            optional
#   ALLOWED_IPS="192.168.12.30 192.168.12.31 192.168.12.40 192.168.12.41"   optional

set -eu
umask 077
PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH

CONF=/usr/local/etc/screenctl.conf
PFCTL=pfctl
ACTIVE_TABLE=SCR_ACTIVE
EDU_TABLE=SCR_EDU_ALLOW
MANAGED_SUBNET=""
ALLOWED_IPS=""
MAX_EDU_ENTRIES=4096

die() {
    printf 'screenctl: %s\n' "$1" >&2
    logger -t screenctl "refused: $1" 2>/dev/null || true
    exit "${2:-1}"
}

# Unprivileged runs can only ever affect what that user could already do, so they may point
# the wrapper at a stub pfctl and a private config (used by the test-suite). As root the
# environment is never trusted.
if [ "$(id -u)" -ne 0 ]; then
    [ -n "${SCREENCTL_CONF:-}" ] && CONF=$SCREENCTL_CONF
    [ -n "${SCREENCTL_PFCTL:-}" ] && PFCTL=$SCREENCTL_PFCTL
else
    # The config is read as root, so it must not be modifiable by anyone else.
    if ! ls -ld "$CONF" 2>/dev/null | awk '{ ok = ($3 == "root" && substr($1,6,1) == "-" && substr($1,9,1) == "-"); exit !ok }'; then
        die "$CONF must exist, be owned by root and not be group/other writable" 78
    fi
fi

load_config() {
    [ -r "$CONF" ] || die "cannot read $CONF" 78
    while IFS='=' read -r key value || [ -n "$key" ]; do
        case "$key" in ''|'#'*) continue ;; esac
        value=$(printf '%s' "$value" | sed -e 's/^"//' -e 's/"$//')
        case "$value" in *[!A-Za-z0-9_./:\ -]*) die "unsupported characters in $key" 78 ;; esac
        case "$key" in
            MANAGED_SUBNET) MANAGED_SUBNET=$value ;;
            ACTIVE_TABLE) ACTIVE_TABLE=$value ;;
            EDU_TABLE) EDU_TABLE=$value ;;
            ALLOWED_IPS) ALLOWED_IPS=$value ;;
            *) die "unknown configuration key $key" 78 ;;
        esac
    done < "$CONF"
    [ -n "$MANAGED_SUBNET" ] || die "MANAGED_SUBNET is required in $CONF" 78
    case "$ACTIVE_TABLE$EDU_TABLE" in *[!A-Za-z0-9_]*) die "table names must be alphanumeric" 78 ;; esac
    valid_cidr "$MANAGED_SUBNET" || die "MANAGED_SUBNET is not a valid IPv4 CIDR" 78
}

# --- validation ------------------------------------------------------------------------------

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

valid_ipv6() {
    case "$1" in
        *[!0-9a-fA-F:.]*|'') return 1 ;;
    esac
    [ "${#1}" -le 45 ] || return 1
    # at least two colons, no more than seven groups plus '::'
    printf '%s' "$1" | awk -F: 'NF >= 3 && NF <= 9 { exit 0 } { exit 1 }'
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

check_device_ip() {
    valid_ipv4 "$1" || die "invalid IPv4 address" 64
    in_subnet "$1" || die "address outside the managed subnet" 64
    if [ -n "$ALLOWED_IPS" ]; then
        found=0
        for known in $ALLOWED_IPS; do
            [ "$known" = "$1" ] && found=1
        done
        [ "$found" -eq 1 ] || die "address is not a known device" 64
    fi
}

# --- operations ------------------------------------------------------------------------------

op_health() {
    "$PFCTL" -t "$ACTIVE_TABLE" -T show >/dev/null 2>&1 || die "table $ACTIVE_TABLE is not available" 69
    "$PFCTL" -t "$EDU_TABLE" -T show >/dev/null 2>&1 || die "table $EDU_TABLE is not available" 69
    echo ok
}

op_show_active() {
    "$PFCTL" -t "$ACTIVE_TABLE" -T show | awk 'NF { print $1 }'
}

op_add_active() {
    check_device_ip "$1"
    "$PFCTL" -t "$ACTIVE_TABLE" -T add "$1" >/dev/null
    logger -t screenctl "add-active $1" 2>/dev/null || true
}

op_del_active() {
    check_device_ip "$1"
    "$PFCTL" -t "$ACTIVE_TABLE" -T delete "$1" >/dev/null
    logger -t screenctl "del-active $1" 2>/dev/null || true
}

op_kill_states() {
    check_device_ip "$1"
    # States opened by the device, and (less commonly) states aimed at it.
    "$PFCTL" -k "$1" >/dev/null 2>&1 || true
    "$PFCTL" -k 0.0.0.0/0 -k "$1" >/dev/null 2>&1 || true
    logger -t screenctl "kill-states $1" 2>/dev/null || true
}

op_replace_edu() {
    [ "$1" = "-" ] || die "replace-edu reads addresses from stdin: replace-edu -" 64
    tmp=$(mktemp -t screenctl.XXXXXX) || die "cannot create temporary file" 73
    trap 'rm -f "$tmp"' EXIT HUP INT TERM
    count=0
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        if valid_ipv4 "$line" || valid_ipv6 "$line"; then
            printf '%s\n' "$line" >> "$tmp"
            count=$((count + 1))
            [ "$count" -le "$MAX_EDU_ENTRIES" ] || die "too many addresses (limit $MAX_EDU_ENTRIES)" 64
        else
            die "rejected non-address input" 64
        fi
    done
    if [ "$count" -eq 0 ]; then
        "$PFCTL" -t "$EDU_TABLE" -T flush >/dev/null
    else
        "$PFCTL" -t "$EDU_TABLE" -T replace -f "$tmp" >/dev/null
    fi
    logger -t screenctl "replace-edu entries=$count" 2>/dev/null || true
}

usage() {
    echo "usage: screenctl {health|show-active|add-active IP|del-active IP|kill-states IP|replace-edu -}" >&2
    exit 64
}

# --- entry point -----------------------------------------------------------------------------

if [ "${1:-}" = "--ssh" ]; then
    # Forced-command mode: take the request from the client, but only if it is plain words.
    request=${SSH_ORIGINAL_COMMAND:-}
    [ -n "$request" ] || die "no command supplied" 64
    case "$request" in *[!A-Za-z0-9_./:\ -]*) die "unsupported characters in request" 64 ;; esac
    set -f
    # shellcheck disable=SC2086
    set -- $request
    set +f
    while [ "$#" -gt 0 ]; do
        case "$1" in
            sudo|screenctl|*/screenctl) shift ;;
            *) break ;;
        esac
    done
else
    :
fi

[ "$#" -ge 1 ] || usage
op=$1
shift

load_config

case "$op" in
    health) [ "$#" -eq 0 ] || usage; op_health ;;
    show-active) [ "$#" -eq 0 ] || usage; op_show_active ;;
    add-active) [ "$#" -eq 1 ] || usage; op_add_active "$1" ;;
    del-active) [ "$#" -eq 1 ] || usage; op_del_active "$1" ;;
    kill-states) [ "$#" -eq 1 ] || usage; op_kill_states "$1" ;;
    replace-edu) [ "$#" -eq 1 ] || usage; op_replace_edu "$1" ;;
    *) die "operation not permitted" 64 ;;
esac
