#!/usr/bin/env bash
# Screen-Time Controller installer for Raspberry Pi OS (Debian Trixie or newer).
# On a Raspberry Pi 1 or Zero (armv6l) use Raspberry Pi OS Lite (32-bit); dependencies then
# come from Raspberry Pi OS packages (deploy/apt-packages.txt), not PyPI.
#
#   sudo deploy/install.sh                 # install or upgrade in place
#   sudo deploy/install.sh --renew-tls     # reissue the server certificate
#   deploy/install.sh --help
#
# Idempotent: safe to re-run for upgrades. It never overwrites config.yaml or users.yaml
# unless you pass --overwrite-config and confirm.

set -euo pipefail

PREFIX=/opt/screentime
SERVICE_USER=screentime
HOSTNAME_FQDN=screen.home.arpa
TLS_DIR=/etc/screentime/tls
PYTHON=python3
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHEELHOUSE=""
DEPS=""
NTP_SERVER=192.168.12.1
BACKUP_DEST=/mnt/screentime-backup
BOOT_CONFIG=/boot/firmware/config.txt
BOOT_CONFIG_EXPLICIT=0
REBOOT_NEEDED=0
DRY_RUN=0
ASSUME_YES=0
NO_SYSTEM=0
NO_TLS=0
NO_NGINX=0
NO_SYSTEMD=0
SKIP_VENV=0
OVERWRITE_CONFIG=0
RENEW_TLS=0
EXTRA_SAN=""
TLS_DIR_EXPLICIT=0

usage() {
    cat <<EOF
Usage: install.sh [options]

  --prefix DIR         install root (default $PREFIX)
  --user NAME          service account (default $SERVICE_USER)
  --hostname FQDN      name clients use (default $HOSTNAME_FQDN)
  --extra-san IP       add an IP address to the server certificate (e.g. the Pi's LAN address)
  --tls-dir DIR        where CA and server certificate live (default $TLS_DIR)
  --python PATH        python interpreter to build the venv with (default $PYTHON)
  --deps apt|pip       where Python libraries come from (default: apt on armv6l, else pip).
                       apt: Raspberry Pi OS packages, venv with --system-site-packages
  --wheelhouse DIR     pip: install dependencies offline from DIR; apt: add these wheels
                       on top (fallback for a package with no ARMv6-safe build)
  --ntp-server ADDR    first NTP server for systemd-timesyncd (default $NTP_SERVER, pfSense)
  --backup-dest DIR    mounted USB drive for nightly backups (default $BACKUP_DEST)
  --boot-config FILE   Raspberry Pi firmware config (default $BOOT_CONFIG)
  --no-tls             do not generate certificates (you will supply them)
  --no-nginx           do not configure nginx
  --no-systemd         do not install systemd units
  --no-system          install files only: no user creation, no /etc, no nginx, no systemd
  --renew-tls          reissue the server certificate even if it is not near expiry
  --overwrite-config   replace config.yaml/users.yaml with the examples (asks first)
  --yes                answer yes to confirmations
  --dry-run            print what would be done
  -h, --help           this text
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift 2 ;;
        --user) SERVICE_USER=$2; shift 2 ;;
        --hostname) HOSTNAME_FQDN=$2; shift 2 ;;
        --extra-san) EXTRA_SAN=$2; shift 2 ;;
        --tls-dir) TLS_DIR=$2; TLS_DIR_EXPLICIT=1; shift 2 ;;
        --python) PYTHON=$2; shift 2 ;;
        --wheelhouse) WHEELHOUSE=$2; shift 2 ;;
        --deps) DEPS=$2; shift 2 ;;
        --ntp-server) NTP_SERVER=$2; shift 2 ;;
        --backup-dest) BACKUP_DEST=$2; shift 2 ;;
        --boot-config) BOOT_CONFIG=$2; BOOT_CONFIG_EXPLICIT=1; shift 2 ;;
        --no-tls) NO_TLS=1; shift ;;
        --no-nginx) NO_NGINX=1; shift ;;
        --no-systemd) NO_SYSTEMD=1; shift ;;
        --no-system) NO_SYSTEM=1; NO_NGINX=1; NO_SYSTEMD=1; shift ;;
        --skip-venv) SKIP_VENV=1; shift ;;   # used by the test-suite
        --renew-tls) RENEW_TLS=1; shift ;;
        --overwrite-config) OVERWRITE_CONFIG=1; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 64 ;;
    esac
done

case "$DEPS" in
    ""|apt|pip) ;;
    *) echo "--deps must be apt or pip" >&2; exit 64 ;;
esac

APP_DIR="$PREFIX/app"
CONFIG_DIR="$PREFIX/config"
DATA_DIR="$PREFIX/data"
SSH_DIR="$PREFIX/.ssh"
VENV="$PREFIX/venv"

log() { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ "$DRY_RUN" -eq 1 ] && return 0
    local reply
    read -r -p "$1 [y/N] " reply
    [ "$reply" = "y" ] || [ "$reply" = "Y" ]
}

if [ "$NO_SYSTEM" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "run as root (sudo), or use --no-system to install files only"
fi

# --- platform --------------------------------------------------------------------------------

MACHINE=$(uname -m)
if [ -z "$DEPS" ]; then
    # ARMv6 (Pi 1, Zero): PyPI/piwheels builds of compiled packages may use ARMv7 instructions
    # and die with "Illegal instruction"; Raspberry Pi OS builds its packages for ARMv6.
    if [ "$MACHINE" = armv6l ]; then DEPS=apt; else DEPS=pip; fi
fi
log "Machine $MACHINE; Python libraries from: $DEPS"
APT_PACKAGES=$(grep -Ev '^[[:space:]]*(#|$)' "$SOURCE_DIR/deploy/apt-packages.txt" | tr '\n' ' ')

# --- prerequisites ---------------------------------------------------------------------------

install_apt_packages() {
    if [ "$NO_SYSTEM" -eq 1 ]; then
        log "--no-system: not installing packages; the apt set is: sudo apt install $APT_PACKAGES"
        return
    fi
    log "Installing Raspberry Pi OS packages (deploy/apt-packages.txt)"
    run apt-get install -y --no-install-recommends $APT_PACKAGES
}

check_python() {
    command -v "$PYTHON" >/dev/null 2>&1 || die "$PYTHON not found. Install it: sudo apt install python3 python3-venv"
    "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' ||
        die "Python 3.12 or newer is required (found $("$PYTHON" -V 2>&1)). Use Raspberry Pi OS Trixie (Debian 13, Python 3.13): the Lite (32-bit) image on a Raspberry Pi 1 or Zero, 32- or 64-bit on later models. Bookworm ships 3.11 and must be upgraded first."
    "$PYTHON" -c 'import venv, ensurepip' 2>/dev/null || die "python3-venv is missing: sudo apt install python3-venv"
}

if [ "$DEPS" = apt ] && [ "$SKIP_VENV" -eq 0 ]; then
    install_apt_packages
fi
[ "$SKIP_VENV" -eq 1 ] || check_python
if [ "$NO_TLS" -eq 0 ] && [ "$NO_SYSTEM" -eq 0 ]; then
    command -v openssl >/dev/null 2>&1 || die "openssl is required to generate certificates: sudo apt install openssl"
fi

# --- account and directories -----------------------------------------------------------------

log "Preparing $PREFIX"
if [ "$NO_SYSTEM" -eq 0 ]; then
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        run useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin --no-create-home "$SERVICE_USER"
    fi
    OWNER="$SERVICE_USER:$SERVICE_USER"
else
    OWNER="$(id -un):$(id -gn)"
fi

run install -d -m 0755 "$PREFIX" "$APP_DIR"
run install -d -m 0750 "$CONFIG_DIR"
run install -d -m 0700 "$DATA_DIR" "$SSH_DIR"
if [ "$NO_SYSTEM" -eq 0 ]; then
    run chown "$OWNER" "$PREFIX" "$CONFIG_DIR" "$DATA_DIR" "$SSH_DIR"
fi

# --- application files -----------------------------------------------------------------------

log "Installing application files from $SOURCE_DIR"
if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] replace $APP_DIR/{app,migrations,scripts,deploy} and copy metadata"
else
    for d in app migrations scripts deploy; do
        rm -rf "${APP_DIR:?}/$d"
    done
    (cd "$SOURCE_DIR" && tar cf - \
        --exclude='__pycache__' --exclude='*.pyc' \
        app migrations scripts deploy alembic.ini pyproject.toml VERSION README.md OPERATIONS.md SECURITY.md \
        config/config.example.yaml config/users.example.yaml config/config.dev.yaml) | (cd "$APP_DIR" && tar xf -)
    chmod 0755 "$APP_DIR"/deploy/*.sh "$APP_DIR"/scripts/*.py 2>/dev/null || true
    # Precompile once, as root: the service runs with a read-only app directory and
    # PYTHONDONTWRITEBYTECODE=1, so otherwise every start recompiles every module (slow on a Pi 1).
    "$PYTHON" -m compileall -q "$APP_DIR/app" "$APP_DIR/migrations" "$APP_DIR/scripts" >/dev/null ||
        warn "could not precompile the application; it will still run, just start more slowly"
    [ "$NO_SYSTEM" -eq 1 ] || chown -R root:root "$APP_DIR"
fi

# --- python environment ----------------------------------------------------------------------

make_venv() {
    if [ "$DEPS" = apt ]; then
        # Use the Raspberry Pi OS packages. A venv from an earlier pip install would shadow
        # them, so rebuild it unless it already sees the system packages.
        if [ ! -x "$VENV/bin/python" ] || ! grep -q '^include-system-site-packages = true' "$VENV/pyvenv.cfg" 2>/dev/null; then
            run "$PYTHON" -m venv --clear --system-site-packages "$VENV"
        fi
        if [ -n "$WHEELHOUSE" ]; then
            log "Adding wheels from $WHEELHOUSE on top of the Raspberry Pi OS packages"
            run bash -c "'$VENV/bin/pip' install --quiet --no-index --no-deps '$WHEELHOUSE'/*.whl"
        fi
        return
    fi
    [ -x "$VENV/bin/python" ] || run "$PYTHON" -m venv "$VENV"
    run "$VENV/bin/pip" install --quiet --upgrade pip
    if [ -n "$WHEELHOUSE" ]; then
        run "$VENV/bin/pip" install --quiet --no-index --find-links "$WHEELHOUSE" "$APP_DIR"
    else
        run "$VENV/bin/pip" install --quiet "$APP_DIR"
    fi
}

smoke_test() {
    [ "$DRY_RUN" -eq 1 ] && { echo "[dry-run] $VENV/bin/python $APP_DIR/scripts/smoke_test.py"; return; }
    log "Checking every library imports and runs on this CPU (smoke test)"
    local rc=0
    (cd "$APP_DIR" && "$VENV/bin/python" scripts/smoke_test.py) || rc=$?
    case "$rc" in
        0) ;;
        132) die "a library died with 'Illegal instruction': it was built for a newer ARM CPU. The last line above names it. Nothing in systemd was changed; see OPERATIONS.md (risk R1 fallbacks)." ;;
        *) die "the smoke test failed (exit $rc); nothing in systemd was changed. Fix the problem above and re-run." ;;
    esac
}

if [ "$SKIP_VENV" -eq 0 ]; then
    log "Creating the Python environment ($VENV)"
    make_venv
    smoke_test
fi

# --- configuration (never overwritten silently) ------------------------------------------------

install_config_file() {  # name example mode
    local target="$CONFIG_DIR/$1" example="$APP_DIR/config/$2" mode=$3
    if [ -e "$target" ]; then
        if [ "$OVERWRITE_CONFIG" -eq 1 ] && confirm "Replace existing $target with the example?"; then
            run cp -f "$target" "$target.bak.$(date +%Y%m%d%H%M%S)"
            run install -m "$mode" "$example" "$target"
            log "Replaced $target (backup kept)"
        else
            log "Keeping existing $target"
        fi
    else
        run install -m "$mode" "$example" "$target"
        log "Created $target from the example: edit it before starting"
    fi
}

install_config_file config.yaml config.example.yaml 0640
if [ ! -e "$CONFIG_DIR/users.yaml" ] || [ "$OVERWRITE_CONFIG" -eq 1 ]; then
    install_config_file users.yaml users.example.yaml 0600
else
    log "Keeping existing $CONFIG_DIR/users.yaml"
fi
if [ "$NO_SYSTEM" -eq 0 ]; then
    run chown "$OWNER" "$CONFIG_DIR"/*.yaml
    run chmod 0600 "$CONFIG_DIR/users.yaml"
fi

# --- TLS: a private CA plus a server certificate for the LAN name -----------------------------

make_tls() {
    local ca_key="$TLS_DIR/ca.key" ca_crt="$TLS_DIR/ca.crt" key="$TLS_DIR/screen.key" crt="$TLS_DIR/screen.crt"
    run install -d -m 0755 "$TLS_DIR"
    if [ ! -e "$ca_key" ]; then
        # Name-constrained to home.arpa: even if this CA key were stolen it could not be used to
        # impersonate any public website to a device that trusts it.
        log "Creating the private certificate authority (install ca.crt on the kids' devices once)"
        run openssl ecparam -name prime256v1 -genkey -noout -out "$ca_key"
        run chmod 0600 "$ca_key"
        run openssl req -x509 -new -key "$ca_key" -sha256 -days 3650 \
            -subj "/CN=Screen Time Local CA" \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "nameConstraints=critical,permitted;DNS:home.arpa" \
            -out "$ca_crt"
        run chmod 0644 "$ca_crt"
    fi
    if [ "$RENEW_TLS" -eq 1 ] || [ ! -e "$crt" ] || ! openssl x509 -checkend $((30 * 86400)) -noout -in "$crt" >/dev/null 2>&1; then
        log "Issuing the server certificate for $HOSTNAME_FQDN"
        local san="DNS:$HOSTNAME_FQDN"
        [ -z "$EXTRA_SAN" ] || san="$san,IP:$EXTRA_SAN"
        local ext
        ext=$(mktemp)
        printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$san" > "$ext"
        run openssl ecparam -name prime256v1 -genkey -noout -out "$key"
        run chmod 0600 "$key"
        # Apple limits server certificates to 825 days; stay under it.
        run bash -c "openssl req -new -key '$key' -subj '/CN=$HOSTNAME_FQDN' | openssl x509 -req -CA '$ca_crt' -CAkey '$ca_key' -CAcreateserial -days 800 -sha256 -extfile '$ext' -out '$crt'"
        run bash -c "cat '$crt' '$ca_crt' > '$TLS_DIR/screen-fullchain.crt'"
        run chmod 0644 "$crt" "$TLS_DIR/screen-fullchain.crt"
        rm -f "$ext"
    else
        log "Server certificate is valid for more than 30 days; use --renew-tls to reissue"
    fi
}

if [ "$NO_TLS" -eq 0 ] && [ "$NO_SYSTEM" -eq 0 ]; then
    make_tls
elif [ "$NO_TLS" -eq 0 ] && [ "$NO_SYSTEM" -eq 1 ] && [ "$TLS_DIR_EXPLICIT" -eq 1 ]; then
    make_tls
fi

# --- nginx -----------------------------------------------------------------------------------

if [ "$NO_NGINX" -eq 0 ]; then
    if ! command -v nginx >/dev/null 2>&1; then
        warn "nginx is not installed (sudo apt install nginx); skipping the reverse proxy"
    else
        log "Configuring nginx"
        run install -d -m 0755 /etc/nginx/snippets
        run install -m 0644 "$APP_DIR/deploy/screentime-proxy.conf" /etc/nginx/snippets/screentime-proxy.conf
        run install -m 0644 "$APP_DIR/deploy/screentime-lan-only.conf" /etc/nginx/snippets/screentime-lan-only.conf
        if [ -d /etc/nginx/sites-available ]; then
            site=/etc/nginx/sites-available/screentime
            enabled=/etc/nginx/sites-enabled/screentime
        else
            site=/etc/nginx/conf.d/screentime.conf
            enabled=""
        fi
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "[dry-run] render nginx-screen.conf -> $site"
        else
            sed -e "s|@HOSTNAME@|$HOSTNAME_FQDN|g" -e "s|@TLS_DIR@|$TLS_DIR|g" \
                "$APP_DIR/deploy/nginx-screen.conf" > "$site"
            chmod 0644 "$site"
        fi
        [ -z "$enabled" ] || run ln -sfn "$site" "$enabled"
        if [ "$DRY_RUN" -eq 0 ]; then
            if nginx -t 2>/dev/null; then
                systemctl reload nginx 2>/dev/null || systemctl restart nginx
            else
                nginx -t || true
                die "nginx rejected the configuration; fix the problem above and re-run"
            fi
        fi
    fi
fi

# --- operating system: memory, clock, logs and backup drive ----------------------------------

write_file() {  # path, then lines
    local target=$1
    shift
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[dry-run] write $target"
        return
    fi
    install -d -m 0755 "$(dirname "$target")"
    printf '%s\n' "$@" > "$target"
    chmod 0644 "$target"
}

configure_gpu_mem() {
    [ "$MACHINE" = armv6l ] || return 0
    if [ ! -f "$BOOT_CONFIG" ]; then
        warn "$BOOT_CONFIG not found: add gpu_mem=16 to the firmware config by hand (frees memory for Linux)"
        return 0
    fi
    if grep -Eq '^[[:space:]]*gpu_mem=16[[:space:]]*$' "$BOOT_CONFIG"; then
        log "gpu_mem=16 is already set in $BOOT_CONFIG"
        return 0
    fi
    if grep -Eq '^[[:space:]]*gpu_mem=' "$BOOT_CONFIG"; then
        warn "$BOOT_CONFIG sets a different gpu_mem; 16 gives Linux the most memory on a headless Pi"
        return 0
    fi
    if confirm "Add gpu_mem=16 to $BOOT_CONFIG (headless, so Linux gets about 60 MB more; needs a reboot)?"; then
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "[dry-run] append gpu_mem=16 to $BOOT_CONFIG"
        else
            printf '\n# Screen-Time Controller: headless, so the GPU needs only the minimum\ngpu_mem=16\n' >> "$BOOT_CONFIG"
        fi
        REBOOT_NEEDED=1
    else
        warn "gpu_mem not changed: Linux has about 60 MB less memory than it could"
    fi
}

configure_time_sync() {
    # No RTC: the app refuses to grant anything until systemd-timesyncd has synchronised.
    log "Configuring NTP: $NTP_SERVER first, public pool servers if it does not answer"
    write_file /etc/systemd/timesyncd.conf.d/screentime.conf \
        '# Screen-Time Controller installer. pfSense first, so the clock does not depend on the' \
        '# Internet; the public servers are tried in turn if it does not answer.' \
        '[Time]' \
        "NTP=$NTP_SERVER 0.debian.pool.ntp.org 1.debian.pool.ntp.org"
    write_file /etc/systemd/system/systemd-time-wait-sync.service.d/screentime.conf \
        '# Screen-Time Controller: at boot, wait for NTP before starting the service, but for no' \
        '# more than 90 s. After that it starts anyway and grants nothing until the clock is set.' \
        '[Service]' \
        'TimeoutStartSec=90s'
    [ "$DRY_RUN" -eq 1 ] && return 0
    systemctl daemon-reload
    systemctl enable systemd-time-wait-sync.service >/dev/null 2>&1 ||
        warn "could not enable systemd-time-wait-sync.service"
    if systemctl is-enabled systemd-timesyncd >/dev/null 2>&1; then
        systemctl restart systemd-timesyncd || warn "could not restart systemd-timesyncd"
    else
        warn "systemd-timesyncd is not enabled (another NTP client?). The app waits for its marker"
        warn "file and will grant nothing until it exists: sudo systemctl enable --now systemd-timesyncd"
    fi
}

configure_journald() {
    write_file /etc/systemd/journald.conf.d/screentime.conf \
        '# Screen-Time Controller: bound the journal to spare the SD card.' \
        '[Journal]' \
        'SystemMaxUse=64M'
    [ "$DRY_RUN" -eq 1 ] || systemctl restart systemd-journald || warn "could not restart systemd-journald"
}

check_root_noatime() {
    command -v findmnt >/dev/null 2>&1 || return 0
    findmnt -no OPTIONS / 2>/dev/null | grep -q noatime ||
        warn "the root filesystem is mounted without noatime; add it to / in /etc/fstab to cut SD card writes"
}

prepare_backup_dest() {
    run install -d -m 0755 "$BACKUP_DEST"
    if mountpoint -q "$BACKUP_DEST" 2>/dev/null; then
        run chown "$OWNER" "$BACKUP_DEST"
        run chmod 0700 "$BACKUP_DEST"
        log "Nightly backups go to the drive mounted at $BACKUP_DEST"
    else
        warn "No drive is mounted at $BACKUP_DEST, so nightly backups fail (and say so on the"
        warn "diagnostics page) until one is. With the USB drive plugged in:"
        warn "  1. find its UUID:       lsblk -f"
        warn "  2. add to /etc/fstab:   UUID=<uuid>  $BACKUP_DEST  ext4  defaults,nofail,noatime,x-systemd.device-timeout=10  0  2"
        warn "  3. mount and hand over: sudo mount $BACKUP_DEST && sudo chown $SERVICE_USER: $BACKUP_DEST && sudo chmod 0700 $BACKUP_DEST"
    fi
}

if [ "$NO_SYSTEM" -eq 0 ] || [ "$BOOT_CONFIG_EXPLICIT" -eq 1 ]; then
    configure_gpu_mem
fi
if [ "$NO_SYSTEM" -eq 0 ]; then
    check_root_noatime
    prepare_backup_dest
    if [ "$NO_SYSTEMD" -eq 0 ]; then
        configure_time_sync
        configure_journald
    fi
fi

# --- systemd ---------------------------------------------------------------------------------

if [ "$NO_SYSTEMD" -eq 0 ]; then
    log "Installing systemd units"
    for unit in screentime.service screentime-backup.service screentime-backup.timer; do
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "[dry-run] install $unit"
        else
            sed -e "s|/opt/screentime|$PREFIX|g" -e "s|/mnt/screentime-backup|$BACKUP_DEST|g" \
                "$APP_DIR/deploy/$unit" > "/etc/systemd/system/$unit"
            chmod 0644 "/etc/systemd/system/$unit"
        fi
    done
    run systemctl daemon-reload
    run systemctl enable screentime.service screentime-backup.timer
    if [ "$DRY_RUN" -eq 0 ]; then
        if (cd "$APP_DIR" && SCREENTIME_CONFIG="$CONFIG_DIR/config.yaml" SCREENTIME_USERS="$CONFIG_DIR/users.yaml" \
            "$VENV/bin/python" -m app --check-config >/dev/null 2>&1); then
            systemctl restart screentime.service
            systemctl start screentime-backup.timer
            log "Service started"
        else
            warn "Configuration is not valid yet, so the service was NOT started."
            warn "Edit $CONFIG_DIR/config.yaml and $CONFIG_DIR/users.yaml, then run:"
            warn "  cd $APP_DIR && sudo -u $SERVICE_USER env SCREENTIME_CONFIG=$CONFIG_DIR/config.yaml SCREENTIME_USERS=$CONFIG_DIR/users.yaml $VENV/bin/python -m app --check-config"
            warn "  sudo systemctl start screentime.service screentime-backup.timer"
        fi
    fi
fi

cat <<EOF

Done. Next steps:
  1. Edit $CONFIG_DIR/config.yaml (devices, allowances, pfSense address).
  2. Create logins: $VENV/bin/python $APP_DIR/scripts/make_password_hash.py --config $CONFIG_DIR/config.yaml
     and paste them into $CONFIG_DIR/users.yaml.
  3. Validate:  cd $APP_DIR && sudo -u $SERVICE_USER env SCREENTIME_CONFIG=$CONFIG_DIR/config.yaml SCREENTIME_USERS=$CONFIG_DIR/users.yaml $VENV/bin/python -m app --check-config
  4. Install http://$HOSTNAME_FQDN/ca.crt on each iPhone/iPad (see README) and add a pfSense
     DNS host override for $HOSTNAME_FQDN pointing at this Pi.
EOF
if [ "$MACHINE" = armv6l ]; then
    cat <<EOF

Raspberry Pi 1 / Zero: measure this CPU's password-check cost with
  $VENV/bin/python $APP_DIR/scripts/make_password_hash.py --calibrate
and see the full resource benchmark in OPERATIONS.md.
EOF
fi
if [ "$REBOOT_NEEDED" -eq 1 ]; then
    printf '\nReboot for gpu_mem=16 to take effect:  sudo reboot\n'
fi
