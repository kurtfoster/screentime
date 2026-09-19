#!/usr/bin/env bash
# Screen-Time Controller installer for Raspberry Pi OS (Debian Trixie or newer).
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
  --wheelhouse DIR     install Python dependencies offline from DIR
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

APP_DIR="$PREFIX/app"
CONFIG_DIR="$PREFIX/config"
DATA_DIR="$PREFIX/data"
BACKUP_DIR="$PREFIX/backups"
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

# --- prerequisites ---------------------------------------------------------------------------

check_python() {
    command -v "$PYTHON" >/dev/null 2>&1 || die "$PYTHON not found. Install it: sudo apt install python3 python3-venv"
    "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' ||
        die "Python 3.12 or newer is required (found $("$PYTHON" -V 2>&1)). Raspberry Pi OS Trixie (Debian 13) ships 3.13; Bookworm ships 3.11 and must be upgraded first."
    "$PYTHON" -c 'import venv, ensurepip' 2>/dev/null || die "python3-venv is missing: sudo apt install python3-venv"
}

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
run install -d -m 0700 "$DATA_DIR" "$SSH_DIR" "$BACKUP_DIR"
if [ "$NO_SYSTEM" -eq 0 ]; then
    run chown "$OWNER" "$PREFIX" "$CONFIG_DIR" "$DATA_DIR" "$SSH_DIR" "$BACKUP_DIR"
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
    [ "$NO_SYSTEM" -eq 1 ] || chown -R root:root "$APP_DIR"
fi

# --- python environment ----------------------------------------------------------------------

if [ "$SKIP_VENV" -eq 0 ]; then
    log "Creating the Python environment ($VENV)"
    [ -x "$VENV/bin/python" ] || run "$PYTHON" -m venv "$VENV"
    run "$VENV/bin/pip" install --quiet --upgrade pip
    if [ -n "$WHEELHOUSE" ]; then
        run "$VENV/bin/pip" install --quiet --no-index --find-links "$WHEELHOUSE" "$APP_DIR"
    else
        run "$VENV/bin/pip" install --quiet "$APP_DIR"
    fi
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

# --- systemd ---------------------------------------------------------------------------------

if [ "$NO_SYSTEMD" -eq 0 ]; then
    log "Installing systemd units"
    for unit in screentime.service screentime-backup.service screentime-backup.timer; do
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "[dry-run] install $unit"
        else
            sed -e "s|/opt/screentime|$PREFIX|g" "$APP_DIR/deploy/$unit" > "/etc/systemd/system/$unit"
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
  2. Create logins: $VENV/bin/python $APP_DIR/scripts/make_password_hash.py  (one hash per user)
     and paste them into $CONFIG_DIR/users.yaml.
  3. Validate:  cd $APP_DIR && sudo -u $SERVICE_USER env SCREENTIME_CONFIG=$CONFIG_DIR/config.yaml SCREENTIME_USERS=$CONFIG_DIR/users.yaml $VENV/bin/python -m app --check-config
  4. Install http://$HOSTNAME_FQDN/ca.crt on each iPhone/iPad (see README) and add a pfSense
     DNS host override for $HOSTNAME_FQDN pointing at this Pi.
EOF
