#!/usr/bin/env bash
# Restore a backup made by deploy/backup.sh onto this machine (typically a freshly installed Pi).
#
#   sudo deploy/restore.sh /path/to/screentime-YYYYmmdd-HHMMSS.tar.gz [--prefix DIR] [--yes] [--no-service]
#
# Run deploy/install.sh first so the account, directories and virtualenv exist. Existing
# files are kept alongside as *.pre-restore. The database is upgraded by the application
# (Alembic) on next start, so backups from an older release restore cleanly.

set -euo pipefail
umask 077

PREFIX=${SCREENTIME_PREFIX:-/opt/screentime}
ARCHIVE=""
ASSUME_YES=0
MANAGE_SERVICE=1
SERVICE_USER=screentime

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift 2 ;;
        --user) SERVICE_USER=$2; shift 2 ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --no-service) MANAGE_SERVICE=0; shift ;;
        -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
        -*) echo "unknown option: $1" >&2; exit 64 ;;
        *) ARCHIVE=$1; shift ;;
    esac
done

[ -n "$ARCHIVE" ] && [ -r "$ARCHIVE" ] || { echo "restore: give the path of a backup archive" >&2; exit 64; }
DATA_DIR=$PREFIX/data
CONFIG_DIR=$PREFIX/config
[ -d "$PREFIX" ] || { echo "restore: $PREFIX does not exist; run deploy/install.sh first" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
tar -C "$WORK" -xzf "$ARCHIVE"
SRC=$WORK/screentime-backup
[ -r "$SRC/data/screentime.db" ] || { echo "restore: archive does not contain a database" >&2; exit 1; }
cat "$SRC/MANIFEST" 2>/dev/null || true

if [ "$ASSUME_YES" -eq 0 ]; then
    read -r -p "Restore into $PREFIX (existing files are kept as .pre-restore)? [y/N] " reply
    [ "$reply" = "y" ] || [ "$reply" = "Y" ] || { echo "restore: cancelled"; exit 1; }
fi

SERVICE_WAS_ACTIVE=0
if [ "$MANAGE_SERVICE" -eq 1 ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet screentime.service; then
    SERVICE_WAS_ACTIVE=1
    systemctl stop screentime.service
fi

mkdir -p "$DATA_DIR" "$CONFIG_DIR"
place() {  # source target mode
    if [ -e "$2" ]; then mv -f "$2" "$2.pre-restore"; fi
    install -m "$3" "$1" "$2"
}
place "$SRC/data/screentime.db" "$DATA_DIR/screentime.db" 0600
rm -f "$DATA_DIR/screentime.db-wal" "$DATA_DIR/screentime.db-shm"
for f in secret.key vapid_private.pem; do
    [ -e "$SRC/data/$f" ] && place "$SRC/data/$f" "$DATA_DIR/$f" 0600
done
[ -e "$SRC/config/config.yaml" ] && place "$SRC/config/config.yaml" "$CONFIG_DIR/config.yaml" 0640
[ -e "$SRC/config/users.yaml" ] && place "$SRC/config/users.yaml" "$CONFIG_DIR/users.yaml" 0600

if [ "$(id -u)" -eq 0 ] && id "$SERVICE_USER" >/dev/null 2>&1; then
    chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$CONFIG_DIR"
fi
echo "restore: files restored into $PREFIX"

if [ "$MANAGE_SERVICE" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    if [ "$SERVICE_WAS_ACTIVE" -eq 1 ] || [ -e /etc/systemd/system/screentime.service ]; then
        systemctl start screentime.service && echo "restore: service started; pfSense tables will be rebuilt from the database"
    fi
fi
cat <<EOF
restore: next steps
  * The SSH key is not part of a backup. If this is a new Pi, create one and authorise it on
    pfSense (OPERATIONS.md, "pfSense setup").
  * Check status:  $PREFIX/venv/bin/python $PREFIX/app/scripts/admin_cli.py status
EOF
