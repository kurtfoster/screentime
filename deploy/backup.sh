#!/usr/bin/env bash
# Consistent backup of the Screen-Time Controller: SQLite database (WAL-safe, via the SQLite
# online-backup API), configuration YAML and application secrets, in one 0600 tarball.
#
#   deploy/backup.sh [--prefix DIR] [--dest DIR] [--keep N] [--python PATH] [--allow-unmounted]
#
# The destination (default /mnt/screentime-backup) must be a mounted filesystem, normally a
# USB drive: a backup on the same SD card as the database dies with it, and silently filling
# the SD card would take the service down. --allow-unmounted lifts that check (development).
# Every run records its outcome in <data>/backup-status.json for the diagnostics page.
#
# The pfSense runtime tables are NOT backed up: they are rebuilt from the database.
# The SSH private key is deliberately excluded; on a rebuilt Pi generate a new key and
# authorise it on pfSense (see OPERATIONS.md).

set -euo pipefail
umask 077

PREFIX=${SCREENTIME_PREFIX:-/opt/screentime}
DEST=""
KEEP=14
PYTHON=""
ALLOW_UNMOUNTED=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift 2 ;;
        --dest) DEST=$2; shift 2 ;;
        --keep) KEEP=$2; shift 2 ;;
        --python) PYTHON=$2; shift 2 ;;
        --allow-unmounted) ALLOW_UNMOUNTED=1; shift ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 64 ;;
    esac
done

DEST=${DEST:-/mnt/screentime-backup}
PYTHON=${PYTHON:-$PREFIX/venv/bin/python}
DATA_DIR=$PREFIX/data
CONFIG_DIR=$PREFIX/config
DB=$DATA_DIR/screentime.db
STATUS_FILE=$DATA_DIR/backup-status.json
FAILURE="backup failed"
ARCHIVE=""

# Record the outcome (keeping the time of the last success) for the diagnostics page.
record_status() {  # exit code of the script
    local code=$1
    [ -d "$DATA_DIR" ] && [ -x "$PYTHON" ] || exit "$code"
    local result=ok detail=$ARCHIVE
    if [ "$code" -ne 0 ]; then
        result=failed
        detail=$FAILURE
    fi
    "$PYTHON" - "$STATUS_FILE" "$result" "$detail" <<'PY' || true
import json, os, sys
from datetime import datetime, timezone
path, result, detail = sys.argv[1:4]
try:
    with open(path) as handle:
        previous = json.load(handle)
except (OSError, ValueError):
    previous = {}
now = datetime.now(timezone.utc).isoformat(timespec="seconds")
status = {
    "result": result,
    "at": now,
    "detail": detail,
    "last_success_at": now if result == "ok" else previous.get("last_success_at"),
}
tmp = path + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump(status, handle)
os.replace(tmp, path)
PY
    exit "$code"
}

fail() {
    FAILURE=$1
    echo "backup: $1" >&2
    exit "${2:-1}"
}

# The database path may be overridden in config.yaml; honour it when present.
if [ -x "$PYTHON" ] && [ -r "$CONFIG_DIR/config.yaml" ]; then
    configured=$("$PYTHON" - "$CONFIG_DIR/config.yaml" <<'PY' 2>/dev/null || true
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1])) or {}
st = cfg.get("storage") or {}
path = st.get("database_path") or (str(st["data_dir"]).rstrip("/") + "/screentime.db" if st.get("data_dir") else "")
print(path)
PY
)
    [ -z "$configured" ] || DB=$configured
fi

[ "$KEEP" -ge 1 ] 2>/dev/null || { echo "backup: --keep must be a positive number" >&2; exit 64; }
trap 'record_status $?' EXIT
[ -r "$DB" ] || fail "database not found at $DB"
if [ "$ALLOW_UNMOUNTED" -eq 0 ] && ! mountpoint -q "$DEST" 2>/dev/null; then
    fail "$DEST is not a mounted drive (is the USB drive plugged in and listed in /etc/fstab?); refusing to write the backup to the SD card"
fi

mkdir -p "$DEST"
chmod 0700 "$DEST"
STAMP=$(date +%Y%m%d-%H%M%S)
WORK=$(mktemp -d "$DEST/.work.XXXXXX") || fail "cannot write to $DEST"
trap 'code=$?; rm -rf "$WORK"; record_status "$code"' EXIT

mkdir -p "$WORK/screentime-backup/data" "$WORK/screentime-backup/config"

# Online backup: safe while the service is running and the database is in WAL mode.
"$PYTHON" - "$DB" "$WORK/screentime-backup/data/screentime.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=30)
dst = sqlite3.connect(sys.argv[2])
with dst:
    src.backup(dst)
result = dst.execute("PRAGMA integrity_check").fetchone()[0]
src.close(); dst.close()
if result != "ok":
    sys.exit(f"integrity check failed on the backup copy: {result}")
PY

for f in config.yaml users.yaml; do
    [ -e "$CONFIG_DIR/$f" ] && cp -p "$CONFIG_DIR/$f" "$WORK/screentime-backup/config/$f"
done
for f in secret.key vapid_private.pem; do
    [ -e "$DATA_DIR/$f" ] && cp -p "$DATA_DIR/$f" "$WORK/screentime-backup/data/$f"
done
cat > "$WORK/screentime-backup/MANIFEST" <<EOF
created=$STAMP
host=$(hostname)
version=$(cat "$PREFIX/app/VERSION" 2>/dev/null || echo unknown)
database=$DB
EOF

FAILURE="could not write the archive to $DEST (drive full or read-only?)"
ARCHIVE="$DEST/screentime-$STAMP.tar.gz"
tar -C "$WORK" -czf "$ARCHIVE" screentime-backup
chmod 0600 "$ARCHIVE"
echo "backup: wrote $ARCHIVE"

# Retention: keep the newest $KEEP archives.
# shellcheck disable=SC2012
ls -1t "$DEST"/screentime-*.tar.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | while IFS= read -r old; do
    rm -f -- "$old"
    echo "backup: removed old $old"
done
