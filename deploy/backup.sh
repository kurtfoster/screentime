#!/usr/bin/env bash
# Consistent backup of the Screen-Time Controller: SQLite database (WAL-safe, via the SQLite
# online-backup API), configuration YAML and application secrets, in one 0600 tarball.
#
#   deploy/backup.sh [--prefix DIR] [--dest DIR] [--keep N] [--python PATH]
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

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX=$2; shift 2 ;;
        --dest) DEST=$2; shift 2 ;;
        --keep) KEEP=$2; shift 2 ;;
        --python) PYTHON=$2; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 64 ;;
    esac
done

DEST=${DEST:-$PREFIX/backups}
PYTHON=${PYTHON:-$PREFIX/venv/bin/python}
DATA_DIR=$PREFIX/data
CONFIG_DIR=$PREFIX/config
DB=$DATA_DIR/screentime.db

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

[ -r "$DB" ] || { echo "backup: database not found at $DB" >&2; exit 1; }
[ "$KEEP" -ge 1 ] 2>/dev/null || { echo "backup: --keep must be a positive number" >&2; exit 64; }

mkdir -p "$DEST"
chmod 0700 "$DEST"
STAMP=$(date +%Y%m%d-%H%M%S)
WORK=$(mktemp -d "$DEST/.work.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

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
