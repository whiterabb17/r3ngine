#!/bin/bash
# Restore a complete r3ngine backup created by 'make backup' / full_backup.sh.
# Imports the PostgreSQL dump and extracts scan_results into the Docker volume.
#
# Environment variables (passed by Makefile):
#   POSTGRES_USER         - database user
#   POSTGRES_DB           - database name
#   DOCKER_COMPOSE_CMD    - full docker compose command with file flags
#   SCAN_RESULTS_VOLUME   - Docker volume name (default: r3ngine_scan_results)
#   BACKUP                - path to a full_* backup directory (required)
#   SKIP_CONFIRM          - set to 1 to skip interactive confirmation

set -euo pipefail

: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${DOCKER_COMPOSE_CMD:?DOCKER_COMPOSE_CMD is required}"
: "${BACKUP:?BACKUP is required - pass BACKUP=./backups/full_YYYYMMDD_HHMMSS}"

SCAN_RESULTS_VOLUME="${SCAN_RESULTS_VOLUME:-r3ngine_scan_results}"
SKIP_CONFIRM="${SKIP_CONFIRM:-0}"

# Resolve BACKUP to an absolute path early (docker bind mounts need absolute paths).
BACKUP="$(cd "$BACKUP" && pwd)"
DB_DUMP_GZ="${BACKUP}/database.sql.gz"
DB_DUMP="${BACKUP}/database.sql"
SCAN_ARCHIVE="${BACKUP}/scan_results.tar.gz"

echo ""
echo "============================================================"
echo "  r3ngine FULL RESTORE"
echo "============================================================"
echo ""

# --- Validate backup artifacts ----------------------------------------------

if [ ! -d "$BACKUP" ]; then
    echo "  ERROR: Backup directory not found: $BACKUP" >&2
    exit 1
fi

if [ -f "$DB_DUMP_GZ" ]; then
    DB_SOURCE="$DB_DUMP_GZ"
    DB_DECOMPRESS="gzip -dc"
elif [ -f "$DB_DUMP" ]; then
    DB_SOURCE="$DB_DUMP"
    DB_DECOMPRESS="cat"
else
    echo "  ERROR: No database dump found in $BACKUP" >&2
    echo "  Expected database.sql.gz or database.sql" >&2
    exit 1
fi

if [ ! -f "$SCAN_ARCHIVE" ]; then
    echo "  ERROR: scan_results archive not found: $SCAN_ARCHIVE" >&2
    exit 1
fi

echo "  Backup:            $BACKUP"
echo "  Database dump:     $(basename "$DB_SOURCE") ($(du -sh "$DB_SOURCE" | cut -f1))"
echo "  scan_results:      $(basename "$SCAN_ARCHIVE") ($(du -sh "$SCAN_ARCHIVE" | cut -f1))"
echo "  Target database:   $POSTGRES_DB"
echo "  Target volume:     $SCAN_RESULTS_VOLUME"
echo ""

if [ "$SKIP_CONFIRM" != "1" ]; then
    echo "  WARNING: This will OVERWRITE the current database and"
    echo "  replace ALL contents of the scan_results volume."
    echo "  Stop any running scans before continuing."
    echo ""
    printf "  Type 'restore' to confirm: "
    read -r confirm
    if [ "$confirm" != "restore" ]; then
        echo ""
        echo "  Restore cancelled."
        echo ""
        exit 1
    fi
    echo ""
fi

# --- Preconditions -----------------------------------------------------------

if ! $DOCKER_COMPOSE_CMD exec -T db \
    pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" > /dev/null 2>&1; then
    echo "  ERROR: Database is not ready. Start the stack with 'make up' first." >&2
    exit 1
fi

if ! docker volume inspect "$SCAN_RESULTS_VOLUME" > /dev/null 2>&1; then
    echo "  ERROR: Docker volume '$SCAN_RESULTS_VOLUME' not found." >&2
    echo "  Start a new installation with 'make up' so volumes are created," >&2
    echo "  then re-run this restore." >&2
    exit 1
fi

# --- 1. Restore database -----------------------------------------------------

echo "[1/2] Restoring PostgreSQL database..."

# Terminate open sessions so DROP/CREATE statements inside a --clean dump
# can run without "database is being accessed by other users" errors.
echo "  Terminating open connections to '$POSTGRES_DB'..."
$DOCKER_COMPOSE_CMD exec -T db psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${POSTGRES_DB}' AND pid <> pg_backend_pid();" \
    > /dev/null

echo "  Importing dump (this may take a while)..."
if ! $DB_DECOMPRESS "$DB_SOURCE" | \
    $DOCKER_COMPOSE_CMD exec -T db \
      psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 \
      > /dev/null; then
    echo "  ERROR: Database restore failed." >&2
    exit 1
fi

SCAN_COUNT=$($DOCKER_COMPOSE_CMD exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -t -c 'SELECT COUNT(*) FROM "startScan_scanhistory";' 2>/dev/null | \
    tr -d '[:space:]' || echo "unknown")
echo "  Database restored. Scan history rows: ${SCAN_COUNT}"

# --- 2. Restore scan_results -------------------------------------------------

echo ""
echo "[2/2] Restoring scan_results volume..."

# Clear volume contents, then extract the archive. Bind-mount the backup dir
# read-only so we never mutate the backup itself.
if ! docker run --rm \
    -v "${SCAN_RESULTS_VOLUME}:/data" \
    -v "${BACKUP}:/backup:ro" \
    alpine:latest \
    sh -c 'rm -rf /data/..?* /data/.[!.]* /data/* 2>/dev/null; tar xzf /backup/scan_results.tar.gz -C /data'; then
    echo "  ERROR: Failed to extract scan_results archive into volume." >&2
    exit 1
fi

FILE_COUNT=$(docker run --rm \
    -v "${SCAN_RESULTS_VOLUME}:/data:ro" \
    alpine:latest \
    sh -c 'find /data -type f 2>/dev/null | wc -l' | tr -d '[:space:]')
echo "  scan_results restored. Files in volume: ${FILE_COUNT}"

echo ""
echo "============================================================"
echo "  Restore complete."
echo ""
echo "  Next steps for a new installation:"
echo "    1. Ensure services are running:  make up"
echo "    2. Apply any newer migrations:   make migrate"
echo "    3. Open the UI and verify scans/results look correct"
echo "============================================================"
echo ""
