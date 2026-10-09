#!/bin/bash
# Complete r3ngine backup: PostgreSQL dump + scan_results volume archive.
# Called by 'make backup'. Requires the db container to be running.
#
# Environment variables (passed by Makefile):
#   POSTGRES_USER         - database user
#   POSTGRES_DB           - database name
#   DOCKER_COMPOSE_CMD    - full docker compose command with file flags
#   SCAN_RESULTS_VOLUME   - Docker volume name (default: r3ngine_scan_results)
#   BACKUP_ROOT           - parent directory for backups (default: ./backups)

set -euo pipefail

: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${DOCKER_COMPOSE_CMD:?DOCKER_COMPOSE_CMD is required}"

SCAN_RESULTS_VOLUME="${SCAN_RESULTS_VOLUME:-r3ngine_scan_results}"
BACKUP_ROOT="${BACKUP_ROOT:-./backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/full_${TIMESTAMP}"
DB_DUMP="${BACKUP_DIR}/database.sql"
DB_DUMP_GZ="${DB_DUMP}.gz"
SCAN_ARCHIVE="${BACKUP_DIR}/scan_results.tar.gz"
MANIFEST="${BACKUP_DIR}/MANIFEST.txt"
ERROR_LOG="${BACKUP_DIR}/.pg_dump_err.tmp"

echo ""
echo "============================================================"
echo "  r3ngine FULL BACKUP"
echo "============================================================"
echo ""

# --- Preconditions -----------------------------------------------------------

if ! $DOCKER_COMPOSE_CMD exec -T db \
    pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" > /dev/null 2>&1; then
    echo "  ERROR: Database is not ready. Start the stack with 'make up' first." >&2
    exit 1
fi

if ! docker volume inspect "$SCAN_RESULTS_VOLUME" > /dev/null 2>&1; then
    echo "  ERROR: Docker volume '$SCAN_RESULTS_VOLUME' not found." >&2
    echo "  Is the stack running? Start with 'make up' first." >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"

# --- 1. Database dump --------------------------------------------------------

echo "[1/3] Exporting PostgreSQL database '$POSTGRES_DB'..."
if ! $DOCKER_COMPOSE_CMD exec -T db \
    pg_dump -U "$POSTGRES_USER" \
      --clean --if-exists \
      --no-owner --no-acl \
      "$POSTGRES_DB" \
    > "$DB_DUMP" \
    2> "$ERROR_LOG"; then
    echo "  ERROR: pg_dump failed." >&2
    cat "$ERROR_LOG" >&2
    rm -rf "$BACKUP_DIR"
    exit 1
fi

if [ ! -s "$DB_DUMP" ]; then
    echo "  ERROR: pg_dump produced an empty file." >&2
    cat "$ERROR_LOG" >&2
    rm -rf "$BACKUP_DIR"
    exit 1
fi
rm -f "$ERROR_LOG"

gzip -f "$DB_DUMP"
DB_SIZE=$(du -sh "$DB_DUMP_GZ" | cut -f1)
echo "  Database dump: $DB_DUMP_GZ ($DB_SIZE)"

# --- 2. scan_results archive -------------------------------------------------

echo ""
echo "[2/3] Compressing scan_results volume ('$SCAN_RESULTS_VOLUME')..."
# Archive volume contents onto the host. Use a short-lived alpine helper so we
# do not depend on tools inside the web image.
if ! docker run --rm \
    -v "${SCAN_RESULTS_VOLUME}:/data:ro" \
    -v "$(cd "$(dirname "$SCAN_ARCHIVE")" && pwd):/backup" \
    alpine:latest \
    tar czf "/backup/$(basename "$SCAN_ARCHIVE")" -C /data .; then
    echo "  ERROR: Failed to archive scan_results volume." >&2
    rm -rf "$BACKUP_DIR"
    exit 1
fi

if [ ! -s "$SCAN_ARCHIVE" ]; then
    echo "  ERROR: scan_results archive is empty." >&2
    rm -rf "$BACKUP_DIR"
    exit 1
fi

SCAN_SIZE=$(du -sh "$SCAN_ARCHIVE" | cut -f1)
FILE_COUNT=$(docker run --rm \
    -v "${SCAN_RESULTS_VOLUME}:/data:ro" \
    alpine:latest \
    sh -c 'find /data -type f 2>/dev/null | wc -l' | tr -d '[:space:]')
echo "  scan_results archive: $SCAN_ARCHIVE ($SCAN_SIZE, ${FILE_COUNT} files)"

# --- 3. Manifest -------------------------------------------------------------

echo ""
echo "[3/3] Writing manifest..."
{
    echo "r3ngine full backup"
    echo "created_at=${TIMESTAMP}"
    echo "postgres_db=${POSTGRES_DB}"
    echo "postgres_user=${POSTGRES_USER}"
    echo "scan_results_volume=${SCAN_RESULTS_VOLUME}"
    echo "database_dump=$(basename "$DB_DUMP_GZ")"
    echo "database_size=${DB_SIZE}"
    echo "scan_results_archive=$(basename "$SCAN_ARCHIVE")"
    echo "scan_results_size=${SCAN_SIZE}"
    echo "scan_results_files=${FILE_COUNT}"
} > "$MANIFEST"

TOTAL_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)

echo ""
echo "============================================================"
echo "  Backup complete."
echo "  Location:  $BACKUP_DIR"
echo "  Size:      $TOTAL_SIZE"
echo ""
echo "  Contents:"
echo "    - $(basename "$DB_DUMP_GZ")   (PostgreSQL dump)"
echo "    - $(basename "$SCAN_ARCHIVE")  (scan_results volume)"
echo "    - $(basename "$MANIFEST")"
echo ""
echo "  Restore on this or another install with:"
echo "    make restore BACKUP=$BACKUP_DIR"
echo "============================================================"
echo ""
