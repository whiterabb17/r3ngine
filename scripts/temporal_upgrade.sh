#!/bin/bash
# Step an existing r3ngine Temporal database through every server minor release
# up to the one docker/docker-compose.yml runs.
#
# Temporal supports upgrading one minor version at a time only: each release
# expects the schema of its own version and may migrate data when it starts.
# This script applies the schema of each intermediate release with
# temporal-sql-tool and runs that release's server against the database until
# it reports healthy, then moves on. It also converts the visibility store from
# "standard" visibility (the DB=postgresql setting temporalio/auto-setup used
# up to r3ngine 3.7.6), which Temporal removed in 1.24, to the SQL advanced
# visibility store (postgres12 plugin).
#
# See documents/upgrading-infrastructure.md for the full procedure.
#
# Preconditions:
#   - the db service is running; temporal, temporal-python-orchestrator and
#     temporal-go-executor are stopped (no scan is in progress)
#   - `make temporal-upgrade` runs it; the database credentials are read from
#     the db container unless POSTGRES_USER / POSTGRES_PASSWORD are set
#
# Optional environment:
#   COMPOSE_PROJECT_NAME  compose project (default r3ngine)
#   DB_CONTAINER          postgres container (default <project>-db-1)
#   NETWORK               compose network (default <project>_r3ngine_network)
#   IMAGE_PREFIX          registry prefix for the temporalio images, e.g. mirror.gcr.io/
#   BACKUP_DIR            where the pre-upgrade dumps go (default ./backups)
#   HOP_SETTLE_SECONDS    how long each intermediate server runs once healthy (default 30)
#   RESUME_AT             release to restart from after a failed hop (e.g. 1.27.4)

set -euo pipefail
# The dumps hold workflow payloads (scan targets and arguments).
umask 077

PROJECT="${COMPOSE_PROJECT_NAME:-r3ngine}"
DB_CONTAINER="${DB_CONTAINER:-${PROJECT}-db-1}"
NETWORK="${NETWORK:-${PROJECT}_r3ngine_network}"
IMAGE_PREFIX="${IMAGE_PREFIX:-}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
HOP_SETTLE_SECONDS="${HOP_SETTLE_SECONDS:-30}"
RESUME_AT="${RESUME_AT:-}"
DB_HOST=db
DYNAMIC_CONFIG_DIR="$(cd "$(dirname "$0")/../docker/temporal/dynamicconfig" && pwd)"

# The last release in this table must match the temporal image in docker-compose.yml.
# release | temporal schema | visibility schema (postgresql/v12)
HOPS="
1.23.1 1.11 1.4
1.24.3 1.12 1.6
1.25.2 1.14 1.6
1.26.3 1.14 1.7
1.27.4 1.16 1.9
1.28.4 1.17 1.9
1.29.7 1.18 1.9
1.30.7 1.18 1.13
1.31.3 1.19 1.14
"
TARGET="$(echo "$HOPS" | awk 'NF { last = $1 } END { print last }')"
ADMIN_TOOLS="${IMAGE_PREFIX}temporalio/admin-tools:${TARGET}"
SCHEMA_ROOT=/etc/temporal/schema/postgresql/v12
HOP_CONTAINER="${PROJECT}-temporal-upgrade"

die() { echo "ERROR: $*" >&2; exit 1; }

psql_q() {
    docker exec "$DB_CONTAINER" psql -U "$POSTGRES_USER" -d "$1" -tAc "$2"
}

# "1.9" < "1.10": compare dotted versions numerically.
version_gt() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

# temporal-sql-tool logs every statement; keep that in a file and show it on failure.
sql_tool() {
    if ! docker run --rm --network "$NETWORK" -e SQL_PASSWORD "$ADMIN_TOOLS" \
        temporal-sql-tool --plugin postgres12 --ep "$DB_HOST" -p 5432 -u "$POSTGRES_USER" "$@" >>"$LOG" 2>&1; then
        tail -n 20 "$LOG" >&2
        die "temporal-sql-tool $* failed (full log: $LOG)"
    fi
}

update_schema() {  # <database> <temporal|visibility> <version>
    echo "  - $1 schema -> $3"
    sql_tool --db "$1" update-schema -d "$SCHEMA_ROOT/$2/versioned" -v "$3"
}

# Run one server release until it is healthy and can read the default namespace.
run_server() {  # <release> <DB plugin>
    local release="$1" plugin="$2" i
    echo "  - starting temporalio/server:$release (DB=$plugin)"
    docker rm -f "$HOP_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$HOP_CONTAINER" --network "$NETWORK" \
        -e DB="$plugin" -e DB_PORT=5432 -e POSTGRES_SEEDS="$DB_HOST" \
        -e POSTGRES_USER="$POSTGRES_USER" -e POSTGRES_PWD \
        -v "$DYNAMIC_CONFIG_DIR:/etc/temporal/config/dynamicconfig:ro" \
        "${IMAGE_PREFIX}temporalio/server:$release" >/dev/null
    for i in $(seq 1 60); do
        if docker run --rm --network "$NETWORK" "$ADMIN_TOOLS" \
            temporal operator namespace describe -n default --address "$HOP_CONTAINER:7233" >/dev/null 2>&1; then
            echo "  - $release healthy; letting it settle for ${HOP_SETTLE_SECONDS}s"
            sleep "$HOP_SETTLE_SECONDS"
            docker stop -t 30 "$HOP_CONTAINER" >/dev/null
            docker rm "$HOP_CONTAINER" >/dev/null
            return 0
        fi
        if [ "$(docker inspect -f '{{.State.Running}}' "$HOP_CONTAINER")" != true ]; then
            break
        fi
        sleep 3
    done
    docker logs --tail 40 "$HOP_CONTAINER" >&2 || true
    docker rm -f "$HOP_CONTAINER" >/dev/null 2>&1 || true
    die "temporalio/server:$release did not become healthy. The database has the schema of $release: fix the cause and re-run with RESUME_AT=$release, or restore the dumps in $BACKUP_DIR."
}

migrate_standard_visibility() {
    local rows="$BACKUP_DIR/temporal_visibility_standard_rows_${STAMP}.sql"
    echo "==> Converting standard visibility to the SQL advanced visibility store"
    # Only the columns both schemas share are dumped, so the rows load into the new table:
    # the Temporal UI keeps listing past executions and running ones stay visible.
    docker exec "$DB_CONTAINER" pg_dump -U "$POSTGRES_USER" -d temporal_visibility \
        --data-only --column-inserts --table=executions_visibility > "$rows"
    echo "  - saved $(grep -c '^INSERT' "$rows" || true) visibility rows to $rows"
    psql_q postgres "DROP DATABASE temporal_visibility" >/dev/null
    sql_tool --db temporal_visibility create
    sql_tool --db temporal_visibility setup-schema -v 0.0
    update_schema temporal_visibility visibility 1.4
    docker exec -i "$DB_CONTAINER" psql -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d temporal_visibility < "$rows" >/dev/null
    echo "  - reloaded $(psql_q temporal_visibility 'SELECT count(*) FROM executions_visibility') rows"
}

[ "$(docker inspect -f '{{.State.Running}}' "$DB_CONTAINER" 2>/dev/null)" = true ] \
    || die "container $DB_CONTAINER is not running (start it with: docker compose ... up -d db, or set DB_CONTAINER)"
POSTGRES_USER="${POSTGRES_USER:-$(docker exec "$DB_CONTAINER" printenv POSTGRES_USER)}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(docker exec "$DB_CONTAINER" printenv POSTGRES_PASSWORD)}"
# Handed to containers as `-e NAME` so the password never appears in a docker argv.
export SQL_PASSWORD="$POSTGRES_PASSWORD" POSTGRES_PWD="$POSTGRES_PASSWORD"
docker network inspect "$NETWORK" >/dev/null 2>&1 || die "network $NETWORK not found (set NETWORK)"
if [ -n "$(docker ps -q --filter "name=^${PROJECT}-temporal-1$")" ]; then
    die "stop the temporal service first: docker compose ... stop temporal temporal-python-orchestrator temporal-go-executor"
fi

if [ -z "$(psql_q postgres "SELECT 1 FROM pg_database WHERE datname = 'temporal'")" ]; then
    echo "No Temporal database yet: the temporal-schema service creates it on the next 'make up'."
    exit 0
fi
main_version="$(psql_q temporal 'SELECT curr_version FROM schema_version')"
if [ -n "$(psql_q temporal_visibility "SELECT 1 FROM information_schema.columns WHERE table_name = 'executions_visibility' AND column_name = 'search_attributes'")" ]; then
    standard_visibility=false
    vis_version="$(psql_q temporal_visibility 'SELECT curr_version FROM schema_version')"
else
    standard_visibility=true
    vis_version=0
fi
echo "Current schema: temporal=$main_version visibility=$vis_version (standard visibility: $standard_visibility); target server $TARGET"

if [ -n "$RESUME_AT" ] && ! echo "$HOPS" | awk '{ print $1 }' | grep -qx "$RESUME_AT"; then
    die "RESUME_AT=$RESUME_AT is not one of: $(echo "$HOPS" | awk 'NF { printf "%s ", $1 }')"
fi
version_gt 1.10 "$main_version" && die "schema $main_version is older than Temporal 1.22; upgrade to 1.22 first"
target_main="$(echo "$HOPS" | awk 'NF { last = $2 } END { print last }')"
target_vis="$(echo "$HOPS" | awk 'NF { last = $3 } END { print last }')"
if [ -z "$RESUME_AT" ] && ! $standard_visibility \
    && ! version_gt "$target_main" "$main_version" && ! version_gt "$target_vis" "$vis_version"; then
    echo "Already at the schema of Temporal $TARGET; nothing to do."
    exit 0
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
LOG="$BACKUP_DIR/temporal_upgrade_${STAMP}.log"
for db in temporal temporal_visibility; do
    docker exec "$DB_CONTAINER" pg_dump -U "$POSTGRES_USER" -Fc "$db" > "$BACKUP_DIR/${db}_${STAMP}.dump"
    echo "Backed up $db to $BACKUP_DIR/${db}_${STAMP}.dump"
done

docker image inspect "$ADMIN_TOOLS" >/dev/null 2>&1 || docker pull -q "$ADMIN_TOOLS" >/dev/null

echo "$HOPS" | while read -r release main vis; do
    [ -n "$release" ] || continue
    # RESUME_AT re-runs a hop whose schema was applied but whose server failed.
    force=false
    if [ -n "$RESUME_AT" ]; then
        [ "$release" = "$RESUME_AT" ] || continue
        RESUME_AT=""
        force=true
    elif $standard_visibility; then
        # Standard visibility is converted on 1.23, the last release that runs both stores.
        [ "$release" = 1.23.1 ] || die "visibility is still the standard store on schema $main_version; expected to convert it on 1.23.1"
    elif ! version_gt "$main" "$main_version" && ! version_gt "$vis" "$vis_version"; then
        continue
    fi
    echo "==> Temporal $release"
    if $standard_visibility; then
        if $force || version_gt "$main" "$main_version"; then
            update_schema temporal temporal "$main"
            run_server "$release" postgresql
        fi
        migrate_standard_visibility
        standard_visibility=false
    else
        update_schema temporal temporal "$main"
        update_schema temporal_visibility visibility "$vis"
    fi
    run_server "$release" postgres12
    main_version="$main"
    vis_version="$vis"
done

echo
echo "Temporal database is at the schema of $TARGET. Start the stack with 'make up'."
