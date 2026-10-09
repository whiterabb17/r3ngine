#!/bin/sh
# Run once by the temporal-schema service before the Temporal server starts.
#
# Fresh install: creates the temporal and temporal_visibility databases and
# applies the schema that ships with this admin-tools image.
# Existing install: checks that the schema is the one this image ships and
# changes nothing. Temporal only supports moving a database one minor release
# at a time, so an older schema is not upgraded here: that is
# scripts/temporal_upgrade.sh (documents/upgrading-infrastructure.md).
set -eu

: "${POSTGRES_SEEDS:?POSTGRES_SEEDS is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_PWD:?POSTGRES_PWD is required}"
DB_PORT="${DB_PORT:-5432}"
SCHEMA_ROOT=/etc/temporal/schema/postgresql/v12
export SQL_PASSWORD="$POSTGRES_PWD"

tool() {
    temporal-sql-tool --plugin postgres12 --ep "$POSTGRES_SEEDS" -p "$DB_PORT" -u "$POSTGRES_USER" "$@"
}

until nc -z "$POSTGRES_SEEDS" "$DB_PORT"; do
    echo "Waiting for PostgreSQL at $POSTGRES_SEEDS:$DB_PORT"
    sleep 1
done

for pair in temporal:temporal temporal_visibility:visibility; do
    db="${pair%%:*}"
    dir="$SCHEMA_ROOT/${pair##*:}/versioned"
    shipped="$(ls "$dir" | sort -V | tail -n 1 | sed 's/^v//')"

    # Both commands are no-ops on a database that already has a schema.
    tool --db "$db" create >/dev/null 2>&1 || true
    tool --db "$db" setup-schema -v 0.0 >/dev/null 2>&1 || true

    # Asking for version 0.0 succeeds only on an empty schema; otherwise the
    # tool fails and names the current version.
    if probe="$(tool --db "$db" update-schema -d "$dir" -v 0.0 2>&1)"; then
        echo "Database $db is new: applying schema $shipped"
        tool --db "$db" update-schema -d "$dir" >/dev/null
        continue
    fi
    current="$(echo "$probe" | sed -n "s/.*start version '\([0-9.]*\)' must be less than.*/\1/p" | head -n 1)"
    if [ "$current" = "$shipped" ]; then
        echo "Database $db has schema $current, as expected"
    elif [ -n "$current" ]; then
        echo "Database $db has schema $current; this Temporal release expects $shipped." >&2
        echo "Upgrade it with scripts/temporal_upgrade.sh (documents/upgrading-infrastructure.md)." >&2
        exit 1
    else
        echo "$probe" >&2
        echo "Could not read the schema version of $db" >&2
        exit 1
    fi
done
