# r3ngine — Upgrading the Infrastructure Images

This page covers the third-party images in `docker/docker-compose.yml` and
`docker/docker-compose.dev.yml`: which versions they run, why, and what an
operator does to move an existing installation onto them. The application
image (`web`, `temporal-python-orchestrator`, `temporal-go-executor`) is built
from this repository and is not covered here.

## Summary

| Service | Before | Now | Existing install needs |
|---|---|---|---|
| `redis` | `redis:alpine` (floating; 8.10.2 on 2026-09-29) | `redis:8.10-alpine` | Nothing, in the normal case |
| `neo4j` | `neo4j:5.12.0` | `neo4j:5.26-community` (5.26 LTS; 5.26.31 on 2026-09-29) | A volume backup first; the store upgrades itself on start |
| `temporal` | `temporalio/auto-setup:1.22.4` | `temporalio/server:1.31.3` + `temporalio/admin-tools:1.31.3` jobs | `make temporal-upgrade` (also part of `make fullupgrade`) |
| `temporal-ui` (dev only) | `temporalio/ui:2.27.2` | `temporalio/ui:2.54.1` | Nothing |
| `proxy` | `nginx:alpine` (floating; 1.31.6) | `nginx:1.31-alpine` | Nothing |
| `db` | `postgres:16-alpine` | unchanged | Nothing |

The pins follow one rule: the tag names the release line (major.minor) and
floats only across patch releases, which never change the on-disk format.
Moving to a new line is a deliberate change to this file.
`web/tests/test_compose_infrastructure_images.py` fails if a third-party
image loses its version, or if the Temporal images and
`scripts/temporal_upgrade.sh` stop naming the same release.

## Upgrading an existing installation

1. Let running scans finish or abort them. Temporal is stopped for the upgrade,
   and a scan that was mid-flight resumes afterwards, but there is no reason to
   carry one across three database migrations.
2. Pull this version of the repository.
3. Back up (details per service below):
   ```bash
   make backup                      # r3ngine database + scan_results
   ```
   ```bash
   DC="docker compose --env-file .env -f docker/docker-compose.yml"
   $DC stop neo4j
   docker run --rm -v r3ngine_neo4j_data:/data:ro -v "$PWD/backups:/backup" \
     postgres:16-alpine tar czf /backup/neo4j_data_$(date +%Y%m%d_%H%M%S).tgz -C /data .
   ```
   `make temporal-upgrade` dumps the Temporal databases itself.
4. Run the upgrade. Either the full procedure:
   ```bash
   make fullupgrade
   ```
   which now steps the Temporal database right after it starts `db`, or just
   the infrastructure part:
   ```bash
   $DC stop temporal temporal-python-orchestrator temporal-go-executor
   ```
   ```bash
   $DC up -d db
   ```
   ```bash
   make temporal-upgrade
   ```
   ```bash
   make pull && make up
   ```
5. Check: `make images` lists the new tags, `$DC ps -a` shows every service healthy
   and `temporal-schema` / `temporal-create-namespace` as `Exited (0)`, and the
   Temporal UI lists the executions from before the upgrade.

`make.bat fullupgrade` (Windows) does not run the Temporal step. Run
`bash scripts/temporal_upgrade.sh` from WSL or Git Bash between stopping
Temporal and `make.bat up`.

---

## Redis

**`redis:alpine` → `redis:8.10-alpine`.** `redis:alpine` followed every
release, including the jump from 7.x to 8.0. Redis loads an RDB written by an
older release but refuses one written by a newer release, so a floating tag
that is later pinned *below* what a host already pulled stops Redis from
starting. The pin is the release `redis:alpine` resolved to when it was made
(8.10.2), so no existing install is asked to go backwards.

**What an operator does.** Nothing, normally. In `docker-compose.yml` Redis
holds only ephemeral state (Channels groups, cache, `scan:logs:*` streams) and
runs with `--save ""`; it has no named volume. The image does declare an
anonymous `/data` volume, which `docker compose up` carries over when it
recreates the container, and `docker-compose.dev.yml` keeps the default
snapshotting. So an old `dump.rdb` can be loaded on start:

- Written by Redis 7.x or an older 8.x: loads.
- Written by something newer than 8.10 (a host that pulled `redis:alpine`
  after this pin was made): Redis exits with `Can't handle RDB format version`.
  Because the content is disposable, drop the anonymous volume:
  ```bash
  $DC rm -sfv redis && $DC up -d redis
  ```

Rollback: the previous tag was floating, so "rollback" is `redis:7-alpine` at
most — and Redis 7 cannot read a dump written by 8.x (verified: `Can't handle
RDB format version 15`). Use `$DC rm -sfv redis` for the same reason as above.

Redis 8 is distributed under AGPLv3 / RSALv2 / SSPLv1 (7.4 was RSALv2 /
SSPLv1). r3ngine uses it unmodified as an internal service.

**Verified here.** Wrote a key and a stream with `redis:7-alpine` (7.4.11),
`SAVE`, started `redis:8.10-alpine` (8.10.2) with the compose command line on
the same volume: log `Loading RDB produced by version 7.4.11`, both keys
present, the compose healthcheck (`REDISCLI_AUTH=... redis-cli ping`)
passes. Starting 7.4 on the 8.10-written dump fails as described. The compose
service came up healthy with `save ""` and `maxmemory-policy allkeys-lru`.

## Neo4j

**`neo4j:5.12.0` → `neo4j:5.26-community`.** 5.12 is from 2023 and no longer
patched; 5.26 is the long-term-support release of Neo4j 5. The explicit
`-community` suffix documents the edition the stack already ran. APOC comes
from the image's own `labs/` directory (`NEO4J_PLUGINS=["apoc"]`), so its
version always matches the server (5.26.31 today). The memory settings
(`NEO4J_server_memory_*`) are unchanged in 5.26, and the healthcheck and the
entrypoint override (`tini`, the PID-file cleanup) work as before.

**What an operator does.** Back up the volume (step 3 above), then start the
new image. Within Neo4j 5 no `neo4j-admin database migrate` or
`allow_upgrade` setting is needed: 5.26 opens a 5.12 store as it is, and
upgrades the `system` database automatically on the first start.

**Rollback.** Not in place: once 5.26 has started, 5.12 refuses the store
(`Unknown serialization format version: 0` from the system graph). Restore
the tarball and go back to the old image:
```bash
$DC stop neo4j
docker run --rm -v r3ngine_neo4j_data:/data -v "$PWD/backups:/backup" postgres:16-alpine \
  sh -c 'find /data -mindepth 1 -delete && tar xzf /backup/neo4j_data_<stamp>.tgz -C /data'
```
The graph is rebuilt from PostgreSQL by the scans, so losing it is an
inconvenience rather than data loss.

An offline logical dump also works, with the image that owns the store:
```bash
docker run --rm -v r3ngine_neo4j_data:/data -v "$PWD/backups:/backups" neo4j:5.26-community \
  neo4j-admin database dump --to-path=/backups '*'
```

**Verified here.** Started `neo4j:5.12.0` with the compose service's
entrypoint, auth, APOC and memory settings on a named volume; created the
application's indexes (`graph_subdomain_name`, `graph_domain_name`), a
uniqueness constraint and a small graph (6 nodes, 5 relationships); stopped it
with the 60s grace period; started `neo4j:5.26` on the same volume. Result:
`Neo4j Kernel 5.26.31 community`, all nodes and relationships present, indexes
`ONLINE`, `apoc.path.subgraphAll` (the one APOC procedure r3ngine calls) and
`apoc.version()` = 5.26.31, `dbms.upgradeStatus()` = `CURRENT`, writes work,
and the Python driver pinned in `web/requirements.txt` (neo4j 5.23.1)
connects and creates an index. A `neo4j-admin database dump '*'` of the
upgraded store loaded into a fresh volume with all nodes. Starting 5.12 on the
upgraded store fails; restoring the pre-upgrade tarball brings 5.12 back with
its data.

## Temporal

**`temporalio/auto-setup:1.22.4` → `temporalio/server:1.31.3`.**
`auto-setup` is a development image that bundles schema setup, namespace
creation and the server; Temporal stopped publishing it after 1.29.7. 1.22 is
over two years old. The compose files now run the supported split:

| Service | Image | Role |
|---|---|---|
| `temporal-schema` | `temporalio/admin-tools:1.31.3` | One-shot, before the server. On a fresh install creates the `temporal` and `temporal_visibility` databases with the shipped schema. On an existing one only checks that the schema is the one 1.31.3 expects, and fails otherwise (`docker/temporal/setup-schema.sh`). |
| `temporal` | `temporalio/server:1.31.3` | The server, `DB=postgres12`. Mounts `docker/temporal/dynamicconfig/` (the server refuses to start without that file). Healthy once `GET /api/v1/namespaces/default` on the frontend's HTTP port (7243) answers — the image has no CLI for the old `tctl` check. |
| `temporal-create-namespace` | `temporalio/admin-tools:1.31.3` | One-shot, after the server starts: registers `default` with 24h retention, as auto-setup did (`docker/temporal/create-namespace.sh`). `temporal-python-orchestrator` depends on it, which is what makes `make up` run it. |

`scripts/clear_temporal_workflows.sh` runs the `temporal` CLI from the
admin-tools image on the compose network for the same reason.

### Why the database cannot just be pointed at the new server

- Temporal supports upgrading **one minor release at a time**: each release
  expects the schema of its own version, and some migrate data when they
  start. 1.22 → 1.31 is nine steps.
- The old compose file ran with `DB=postgresql`, which selects **standard
  visibility** (the `postgresql/v96` visibility schema). Temporal 1.24 removed
  standard visibility; the replacement is the SQL advanced visibility store,
  plugin `postgres12`, whose `executions_visibility` table has a different
  layout. There is no in-place schema migration between the two.
- Temporal 1.31 checks the schema version on start and exits
  (`version mismatch ... Expected version: 1.19 cannot be greater than Actual
  version: 1.10`), and the `temporal-schema` job refuses before that:
  `Database temporal has schema 1.10; this Temporal release expects 1.19.
  Upgrade it with scripts/temporal_upgrade.sh`. Nothing is migrated by
  accident.

### What `make temporal-upgrade` does

`scripts/temporal_upgrade.sh` needs `db` running and `temporal`,
`temporal-python-orchestrator` and `temporal-go-executor` stopped. It reads the
database credentials from the `db` container.

1. Reads the current schema versions and whether visibility is still standard.
   Exits without doing anything when the database is already at 1.31.3, or when
   there is no `temporal` database yet (a fresh install, which
   `temporal-schema` sets up).
2. Dumps `temporal` and `temporal_visibility` to
   `backups/<db>_<stamp>.dump` (`pg_dump -Fc`, mode 600). `make backup` only
   covers the r3ngine database.
3. For each release below, applies that release's schema with
   `temporal-sql-tool update-schema -v <version>` from `admin-tools:1.31.3`,
   then runs `temporalio/server:<release>` against the database until
   `temporal operator namespace describe default` succeeds, lets it run
   `HOP_SETTLE_SECONDS` (30s), and stops it.

   | Release | `temporal` schema | visibility schema |
   |---|---|---|
   | 1.22.4 (before) | 1.10 | standard (v96) 1.1 |
   | 1.23.1 | 1.11 | 1.4 |
   | 1.24.3 | 1.12 | 1.6 |
   | 1.25.2 | 1.14 | 1.6 |
   | 1.26.3 | 1.14 | 1.7 |
   | 1.27.4 | 1.16 | 1.9 |
   | 1.28.4 | 1.17 | 1.9 |
   | 1.29.7 | 1.18 | 1.9 |
   | 1.30.7 | 1.18 | 1.13 |
   | 1.31.3 | 1.19 | 1.14 |

4. On 1.23.1 — the last release that runs both visibility stores — it converts
   visibility: dumps the rows of the standard `executions_visibility` table
   (only the columns both layouts share) to
   `backups/temporal_visibility_standard_rows_<stamp>.sql`, drops and recreates
   `temporal_visibility` with the `postgres12` schema, and loads the rows back.
   Past executions stay listed in the Temporal UI, and running ones (including
   schedules) stay visible to `list_workflows("ExecutionStatus = 'Running'")`,
   which the orphan-workflow cleanup in `reNgine/tasks/scan_init.py` relies on.
   The main `temporal` schema is identical under both plugins, so it needs no
   conversion.

The run takes a few minutes. The first `make up` afterwards can log
`Not enough hosts to serve the request` for up to a minute while the server
expires the membership records of the intermediate servers; SDK clients retry
through it.

**If a hop fails** the script prints the server's log and stops. The database
then has that release's schema: fix the cause and re-run with
`RESUME_AT=<release> make temporal-upgrade`, or restore the dumps.

**Rollback** (back to `auto-setup:1.22.4`): stop Temporal and the workers,
restore both dumps, and check out the previous compose file:
```bash
for db in temporal temporal_visibility; do
  $DC exec -T db dropdb -U "$POSTGRES_USER" "$db"
  $DC exec -T db createdb -U "$POSTGRES_USER" "$db"
  $DC exec -T db pg_restore -U "$POSTGRES_USER" -d "$db" < "backups/${db}_<stamp>.dump"
done
```

### SDK compatibility

- Python `temporalio==1.30.0` (`web/requirements.txt`): works against 1.31.3 —
  workflows, signals, schedules, visibility queries, history reads (verified
  below). The server does not version-check the Python SDK.
- Go `go.temporal.io/sdk v1.25.1` (`web/executor/go.mod`): the 1.31.3 server
  accepts Go SDK `<2.0.0` (`common/headers/version_checker.go`); a workflow with
  a heartbeating activity ran to completion against it. v1.25.1 is from 2023,
  so a bump is worth doing on its own, but it is not required.
- `temporalio/ui` 2.x is accepted (`<3.0.0`); 2.54.1 lists the pre-upgrade
  executions.

### Verified here

Against a throwaway `postgres:16-alpine`:

1. `auto-setup:1.22.4` with the old compose environment (`DB=postgresql`).
   With the Python SDK 1.30.0: a completed workflow (10 history events), a
   workflow blocked on a signal, and a paused schedule. Schema: `temporal`
   1.10, `temporal_visibility` 1.1 (standard).
2. Stopped it and ran `scripts/temporal_upgrade.sh` (the compose-style names
   `<project>-db-1` / `<project>_r3ngine_network`, credentials read from the
   container): every hop 1.23.1 … 1.31.3 became healthy; 7 visibility rows
   carried over; final schema 1.19 / 1.14.
3. `docker compose up` of this compose file: `temporal-schema` reported
   `schema 1.19, as expected` for both databases, `temporal` healthy,
   namespace job exited 0. The completed workflow's result and 10 events, the
   running workflow (4 events), the paused schedule and the visibility list
   all read back; a new workflow ran; signalling the pre-upgrade workflow
   completed it (`released:after-upgrade`).
4. Fresh volume: `temporal-schema` created both databases (1.19 / 1.14), the
   namespace job registered `default` (retention 24h), workflows run.
5. A database restored from the 1.22 dumps: `temporal-schema` exits 1 with the
   message above and `temporal` is not started.
6. Go SDK v1.25.1 workflow + activity, Temporal UI 2.54.1 API listing, and
   `clear_temporal_workflows.sh` (count, batch delete) against 1.31.3.
7. Rollback: restored the step-2 dumps with the commands above;
   `auto-setup:1.22.4` started on them and served the pre-upgrade workflows
   and schedule.

### Moving to a later Temporal release

1. Add a row per minor release to `HOPS` in `scripts/temporal_upgrade.sh`, with
   the highest `schema/postgresql/v12/{temporal,visibility}/versioned`
   directory of that release's git tag.
2. Change the `temporal`, `temporal-schema` and `temporal-create-namespace`
   images in both compose files to the new release (the compose test checks
   they agree with the last `HOPS` row).
3. Operators run `make temporal-upgrade` before `make up`.

## nginx (`proxy`)

**`nginx:alpine` → `nginx:1.31-alpine`.** `nginx:alpine` is the mainline
branch; the pin keeps the mainline 1.31 line it resolved to (1.31.6), so
running installs see no change. `docker/proxy/config/rengine.conf` passes
`nginx -t` on it (with the IPv6 `listen` lines removed, as the test host has
no IPv6).

## PostgreSQL (`db`)

**Unchanged: `postgres:16-alpine`.** The tag already names the major version,
and within a major PostgreSQL releases are bug and security fixes with the
same on-disk format — pinning to a patch (16.15 today) would only hold those
back. A major upgrade (16 → 17) needs `pg_upgrade` or dump/restore; see
`scripts/pg_upgrade.sh` and `make fullupgrade`. The Temporal databases live in
the same cluster, so they move with it.

## Not changed

- `docker/redis/Dockerfile`, `docker/postgres/Dockerfile`,
  `docker/proxy/Dockerfile` still say `FROM redis:alpine` / `nginx:alpine`;
  no compose file builds them.
- `docker/certs/Dockerfile` (`alpine:latest`) builds the one-shot certificate
  generator in `docker-compose.setup.yml`; it holds no data.
- CI (`.github/workflows/ci.yml`) runs its Redis service on `redis:7-alpine`.
