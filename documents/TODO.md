# Open work

Known issues that need a decision or a real deployment to verify. Each entry
says what the problem is, what was decided, and what has been done.

## Deferred — needs a test stack

Nothing at the moment.

## Decided

### `docker.sock` mounted into `web` and the worker

Decision: **option B** (owner, 2026-09-29) — remove the socket, in stages.

The socket was mounted in `docker/docker-compose.yml` (`web`),
`docker-compose.dev.yml` and `docker-compose.worker.yml`. Access to it is root
on the host, so any code execution inside `web` (a plugin, a dependency, a
deserialisation bug) became a host compromise. It was used by
`tor_manager.py` / `ollama_manager.py` (`containers.run`), `tool_workers.py` /
`tool_inventory.py` (`exec_run` into the worker containers) and
`plugins/views.py` (`docker restart r3ngine-web-1`).

Options considered: A — docker-socket-proxy with an allowlist (`containers.run`
and `exec` are still enough to get root); B — remove the socket; C — the easy
parts of B, Tor/Ollama behind a minimal proxy.

Done (2026-09-29):

- **Compose:** no file mounts `docker.sock` (`web/tests/test_compose_no_docker_socket.py`
  guards it). `tor` and the new `ollama` service (main; dev's always-on ollama
  moved behind the profile too) sit behind `profiles: ["tor"]` /
  `["ollama"]` with `restart: always`; `container_name: tor` is gone. The
  Makefile derives the extra services from `COMPOSE_PROFILES` (in `.env` or
  the environment) and gains `up-tor` / `stop-tor` / `up-ollama` /
  `stop-ollama`; `make.bat` gets the four targets. `.env.example` documents
  `COMPOSE_PROFILES`, `TOR_CONTROL_PASSWORD` and `OLLAMA_DOCKERFILE`.
- **Tor:** `web/tor/entrypoint.sh` refuses to start without
  `TOR_CONTROL_PASSWORD` (it used to default to `changeme`); compose passes the
  variable to `tor`, `web` and the orchestrator. `reNgine/tor_manager.py` only
  probes `tor:9050` (`is_running` / `status` with an enable `hint`) and sends
  NEWNYM with the env password; `start()` / `stop()` / `TorStartError` are
  gone. Saving proxy settings with TOR Mode on is refused (503 + hint, flag
  reset) while Tor is down; `GET /api/rengine/tor-status/` returns
  `{running, host, port, hint}` and the Proxy settings page shows the hint.
- **Ollama:** `reNgine/ollama_manager.py` probes `http://ollama:11434/api/version`.
  `…/ollama/service_status` returns `{running, url, version, hint}`;
  `service_start` answers 503 with the enable hint (200 when already running)
  and `service_stop` 501 with the host command — both kept for API clients.
  The LLM Toolkit page shows status + hint instead of start/stop buttons.
- **Plugin restart:** `POST /api/plugins/restart-server/` keeps the Redis
  `orchestrator_control` signal and, instead of `docker restart`, schedules
  `reNgine/utils/process_restart.py` (SIGTERM to the service root — gunicorn's
  master under tini — after 3 s; `restart: always` brings the container back).
- **Tool inventory:** `reNgine/tool_workers.py` runs the probes locally when
  `R3NGINE_WORKER_ROLE` is set (the orchestrator command sets `python`) and
  otherwise starts `ToolProbeWorkflow` → `ToolProbeActivity` (ops `resolve`,
  `version`, `help`, `summary`, `sync`) on `python-orchestrator-queue`.
  `sync_installed_tools()` from `web` therefore runs on the orchestrator and
  returns its summary (`workers.mode` = `local` / `remote` / `unavailable`);
  paths are stored as `python:/…`. Same public function names, so
  `tool_inventory.py` / `tool_args.py` callers and the Tool Arsenal / tool-args
  API are unchanged. The Go executor is not probed separately: it runs the same
  image.
- **Dependency:** `docker` removed from `web/requirements.txt`; nothing imports
  it any more.
- **Tests:** `test_process_restart.py`, `test_tor_manager.py` (rewritten),
  `test_ollama_manager.py` (managers + endpoints), `test_tool_workers.py`
  (local ops, dispatch, fallback), `test_compose_no_docker_socket.py`; the
  integration test in `test_tool_args_inventory.py` now expects the Temporal
  path.
- **Checked here:** `docker compose config` of all three files (with the
  profiles on) renders without `docker.sock`; the Makefile service list with
  and without `COMPOSE_PROFILES`; a Tor container built from `web/tor/` (on an
  Ubuntu base — the sandbox proxy blocks deb.debian.org) and the real
  `ollama/ollama` image: `TorManager.status()`, `new_circuit()` (correct,
  wrong and missing password), `OllamaManager.status()`, and both probes
  against closed ports.
- **Needs a real deployment to confirm:** the plugin restart on the production
  `init: true` + gunicorn stack (the container must come back on its own after
  the SIGTERM); `ToolProbeWorkflow` end to end against a running orchestrator
  (`manage.py refresh_tool_arg_schemas` from `web`, the Tool Arsenal refresh
  and the `@tag('integration')` test); the `tor` / `ollama` profile services
  under `make up` with `COMPOSE_PROFILES` set, including circuit rotation
  during a TOR-mode scan; the frontend after `make build-web`.

### Remote workers: Go executor shares the master's queue

Decision: **option A** (owner, 2026-09-29) — per-worker executor queue
`go-executor-queue-<WORKER_NAME>`, derived on both sides from `WORKER_NAME`.

The problem: `web/executor/main.go` always polled `go-executor-queue` and
ignored the `--worker-name` flag the worker compose passed; Python sent every
routed tool run (nuclei, ffuf, nmap, httpx, …) to that one queue, so a remote
executor took the master's jobs and vice versa, and tool output landed in the
`scan_results` volume of whichever host ran it while the Python side that
parses it could be on the other host. The worker compose also pointed at a
non-existent image (`docker.pkg.github.com/whiterabb17/r3ngine/r3ngine-go-executor`).

Options considered: A — per-worker queue; B — no executor on workers
(`route_to_executor=False`, losing the executor's cancellation and timeouts);
C — document remote workers as unsupported.

Done (2026-09-29):

- Go: `web/executor/queue.go` derives the queue (`go-executor-queue` when no
  name, else `go-executor-queue-<name>`) from `--worker-name` or `WORKER_NAME`
  (flag wins) and rejects a name outside `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$` at
  startup with a clear error; `main.go` polls that queue and logs it.
  `queue_test.go` covers the rule; CI's Go job now runs `go test ./...`.
- Python: `web/reNgine/utils/task_queues.py` is the single source for
  `python_orchestrator_queue()` / `go_executor_queue()` (from `WORKER_NAME`),
  `validate_worker_name()` (same pattern) and `configure_worker_name()` (flag
  wins, exported to the env). `run_temporal_orchestrator` uses it, so the
  activities it hosts route to the same host's executor. The three
  `GoExecutorTaskWorkflow` starts in `reNgine/utils/task.py` (`stream_command`,
  `run_command`, `_execute_go_workflow`) run the workflow on this host's
  Python queue and pass `executor_task_queue` in the input; the workflow
  (`temporal/workflows/jobs.py`) dispatches `RunToolSubprocessActivity` to that
  value — never to the environment — and falls back to `go-executor-queue` for
  inputs recorded before the key existed. `ScanWorkerSerializer` validates the
  name with the shared pattern. With `WORKER_NAME` unset every name is exactly
  the old one.
- Worker compose: `temporal-go-executor` runs from `${R3NGINE_IMAGE:?…}` with
  the app image's `executor-entrypoint.sh` (which now forwards its arguments to
  the binary), `--worker-name ${WORKER_NAME}`, `REDIS_URL`, and the volumes at
  the same paths as the Python orchestrator (`scan_results:/usr/src/scan_results`,
  wordlists, templates, `tool_config`).
- Docs: `documents/tool-distribution.md` ("Queue names per host") and
  `documents/temporal-system.md`.
- Tests: `web/tests/test_task_queues.py`, `web/tests/test_go_executor_routing.py`
  (every call site with and without `WORKER_NAME`, the workflow, the
  serializer) and `web/tests/test_go_executor_routing_integration.py`
  (`@tag('integration')`: a real Temporal server, two executor binaries — one
  unnamed, one `w1` — and the production call path; each job ran only on the
  matching executor).
- **Not verified on a real two-host deployment.** The check above ran on one
  machine with two executor processes; that a remote worker's Python
  orchestrator, its executor and the master agree end-to-end (shared Redis and
  Postgres over the network, the `R3NGINE_IMAGE` registry image, the mounted
  entrypoint) still needs a second host.
- Known, out of scope here: the scan workflows (`master_scan.py`, `subscan.py`,
  `recon.py`, …) hard-code `task_queue="python-orchestrator-queue"` on their
  activities, so a MasterScanWorkflow started on a worker's queue still runs
  its activities — and therefore its tool runs — on the master. Routing those
  by the workflow's own queue is a separate change.

### Vulnerability list payload

Decision: **option B** (owner, 2026-09-29) — an opt-in compact format for the
list endpoint; the default response stays as it is for compatibility.

`VulnerabilitySerializer` uses `fields='__all__'` with `depth=2`, so every row
of `/api/listVulnerability/` embeds the whole subdomain, endpoint, target and
scan with their own relations. Phase 5 made the query count independent of
page size, but it is still 88 queries per page and a large payload, while the
UI reads only a few of those nested fields.

Options considered: A — change the list format for everyone (breaks the API
contract for other consumers such as MCP clients); B — opt-in compact format
the frontend switches to; C — leave it.

Done (2026-09-29):

- `GET /api/listVulnerability/?compact=1` (also `true`) returns
  `VulnerabilityCompactSerializer` rows: the vulnerability's own fields, plus
  `scan_history {id}`, `subdomain {id, name}`, `endpoint {id, http_url}`,
  `target_domain {id, name}`, `tags [{id, name}]`, `references [{id, url}]` and
  `cve_ids` with the CVE columns the table shows. Every kept key has the same
  name and value as in the default format, so a compact row is a subset of a
  default row. Dropped: `exposure`, `validation_results`, `cwe_ids`,
  `vuln_subscan_ids` — no list view reads them.
- The flag applies to the list action only; `/{id}/` and `/queue/` ignore it.
  Filtering, search, ordering and pagination are unchanged. Without the flag the
  response is byte-identical to before (checked against the previous
  serializer on the same data), so MCP clients, reports and the legacy page
  keep working.
- Cost per page: 88 → 7 queries; a populated row 12.6 KB → 1.4 KB.
- The frontend vulnerability table and the scan Exploits tab request
  `compact=1` (`fetchVulnerabilities` / `useVulnerabilities`), typed with
  `VulnerabilityCompact`. The detail modal still loads the full record from
  `/{id}/`.
- Tests: `web/tests/test_api_vulnerability_compact.py` (default format intact,
  compact ⊂ default, flag parsing, same ids/order/pagination with and without
  the flag across 15 filter cases), a compact query-count test in
  `test_list_endpoint_query_count.py`, and a vitest test for the api function.
- Not done: the generated `frontend/src/types/api.ts` is stale for this model
  (e.g. types `scan_history` as a string) and was not regenerated.

### Compose infrastructure images

Was a known follow-up: `redis:alpine` unpinned, `temporalio/auto-setup:1.22.4`
a development image, `neo4j:5.12.0` old.

Done (2026-09-29), details and operator steps in
[upgrading-infrastructure.md](upgrading-infrastructure.md):

- `redis:8.10-alpine`, `neo4j:5.26-community` (5.26 LTS), `nginx:1.31-alpine`,
  dev `temporalio/ui:2.54.1`; `postgres:16-alpine` unchanged.
- Temporal: `temporalio/server:1.31.3` with one-shot `temporal-schema` and
  `temporal-create-namespace` services (`temporalio/admin-tools:1.31.3`,
  `docker/temporal/`), advanced visibility (`DB=postgres12`).
  `scripts/temporal_upgrade.sh` (`make temporal-upgrade`, also run by
  `make fullupgrade`) steps an existing database through every minor release
  and converts standard visibility on 1.23.
- `web/tests/test_compose_infrastructure_images.py` keeps third-party images
  versioned and the Temporal images in step with the upgrade script.
- Not done: the Go SDK in `web/executor/go.mod` is v1.25.1 (2023); it works
  against 1.31.3 but is due a bump. `make.bat fullupgrade` does not run the
  Temporal step.

### Code quality pass (phase 8, 2026-09-30)

Done:

- No silent broad exception handlers are left in `web/` (60 → 0): each was
  narrowed to what can actually be raised, or now logs. A static test
  (`tests/test_swallowed_exceptions.py`) rejects new ones.
- Bugs found on the way: WebSocket JWT auth accepted deactivated users;
  OpSec "metadata stripping" was a stub and did nothing; the plugin install
  status returned internal error text (pg_dump/migration stderr) to the
  client; an evidence purge recorded "file deleted" before trying and even
  when the storage delete failed.
- Frontend: no `any`/`@ts-ignore` left (147 → 0); API types regenerated from
  the drf-yasg schema (`frontend/README.md` has the steps); 11 display bugs
  the types exposed were fixed.
- Tests: no network access or kaleido rendering in the unit suite; the test
  runner rejects files and directories whose path comes from a mock.
- The WHOIS/BUCKETS tabs and the Nivo chart were fixed in phase 9.

## Other known follow-ups

- Remote workers: scan workflows still send their activities to the fixed
  `python-orchestrator-queue`, so a scan started on a worker runs its tools
  on the master. The per-worker Go queue (phase 10) only takes effect for
  activities that already run on the worker.
- The assessment WebSocket (`AssessmentEventConsumer`) lets any logged-in
  user subscribe to any assessment's events; check it against the REST
  permissions before multi-team use.
- drf-yasg types every `SerializerMethodField` as a string and JSON fields as
  empty objects, so the generated `frontend/src/types/api.ts` needs manual
  overrides for those fields. `swagger_serializer_method` annotations on the
  serializers would fix it at the source.
- `save_email`/`save_employee` start identity-enrichment threads that tests
  cannot switch off centrally (they currently do nothing on hosts without
  the tools); a seam in `reNgine/utils/task.py` would make that explicit.
- MCP sessions still record the client IP from `X-Forwarded-For`.
- Some task functions still put `str(e)` into their internal result dicts
  (not returned to HTTP clients, but stored and shown in places).
- Frontend: ApexCharts and ECharts could still be consolidated into one.
- Go SDK in `web/executor` is v1.25.1 (2023); it works with Temporal 1.31
  but is worth bumping.
- vigolium's known-issue scan wants `known_issue_scan.templates_dir` to be a
  git checkout, but the Go executor entrypoint points it at
  `/root/nuclei-templates`, the shared `nuclei_templates` volume, which has no
  `.git`. On start with tool updates enabled the executor logs
  `~/nuclei-templates exists but is not a git repository`. nuclei itself reads
  the directory fine; only vigolium's known-issue step is affected. Fix by
  giving vigolium its own templates directory instead of the shared volume.
