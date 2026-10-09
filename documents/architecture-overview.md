# r3ngine — Architecture Overview

## System Overview

r3ngine is a modular, containerized reconnaissance and vulnerability assessment platform. The backend is a Django application with a Temporal-based durable workflow engine. Temporal replaced the original Celery task queue in v3.2.0; no Celery worker or broker remains.

---

## Container Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Docker Compose                            │
│                                                                  │
│  ┌──────────────┐  ┌──────────────────────┐  ┌───────────────┐  │
│  │   nginx      │  │   django (web)       │  │  postgres     │  │
│  │  :80/:443    │◄─┤  :8000               │  │  :5432        │  │
│  └──────────────┘  │  Django + DRF API    ├──►│  PostgreSQL   │  │
│                    │  Django Channels WS  │  └───────────────┘  │
│                    └──────────┬───────────┘                      │
│                               │                                  │
│  ┌─────────────────────────────▼──────────────────────────────┐  │
│  │                  Temporal Server :7233                      │  │
│  │  Workflow Engine — Namespace: default                       │  │
│  └──────────┬──────────────────────────┬──────────────────────┘  │
│             │                          │                          │
│  ┌──────────▼──────────┐  ┌───────────▼──────────────────────┐  │
│  │ temporal-orchestrator│  │  temporal-go-executor            │  │
│  │ (Python worker)      │  │  (Go worker)                     │  │
│  │ Queue:               │  │  Queue: go-executor-queue        │  │
│  │  python-orchestrator │  │  Runs heavy CLI tools:           │  │
│  │  -queue              │  │  nuclei, nmap, ffuf, httpx, etc. │  │
│  └─────────────────────┘  └──────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │   redis      │  │   neo4j      │  │  temporal-ui :8080     │ │
│  │  :6379       │  │  :7474/:7687 │  │  Temporal Web UI       │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Service Descriptions

### `django` (Web Container)

- **Framework:** Django 5.2 LTS + Django REST Framework
- **Real-time:** Django Channels (ASGI) with Redis channel layer
- **Responsibilities:**
  - Serves the REST API (`/api/`)
  - Serves the React frontend (static files)
  - Handles WebSocket connections for real-time scan updates
  - Acts as the Temporal client — starts workflows in response to API calls
  - Hosts the plugin management UI

### `temporal-orchestrator` (Python Worker)

- **Language:** Python
- **Task Queue:** `python-orchestrator-queue`
- **Responsibilities:**
  - Hosts all Temporal workflow definitions (`MasterScanWorkflow`, `SubScanWorkflow`, etc.)
  - Hosts Python-side Temporal activities (DB reads/writes, calling scan tool wrappers)
  - Dynamically loads plugin workflows and activities via `PluginTemporalRegistry`
  - Entry: `temporal-entrypoint.sh`

### `temporal-go-executor` (Go Worker)

- **Language:** Go
- **Task Queue:** `go-executor-queue` (master) or `go-executor-queue-<WORKER_NAME>` on a remote worker — see `tool-distribution.md`, "Queue names per host"
- **Responsibilities:**
  - Executes heavy security tool subprocesses (Nuclei, Nmap, Ffuf, Httpx, Aquatone, etc.)
  - Reports stdout/stderr to the Python orchestrator via the shared PostgreSQL database
  - Entry: `executor/main.go`

### `temporal` (Temporal Server)

- **Version:** OSS Temporal Server
- **Storage:** PostgreSQL (shared with Django)
- **UI:** Available at `:8080` (Temporal Web UI)

### `redis`

Used for:
- Django Channels channel layer (WebSocket message routing)
- Redis Streams for real-time AD assessment progress events
- Django cache and scan-time deduplication (e.g. fuzzing noise filtering)

### `neo4j`

Graph database for:
- Attack Path Modeling Engine (APME) — nodes are scan findings, edges are attack paths
- Active Directory plugin — AD domain/trust/exposure graph

---

## Optional Services (compose profiles)

Two services are opt-in and sit behind compose `profiles` in
`docker/docker-compose.yml`. Set `COMPOSE_PROFILES=tor,ollama` in `.env` and the
Makefile includes them in `make up`, `make stop`, `make logs`, …; `make up-tor` /
`make up-ollama` start one without editing `.env` (`make.bat` has the same
targets, since it cannot read `.env`).

| Service | Profile | Used by | The app's view of it |
|---|---|---|---|
| `tor` (built from `web/tor/`) | `tor` | "TOR Mode" in Settings → Proxy; `TorNewCircuitActivity` between scan phases | `reNgine/tor_manager.py` — TCP probe of `tor:9050`, NEWNYM over `tor:9051` with `TOR_CONTROL_PASSWORD` |
| `ollama` (built from `docker/ollama/`, `OLLAMA_DOCKERFILE` picks the GPU variant) | `ollama` | LLM Toolkit local models (`http://ollama:11434`) | `reNgine/ollama_manager.py` — `GET /api/version` |

The application never starts or stops these containers. When a service is
down, the UI (TOR Mode card, Ollama service status) shows the `hint` from the
status endpoint that says how to enable it, and turning TOR Mode on is refused
until Tor answers. `TOR_CONTROL_PASSWORD` is shared by the `tor` service (which
hashes it into its torrc and refuses to start without it), `web` and the
orchestrator.

---

## No Docker Socket

No container mounts `/var/run/docker.sock` (a guard test,
`web/tests/test_compose_no_docker_socket.py`, keeps it that way). The three
things that used it are done without the Docker API:

- **Plugin install restart** (`POST /api/plugins/restart-server/`): the
  orchestrator is told over the `orchestrator_control` Redis channel and exits;
  the web process terminates its own service root a few seconds later
  (`reNgine/utils/process_restart.py`: SIGTERM to the gunicorn master under
  tini, graceful shutdown) and compose's `restart: always` starts the container
  again from its entrypoint.
- **Tool inventory** (Tool Arsenal, `/api/action/tool/<name>/args/`,
  `manage.py sync_installed_tools`): probes run where the tools are installed.
  Inside the Python orchestrator (`R3NGINE_WORKER_ROLE=python`, set by
  `run_temporal_orchestrator`) `reNgine/tool_workers.py` resolves binaries, runs
  `--version`/`--help` and syncs `InstalledExternalTool` locally; from `web`
  the same calls start `ToolProbeWorkflow` → `ToolProbeActivity` on
  `python-orchestrator-queue` and use the answer. Worker paths are stored as
  `python:/usr/local/bin/kr`. If Temporal is unreachable the web process
  falls back to its own filesystem (same image).
- **Tor / Ollama**: compose profile services, see above.

---

## Backend Code Layout

Large modules are packages whose `__init__.py` only re-exports, so existing
imports (`from reNgine.common_func import *`, `from reNgine.tasks import X`,
`reNgine.temporal_activities`) keep working. Patch names in tests where they are
looked up — the submodule — not on the package.

| Package | Modules |
|---|---|
| `reNgine/temporal/workflows/` | `_common` (retry presets, shared helpers), `master_scan`, `subscan`, `jobs`, `recon`, `stress`, `assessment_workflow` |
| `reNgine/temporal/activities/` | `core` (`_run_task`, `TemporalTaskProxy`, cancellation), `scan_lifecycle`, `discovery`, `enumeration`, `vuln_scan`, `post_processing`, `intel`, `proxies`, `maintenance`, `plugin_auth`, `stress`, plus assessment/graph/evidence/followups |
| `reNgine/tasks/` | one module per scan domain; `osint/` and `crawl/` are sub-packages |
| `reNgine/common_func/` | `db_queries`, `proxy_pool`, `notify`, `url_utils`, `vuln_helpers`, `whois_info`, `probe_gates`, `cli_commands`, `scan_config`, `api_keys` |
| `api/views/` | one module per API domain (scan, scan_status, targets, subdomains, endpoints, vulns, recon, notes, tools, settings, …) |
| `api/serializers/` | `scans`, `hosts`, `web_endpoints`, `findings`, `domains`, `engines`, `visualise`, `osint_data`, … |

Trace a feature as: API view → workflow starter (`reNgine/tasks/scan_init.py`) →
workflow → activity → task function → model write.

---

## Request Flow: Starting a Scan

```
Browser → POST /api/startScan/ (Django REST API)
    │
    ▼
startScan/views.py
    │
    ▼
reNgine.temporal_client.TemporalClientProvider.get_client()
    │
    ▼
Temporal Server (start MasterScanWorkflow)
    │
    ▼
temporal-orchestrator (Python Worker)
    │
    ├─ Tier 1–6 Activities → python-orchestrator-queue (Python) OR
    │                        → go-executor-queue (Go)
    │
    └─ Results written to PostgreSQL, events pushed via Redis/WebSocket
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend API | Django 5.2 LTS + Django REST Framework |
| Real-time | Django Channels (ASGI) + Redis |
| Workflow Engine | Temporal (OSS) |
| Python Worker | temporalio Python SDK |
| Go Worker | temporalio Go SDK |
| Database | PostgreSQL 16 |
| Graph Database | Neo4j |
| Cache / Pub-Sub | Redis |
| Frontend | React (TypeScript) + MUI |
| Containerization | Docker Compose |
