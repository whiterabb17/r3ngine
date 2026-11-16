# r3ngine — Tool Distribution (Go Executor)

## Overview

r3ngine uses a two-worker architecture for running security tools. Heavy CLI tool execution (Nuclei, Nmap, Ffuf, Httpx, Aquatone, etc.) is delegated to a dedicated **Go Executor** service that runs on the `go-executor-queue` Temporal task queue (on the master; a remote worker's executor has its own queue, see [Queue names per host](#queue-names-per-host)).

This separation allows:
- **Performance**: Go's goroutine-based concurrency handles many concurrent subprocess calls efficiently.
- **Isolation**: Tool crashes don't affect the Python orchestrator.
- **Scalability**: The Go executor can be independently scaled.

### Three role images

The app stack is built as **three images** from one multi-target Dockerfile (`docker/web/Dockerfile` via `docker-bake.hcl`):

| Image tag (local) | Compose service | Owns |
|---|---|---|
| `r3ngine-web:local` | `web` | Django API/UI, frontend static, migrations, `pg_dump` for plugins |
| `r3ngine-python:local` | `temporal-python-orchestrator` | Temporal workflows/activities, ORM/Neo4j/LLM, Playwright, Python-native tools under `/usr/src/github` |
| `r3ngine-go-executor:local` | `temporal-go-executor` | `r3ngine-executor` + compiled/apt/Ruby CLI scanners |

Registry / worker hosts set `R3NGINE_WEB_IMAGE`, `R3NGINE_PYTHON_IMAGE`, and `R3NGINE_GO_IMAGE` (not a single shared tag).

### Image contents (what each role must / must not ship)

| Image | Must contain | Must not contain |
|---|---|---|
| **web** | Django app, frontend `dist` / Node (DEBUG Vite), `postgresql-client-16` (`pg_dump` for plugins) | Scanner CLIs, Playwright/Chromium for scans, `/usr/src/github` tool forests, Ruby/WPScan, vigolium |
| **python** | Django + Temporal worker code, pipx/uv/Python-native tools, `/usr/src/github` trees, Playwright + Chromium | Compiled `ROUTED_TOOLS` binaries, vigolium, Node global `retire`/`lighthouse`, Ruby/WPScan |
| **go** | `r3ngine-executor`, all `ROUTED_TOOLS` binaries, apt scanners those tools need, Ruby + WPScan, aquatone Chromium slice, baked `/opt/r3ngine/wordlist`, thin `python3`+pip (Wordfence seed) | Django app tree, frontend, pipx forests, SpiderFoot/theHarvester clones |

Do not strip python of `ROUTED_TOOLS` binaries until every scan call site uses `run_command` / `stream_command` (no raw `subprocess` for those names). Long-running **reconx** monitoring is supervised on go-executor; python only writes config and parses findings under `scan_results`.

**Ownership rule for new tools:**
- New **compiled/PATH CLI** → add to the go image **and** add the binary name to `ROUTED_TOOLS` in `web/reNgine/utils/task.py` (plus fixture/`version_lookup` if it appears in Tool Arsenal).
- New **Python-native** tool (`python3 /usr/src/github/...`, pipx-only, in-process Playwright) → python image only; do **not** add to `ROUTED_TOOLS`.
- Interactive UI actions that need a tool must go through Temporal (`tool_workers` / orchestrator), never assume the binary exists in the web container.
- Tool Arsenal **add / update / uninstall / version** use `run_on_workers` / `remove_on_workers`. Python's `ToolProbeActivity` forwards compiled-CLI `run` / binary `remove` / go-preferred `resolve` to `GoExecutorTaskWorkflow` so installs land on go-executor, not web or a stripped python image.
- Scan tasks must call `run_command` (not raw `subprocess`) for anything in `ROUTED_TOOLS`, and put `-o` / input files under the shared `scan_results` volume (`RENGINE_RESULTS`) so go-executor I/O is visible to python.

### Shared volumes

Same pattern as `scan_results`: both workers **mount** these; only one entrypoint **downloads** into each:

| Volume | Mount | Who downloads/writes |
|---|---|---|
| `scan_results` | python + go | Tool/activity output (not entrypoint downloads) |
| `wordlist` | python + go | **Go entrypoint only** |
| `nuclei_templates` | python + go | **Go entrypoint only** |
| `gf_patterns` | consumer of `gf` | Single owner (go once `gf` is routed) |
| `github_repos` | python (+ go for vulscan only) | **Python owns** tool-tree first populate |
| `tool_config` | python + go | Per-role stamps/config keys |

Empty-volume first boot: go seeds wordlists/templates (healthcheck waits for seed sentinels); python seeds `/usr/src/github` tool trees. Web may still **mount** shared volumes for Tool Settings uploads, but it does not download or execute scanners into them.

**Lean assemblies (real size split):** `runtime-full` is an install-only intermediate. Each role is **stripped then flattened** (`FROM scratch` + `COPY --from=<role>-stripped / /`) so published tags do **not** inherit the fat parent layers. A plain `RUN rm` on `FROM runtime-full` does **not** shrink `docker images` size — do not ship that pattern. After rebuild, expect three different sizes (web smallest, go largest from CLIs/Chromium/WPScan, python mid from pipx/github/Playwright).

---

## Architecture

```
activity on the Python orchestrator (e.g. nuclei_scan)
        │  stream_command() / run_command()  — reNgine/utils/task.py
        │  tool in ROUTED_TOOLS → client.start_workflow(...)
        ▼  task_queue=python_orchestrator_queue()
GoExecutorTaskWorkflow (Python, thin)
        │  input_data["executor_task_queue"] = go_executor_queue()
        ▼  task_queue=<that value>
RunToolSubprocessActivity (Go Worker)
        │
        ▼
subprocess: nuclei / nmap / ffuf / httpx / ...
        │
        ▼
stdout/stderr → Redis log stream + Command row; files under /usr/src/scan_results
```

The caller (an activity in the Python orchestrator) decides both queues with
the helpers in `web/reNgine/utils/task_queues.py`; the workflow only forwards
the executor queue it was given, so it stays deterministic and never reads the
environment.

---

## Queue names per host

Tool output is written to the `scan_results` volume of the host that ran the
tool, and the Python task that started the tool parses those files from its own
volume. A remote worker therefore needs its own executor, and its tool runs
must never land on the master's executor (or vice versa). Both processes on a
host read `WORKER_NAME` (set in `docker/docker-compose.worker.yml`; the
`--worker-name` flag takes precedence on both) and derive:

| Process | Master (`WORKER_NAME` unset) | Worker `w1` |
|---|---|---|
| Python orchestrator queue | `python-orchestrator-queue` | `w1` |
| Go executor queue | `go-executor-queue` | `go-executor-queue-w1` |

- Python: `reNgine.utils.task_queues.python_orchestrator_queue()` and
  `go_executor_queue()`; `run_temporal_orchestrator --worker-name` exports the
  name to `WORKER_NAME` so the activities it hosts route to the same host.
- Go: `executorTaskQueue()` in `web/executor/queue.go`; an invalid name makes
  the executor exit at startup with a clear error.
- A worker name is 1–100 characters of `A-Z a-z 0-9 . _ -`, starting with a
  letter or digit. `ScanWorkerSerializer` enforces the same charset when a
  worker is registered, since the name becomes these queue names.

The master's names are exactly the historical ones, so a single-host
deployment is unchanged. Inputs recorded before `executor_task_queue` existed
replay on `go-executor-queue`.

---

## `GoExecutorTaskWorkflow`

**File:** `web/reNgine/temporal/workflows/jobs.py`

```python
@workflow.defn(name="GoExecutorTaskWorkflow")
class GoExecutorTaskWorkflow:
    @workflow.run
    async def run(self, input_data: dict) -> dict:
        timeout_sec = input_data.get("timeout_seconds") or 43200
        executor_queue = input_data.get("executor_task_queue") or "go-executor-queue"
        return await workflow.execute_activity(
            "RunToolSubprocessActivity",
            input_data,
            start_to_close_timeout=timedelta(seconds=timeout_sec),
            schedule_to_close_timeout=timedelta(seconds=int(timeout_sec * 2.2)),
            heartbeat_timeout=timedelta(minutes=10),
            retry_policy=_RETRY_LONG_SCAN,
            task_queue=executor_queue,
        )
```

### Input Payload

```python
{
    "command": ["nuclei -u https://target.example.com -t cves/"],
    "scan_id": 42,
    "command_id": 17,
    "working_dir": "/usr/src/scan_results/example.com_1",
    "timeout_seconds": 43200,
    "executor_task_queue": "go-executor-queue",
}
```

| Key | Type | Description |
|---|---|---|
| `command` | `list[str]` | One element: the full shell command (run via `bash -c`); several elements: binary + arguments |
| `scan_id` | `int` | ScanHistory ID for logging and the `scan_stop_<id>` kill switch |
| `command_id` | `int` | `Command` DB record ID to log stdout/stderr to |
| `working_dir` | `str` | Working directory for the subprocess (optional) |
| `timeout_seconds` | `int` | Per-attempt timeout (optional, default 12 h) |
| `executor_task_queue` | `str` | Go executor queue of the host that started the workflow (`go_executor_queue()`); optional, defaults to `go-executor-queue` |

### Output

```python
{
    "stdout": "...",
    "stderr": "...",
    "exit_code": 0
}
```

---

## Go Executor Service

**Source:** `web/executor/main.go` (queue derivation and worker-name validation in `queue.go`)  
**Container:** `temporal-go-executor`  
**Image:** `r3ngine-go-executor` (`R3NGINE_GO_IMAGE`)  
**Task Queue:** `go-executor-queue`, or `go-executor-queue-<WORKER_NAME>` on a remote worker (`--worker-name` flag or `WORKER_NAME` env, flag wins)

### Responsibilities

1. Registers `RunToolSubprocessActivity` with Temporal.
2. When an activity is dispatched, executes the command as a subprocess.
3. Streams stdout/stderr via Redis for real-time log viewing; Command rows are owned by Python.
4. Sends periodic heartbeats to Temporal to prevent activity timeouts during long-running tools.
5. Returns the subprocess result dict.

### Heartbeating

The Go worker sends heartbeats every 5 seconds during subprocess execution. If the subprocess takes longer than `heartbeat_timeout` without a heartbeat, Temporal reschedules the activity.

---

## Which Tools Run on Which Queue?

Canonical allowlist: `ROUTED_TOOLS` in `web/reNgine/utils/task.py`. Anything in that set that goes through `run_command` / `stream_command` is executed on the go executor. Do not maintain a second list here.

### `go-executor-queue` (Go Worker)

Compiled and PATH CLIs routed via `ROUTED_TOOLS`, including (non-exhaustive): Nuclei, Nmap, Ffuf, Httpx, Aquatone, Amass, Subfinder, Hakrawler, GAU, Gospider, Katana, WaybackURLs, Dirsearch, Dalfox, CRLFuzz, WPScan, S3Scanner, Naabu, Semgrep, Vigolium, TLSX, and other entries maintained in code.

### `python-orchestrator-queue` (Python Worker)

| Task | Description |
|---|---|
| Django DB reads/writes | All ORM operations |
| Tool output parsing | Parsing raw tool output into structured DB records |
| Correlation engine | Vulnerability correlation logic |
| Risk scoring | Risk score computation |
| LLM calls | AI impact assessment and APME |
| Neo4j sync | Graph database synchronization |
| WebSocket events | Real-time progress push to frontend |
| Playwright / screenshots | Browser-based tasks |
| Python-native tools | spiderfoot, CMSeeK, OneForAll, Sublist3r, jwt_tool, *2shell scanners, etc. |

---

## `RunToolSubprocessActivity` (Go)

The single activity registered on the Go worker. Executes any command as a subprocess and streams the output.

### Implementation Details

- Uses `os/exec` to spawn the subprocess.
- Streams stdout/stderr to Redis (`scan:logs:<scan_id>`) and updates Command output from Python when applicable.
- Sends Temporal heartbeats periodically.
- On cancel/abort, the subprocess process group is killed.
- Caps large tool outputs to prevent DB row size issues.

---

## Executor Entrypoint (`executor-entrypoint.sh`)

The Go executor container:

1. Idempotently seeds shared `wordlist` and `nuclei_templates` volumes (sole writer).
2. Installs/links go-owned extras (vulscan, `kr`) and runs weekly CLI updates (nuclei/vigolium/vulnx).
3. Writes seed sentinels used by the compose healthcheck.
4. Starts `/usr/local/bin/r3ngine-executor`.

Python never re-downloads those assets; it mounts the same volumes and waits for go to become healthy on first boot.

---

## Tool Installation

Tools are installed into the **go** and **python** images via the multi-target Dockerfile (`docker/web/Dockerfile`), not a single shared mega-image. Build with:

```bash
docker buildx bake -f docker-bake.hcl
# or: make build-app-images
```

Remote workers pull `R3NGINE_PYTHON_IMAGE` and `R3NGINE_GO_IMAGE` separately (`docker/docker-compose.worker.yml`).
