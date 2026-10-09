# r3ngine — Tool Distribution (Go Executor)

## Overview

r3ngine uses a two-worker architecture for running security tools. Heavy CLI tool execution (Nuclei, Nmap, Ffuf, Httpx, Aquatone, etc.) is delegated to a dedicated **Go Executor** service that runs on the `go-executor-queue` Temporal task queue (on the master; a remote worker's executor has its own queue, see [Queue names per host](#queue-names-per-host)).

This separation allows:
- **Performance**: Go's goroutine-based concurrency handles many concurrent subprocess calls efficiently.
- **Isolation**: Tool crashes don't affect the Python orchestrator.
- **Scalability**: The Go executor can be independently scaled.

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
**Task Queue:** `go-executor-queue`, or `go-executor-queue-<WORKER_NAME>` on a remote worker (`--worker-name` flag or `WORKER_NAME` env, flag wins)

### Responsibilities

1. Registers `RunToolSubprocessActivity` with Temporal.
2. When an activity is dispatched, executes the command as a subprocess.
3. Streams stdout/stderr to the `Command` DB record (PostgreSQL) for real-time log viewing.
4. Sends periodic heartbeats to Temporal to prevent activity timeouts during long-running tools.
5. Returns the subprocess result dict.

### Heartbeating

The Go worker sends heartbeats every 30 seconds during subprocess execution. If the subprocess takes longer than `heartbeat_timeout` without a heartbeat, Temporal reschedules the activity.

---

## Which Tools Run on Which Queue?

### `go-executor-queue` (Go Worker)

| Tool | Description |
|---|---|
| Nuclei | Template-based vulnerability scanner |
| Nmap | Network port scanner |
| Ffuf | Directory/path fuzzing |
| Httpx | HTTP probing and crawling |
| Aquatone | Web screenshot and asset discovery |
| Amass | Subdomain enumeration |
| Subfinder | Passive subdomain discovery |
| Assetfinder | Subdomain discovery |
| Hakrawler | Web spider/crawl |
| GAU | URL archive fetching |
| Gospider | Web spider |
| Katana | JavaScript-aware web spider |
| WaybackURLs | Wayback Machine URL fetcher |
| Dirsearch | Directory fuzzing |
| SQLMap | SQL injection exploitation |
| Dalfox | XSS scanner |
| CRLFuzz | CRLF injection fuzzer |
| WPScan | WordPress scanner |
| S3Scanner | S3 bucket misconfiguration scanner |
| BadDNS | DNS takeover checker |
| SpiderFoot | Attack surface intelligence |

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

---

## `RunToolSubprocessActivity` (Go)

The single activity registered on the Go worker. Executes any command as a subprocess and streams the output.

### Implementation Details

- Uses `os/exec` to spawn the subprocess.
- Reads stdout line-by-line and writes to the `Command` DB record.
- Sends Temporal heartbeats every 30 seconds.
- On heartbeat timeout, the activity is cancelled and the subprocess is killed with `SIGTERM`.
- Buffers large tool outputs to prevent DB row size issues.

---

## Executor Entrypoint (`executor-entrypoint.sh`)

The Go executor container:

1. Waits for the Temporal server and PostgreSQL to be ready.
2. Builds the Go executor binary if not already built.
3. Runs database tool installer scripts to ensure all security tools are present.
4. Starts the Temporal Go worker.

---

## Tool Installation

Tools are installed in the Go executor container via Dockerfile (`web/Dockerfile`):

```dockerfile
# Example tool installations
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/amass/v4/...@latest
RUN pip install sqlmap xsstrike
```

Tools that require Python are installed via pip; Go-based tools via `go install`.
