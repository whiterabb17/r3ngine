# r3ngine — Temporal System

## Overview

r3ngine uses **Temporal** as its durable workflow engine, replacing the previous Celery/Redis task queue. Temporal provides:

- **Durability**: Workflows survive container restarts and crashes.
- **Retry logic**: Activities retry automatically on failure with configurable policies.
- **Visibility**: All workflow executions are visible in the Temporal Web UI.
- **Cancellation**: Workflows can be cancelled cleanly at any tier boundary.
- **Scheduling**: Temporal Schedules replace `django_celery_beat` for periodic/clocked scans.

---

## Task Queues

r3ngine uses two task queues per host:

| Queue Name | Worker | Purpose |
|---|---|---|
| `python-orchestrator-queue` | `temporal-python-orchestrator` (Python) | Workflow hosting, Django DB reads/writes, Neo4j sync, LLM calls |
| `go-executor-queue` | `temporal-go-executor` (Go) | Heavy CLI tool subprocesses (Nuclei, Nmap, Httpx, Ffuf, etc.) |

Those are the master's names. A remote worker host (`docker/docker-compose.worker.yml`,
`WORKER_NAME=<name>`) runs the same two services on `<name>` and
`go-executor-queue-<name>`, so its tool runs stay on the host whose
`scan_results` volume the Python side reads. `reNgine.utils.task_queues` is the
single place that derives the names in Python (`web/executor/queue.go` in Go);
see `tool-distribution.md`, "Queue names per host".

### Why Two Queues?

Python is excellent for Django ORM operations, parsing, and LLM calls. Go is excellent for high-performance, concurrent subprocess management. The split allows each worker to be independently scaled and optimized.

---

## Temporal Connection

**File:** `web/reNgine/temporal_client.py`

```python
class TemporalClientProvider:
    @classmethod
    async def get_client(cls) -> Client:
        temporal_host = os.environ.get("TEMPORAL_HOST", "temporal:7233")
        namespace = os.environ.get("TEMPORAL_NAMESPACE", "default")
        return await Client.connect(temporal_host, namespace=namespace)
```

> **Important:** A fresh `Client()` is created per operation. The SDK's gRPC channel pool handles connection reuse internally. Caching the client across `asyncio.run()` boundaries causes gRPC errors.

### Synchronous Django Callers

Django views are synchronous. To call Temporal from a view, use the `asyncio.new_event_loop()` bridge pattern:

```python
loop = asyncio.new_event_loop()
try:
    loop.run_until_complete(_start_workflow_async())
finally:
    loop.close()
```

---

## Workflow Definitions (`temporal_workflows.py`)

All workflows are defined in `web/reNgine/temporal_workflows.py`.

### Design Principles

1. **Workflows are deterministic** — No I/O, no `datetime.now()`, no random numbers inside `@workflow.defn` methods.
2. **Activities do all side effects** — File I/O, DB writes, subprocess calls.
3. **Workflow code is thin** — It gathers, sequences, and forks activities.
4. **Non-Django imports** are wrapped in `workflow.unsafe.imports_passed_through()`.

### Retry Policy Presets

```python
_RETRY_LONG_SCAN    # max 2 attempts, 1min initial, backoff 2x, max 10min
_RETRY_SCANNER      # max 3 attempts, 2min initial, backoff 2x, max 10min
_RETRY_NETWORK_SCAN # max 3 attempts, 30s initial, backoff 2x, max 5min
_RETRY_INTERNAL     # max 5 attempts, 5s initial, backoff 1.5x, max 30s
_RETRY_LLM          # max 3 attempts, 30s initial, backoff 2x, max 5min
```

Every `execute_activity` call passes one of these explicitly. Temporal's implicit default is
*unlimited* attempts with a 100s maximum interval, and scan tasks report failure by returning
`False` (which `_run_task` raises), so an omitted policy retries a broken scanner forever —
adding a `ScanActivity` row per attempt. Child workflows are the reverse: their default is a
single attempt, so omitting the policy there is safe.

The policy is captured by the server when the activity is scheduled, so redeploying a worker
does not change the behaviour of an execution that is already retrying — cancel it instead.

### Workflow Registry

| Workflow Name | Class | Description |
|---|---|---|
| `MasterScanWorkflow` | `MasterScanWorkflow` | Full 7-tier scan pipeline |
| `NucleiPlannerWorkflow` | `NucleiPlannerWorkflow` | Child workflow for vulnerability scanning |
| `SubScanWorkflow` | `SubScanWorkflow` | Single-subdomain subscan workflow |
| `StressTestWorkflow` | `StressTestWorkflow` | Stress testing with kill switch signal |
| `MonitoringWorkflow` | `MonitoringWorkflow` | Periodic domain monitoring |
| `ScheduledScanWorkflow` | `ScheduledScanWorkflow` | Wrapper for Temporal-scheduled scans |
| `StartupSyncWorkflow` | `StartupSyncWorkflow` | One-shot startup sync tasks |
| `GoExecutorTaskWorkflow` | `GoExecutorTaskWorkflow` | Routes tasks to the Go executor queue |
| `ApmeTaskWorkflow` | `ApmeTaskWorkflow` | LLM-based attack path modeling |
| `IdentityEnrichmentWorkflow` | `IdentityEnrichmentWorkflow` | OSINT identity enrichment |
| `GeoLocalizeWorkflow` | `GeoLocalizeWorkflow` | IP geolocation lookup |
| `HackerOneImportWorkflow` | `HackerOneImportWorkflow` | HackerOne scope import |
| `HackerOneSyncBookmarkedWorkflow` | `HackerOneSyncBookmarkedWorkflow` | HackerOne bookmarks sync |
| `ProxyFetchWorkflow` | `ProxyFetchWorkflow` | Proxy list fetching |

---

## Activity Definitions (`temporal_activities.py`)

Activities are defined in `web/reNgine/temporal_activities.py`. Key activities:

| Activity Name | Queue | Description |
|---|---|---|
| `TargetProfilingActivity` | python | Validates scan, enriches context, sets up directories |
| `LoadCheckpointActivity` | python | Backward-compat checkpoint stub |
| `CheckScanQueueStatusActivity` | python | Queue position check (concurrency control) |
| `RunSubdomainDiscoveryActivity` | python | Subdomain discovery (amass, subfinder, assetfinder, etc.) |
| `RunAmassIntelDiscoveryActivity` | python | Amass intelligence mode |
| `RunFirewallVPNScanActivity` | python | Firewall/VPN detection |
| `SeedEndpointsForCrawlActivity` | python | Pre-seeds endpoint DB before crawl |
| `RunHTTPCrawlActivity` | python | HTTP crawl (httpx/hakrawler) |
| `ParseHTTPCrawlResultsActivity` | python | Parses crawl results into DB |
| `RunPortScanActivity` | python | Nmap port scanning |
| `RunVigoliumDiscoveryActivity` | python | Vigolium service discovery |
| `RunFetchURLActivity` | python | URL fetching (gau, gospider, waybackurls, katana) |
| `RunDirFileFuzzActivity` | python | Directory/file fuzzing (ffuf unless `run_ffuf: false`; optional dirsearch/feroxbuster passes) |
| `ParseFuzzResultsActivity` | python | Parses fuzz results into DB |
| `RunWebAPIDiscoveryActivity` | python | OpenAPI/GraphQL discovery |
| `RunWAFDetectionActivity` | python | WAF detection (wafw00f) |
| `RunSecretScanningActivity` | python | Secret scanning (trufflehog, gitleaks) |
| `RunNucleiActivity` | python | Nuclei vulnerability scanning |
| `RunCRLFuzzActivity` | python | CRLF injection fuzzing |
| `RunDalfoxActivity` | python | Dalfox XSS scanning |
| `RunS3ScannerActivity` | python | S3 bucket scanning |
| `RunSemgrepActivity` | python | Semgrep static analysis |
| `CorrelateVulnerabilitiesActivity` | python | Vulnerability correlation |
| `CalculateRiskScoresActivity` | python | Risk score computation |
| `GenerateImpactAssessmentActivity` | python | LLM impact assessment |
| `SyncGraphActivity` | python | Neo4j graph sync |
| `RunGenericTaskActivity` | python | Generic task dispatcher |
| `FinalizeFailedScanActivity` | python | Mark scan failed in DB |
| `SendScanNotificationActivity` | python | Post-scan notifications |
| `RunToolSubprocessActivity` | **go** | Go executor subprocess runner |

---

## Worker Startup (`temporal-entrypoint.sh`)

The Python orchestrator worker:

1. Waits for Temporal server to be ready.
2. Registers the `default` namespace if it doesn't exist.
3. Runs Django migrations.
4. Loads plugin Temporal workflows and activities via `PluginTemporalRegistry`.
5. Starts the Temporal worker with all workflows and activities registered.

---

## Temporal Web UI

Available at `http://localhost:8080` in development. Provides:
- List of all workflow executions
- Execution history and event timeline
- Activity retries and error messages
- Schedule management
