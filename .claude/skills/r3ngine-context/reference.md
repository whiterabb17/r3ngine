# r3ngine — Full Stack Reference

Loaded on demand when detailed stack or module information is needed.

## Core Technologies

### Backend
- **Django** 5.2.3 LTS: ORM, REST API (DRF 3.15.2), auth, permissions
- **Python** 3.12: backend logic, task functions, Temporal activities
- **temporalio** 1.7.0: workflow and activity SDK (replaced Celery entirely in v3.2.0)
- **channels** 4.2.2: WebSocket support via Redis channel layer
- **Playwright** 1.42.0: headless browser (screenshotting)

### Database
- **PostgreSQL**: primary persistent storage
- **Neo4j** 5.23.1: graph database for Attack Path Modeling Engine (APME) — Cypher queries via `Neo4jManager` in `web/reNgine/graph_utils.py`
- **Redis**: channel layer (WebSocket), task state, caching

### Frontend
- **React 18+**, TypeScript, Vite bundler
- State: Zustand stores (`frontend/src/store/`)
- API client layer: `frontend/src/api/`
- Components: `frontend/src/components/`, `frontend/src/features/`
- Pages: `frontend/src/pages/`
- Theme: `frontend/src/theme/` — use `useThemeTokens()`, `useSemanticColors()`, theme helpers

### Deployment
- **Docker** / Docker Compose (development + production)
- Django dev server (development), Gunicorn (production)
- All `manage.py` commands must run inside the container (`r3ngine-web-1`)
- Use `python3` (not `python`) inside the container
- Frontend build: `npm run build` run **locally** in `frontend/` (NOT inside the container — `node_modules` there is masked by an anonymous volume)
- Compose files live in `docker/`; drive them through the Makefile (`make up`, `make build-web`, `make restart-apps`, `make migrate`, `make logs`)
- `web/` is mounted into the containers, so Python changes need only a restart; a frontend change needs `make build-web && make up`, because the bundle is compiled in the Dockerfile's `frontend-builder` stage

### Quality & Tooling
- **flake8**: lint; **black**: format
- Django test framework; tests under `web/tests/`

## Temporal Architecture

```
Django REST API
    ↓
temporal_client.py (start / cancel)
    ↓
Temporal Server
    ├─ Python orchestrator worker  →  reNgine/temporal/workflows/*.py
    │                              →  reNgine/temporal/activities/*.py (DB, Neo4j, HTTP)
    └─ Go executor worker          →  executor/main.go (subprocess tools)
```

- **Workflows** (`reNgine/temporal/workflows/`, flat modules `_common`, `master_scan`, `subscan`, `stress`, `jobs`, `recon`, `assessment_workflow`; `__init__.py` re-exports): deterministic orchestrators; no I/O
  - Shim: `temporal_workflows.py` re-exports everything for backward compatibility
- **Activities** (`reNgine/temporal/activities/`, `core.py` + domain modules): 30+ activities; DB, Neo4j, HTTP, LLM calls
  - Shim: `temporal_activities.py` re-exports everything for backward compatibility
- **Go executor** (`executor/main.go`): subprocess management for 30+ security tools
- **Temporal UI**: `http://localhost:8080`
- **Retry policies**: every `execute_activity` call passes an explicit `retry_policy` (`_RETRY_SCANNER`, `_RETRY_LONG_SCAN`, `_RETRY_NETWORK_SCAN`, `_RETRY_INTERNAL`, `_RETRY_LLM`, defined in `workflows/_common.py`). The Temporal default is unlimited attempts, and each retry adds a `ScanActivity` row, so an omitted policy floods the scan timeline. The policy is fixed when the activity is scheduled — redeploying does not change an execution already retrying.

## Key Modules

- **startScan** (core domain):
  - `startScan/models.py`: `ScanHistory`, `Subdomain`, `EndPoint`, `Vulnerability`, `Parameter`, `ScanActivity`, `TemporalWorkflowExecution`
  - `startScan/views.py`: scan management REST endpoints
  - `ScanHistory.workflow_ids`: ArrayField tracking running Temporal workflow IDs (no celery_ids)
- **scanEngine**:
  - `scanEngine/models.py`: `EngineType` (YAML scan config templates), `InstalledExternalTool`
- **reNgine app** (shared logic):
  - `reNgine/tasks/`: task package — domain modules (scan_init, subdomain, crawl, vuln, osint, port_scan, persistence, notifications, geo, llm, waf, screenshot, parsers, proxies, acunetix); shim: `tasks/__init__.py`
  - `reNgine/temporal/workflows/`: `master_scan.py` (`MasterScanWorkflow`, `NucleiPlannerWorkflow`), `subscan.py` (`SubScanWorkflow`, `_SUBSCAN_DISPATCH`), `recon.py` (`CodeScanWorkflow`, `URLAuthExtractWorkflow`, recon/URL workflows), `jobs.py` (maintenance, single-activity, retry, follow-up), `stress.py`
  - `reNgine/temporal/activities/`: 117 `@activity.defn` functions in domain modules
  - `reNgine/temporal_workflows.py`: backward-compatible shim
  - `reNgine/temporal_activities.py`: backward-compatible shim
  - `reNgine/temporal_client.py`: `TemporalClientProvider` (sync/async bridge)
  - `reNgine/temporal_schedule_utils.py`: scheduled scan helpers
  - `reNgine/graph_utils.py`: `Neo4jManager` for APME Cypher queries
  - `reNgine/llm.py`, `reNgine/llm_utils.py`: LLM integration with PII anonymisation
  - `reNgine/common_func/`: shared utilities split by domain (`db_queries`, `vuln_helpers`, `api_keys`, `url_utils`, `proxy_pool`, `cli_commands`, `notify`, `whois_info`, `probe_gates`, `scan_config`); `__init__` is the compatibility surface for `from reNgine.common_func import *`
  - `reNgine/definitions.py`: enums, constants, task status values
  - `reNgine/utils/logger.py`: `get_module_logger`, `ModuleLogger`, `format_exception_for_log`
  - `reNgine/utils/opsec.py`: proxy rotation, OpSec controls
  - `reNgine/utils/task.py`: task utility helpers
  - `reNgine/scan_context.py`: scan context dataclass passed through pipeline
  - `reNgine/target_router.py`: routes scans to correct workflow by target type
  - `reNgine/task_plan.py`: pre-populates ordered task list for a scan config
  - **Task modules** (one file per scanning domain, all plain Python functions):
    - `reNgine/api_tasks.py`: API endpoint discovery
    - `reNgine/auth_discovery_tasks.py`: authentication discovery and extraction
    - `reNgine/cpde_tasks.py`: Custom Parameter Discovery Engine (CPDE)
    - `reNgine/crawl_tasks.py`: HTTP crawling (katana, gau, hakrawler, gospider)
    - `reNgine/dns_tasks.py`: DNS enumeration and subdomain discovery
    - `reNgine/firewall_tasks.py`: WAF and firewall detection
    - `reNgine/fuzzing_tasks.py`: directory/file fuzzing (ffuf, dirsearch)
    - `reNgine/monitor_tasks.py`: scan monitoring and heartbeat
    - `reNgine/network_tasks.py`: port scanning (nmap, naabu)
    - `reNgine/osint_tasks.py`: OSINT gathering (holehe, maigret)
    - `reNgine/recon_tasks.py`: general reconnaissance (httpx, tech detection)
    - `reNgine/report_tasks.py`: report generation
    - `reNgine/vigolium_tasks.py`: Vigolium static code scanner (dispatched by CodeScanWorkflow)
    - `reNgine/vulnerability_tasks.py`: vulnerability correlation and lifecycle
    - `reNgine/wpscan_tasks.py`: WPScan WordPress security scanner parser
    - `reNgine/wptaint_tasks.py`: WPTaint taint-flow vulnerability analysis
  - `reNgine/cpde/`: CPDE sub-package (custom parameter discovery engine)
- **apme app** (`web/apme/`):
  - `apme/orchestrator.py`: coordinates APME phases
  - `apme/engine/`: attack path computation engine
  - `apme/graph/`: Neo4j graph construction and traversal
  - `apme/ingestion/`: ingest scan results into the attack graph
  - `apme/models/`: APME-specific Django models
  - `apme/output/`: formats attack paths for the frontend
  - `apme/llm_orchestrator.py`: LLM-assisted attack path analysis
- **api app**:
  - `api/views/`: REST endpoint package — domain modules (scan, scan_status, targets, subdomains, endpoints, vulns, recon, notes, llm, tools, settings, notifications, hackerone, workers, misc, followups); shim: `api/views/__init__.py`
  - `api/serializers/`: DRF serializer package — domain modules (scans, domains, hosts, web_endpoints, findings, osint_data, visualise, engines, system, users, projects, recon_notes, scan_workers, hackerone_programs, alerts); compatibility surface: `api/serializers/__init__.py`
  - `api/urls.py`: URL routing for the API
- **plugins app**:
  - `plugins/views.py`: plugin management endpoints

## Database Model Key Entities

| Model | Purpose |
|-------|---------|
| `ScanHistory` | Top-level scan record with status, config, `workflow_ids` (Temporal IDs) |
| `Subdomain` | Discovered subdomains with scan context |
| `EndPoint` | HTTP endpoints (URL + method + parameters) |
| `Vulnerability` | Findings with severity, status, correlation state |
| `Parameter` | Extracted form/query parameters |
| `ScanActivity` | Granular activity log per scan step: `tier`, `status`, `target_host` (which host it ran against), `error_message`, `traceback`, `execution_id` |
| `EngineType` | YAML-based scan configuration templates |
| `TemporalWorkflowExecution` | FK from ScanHistory to running workflow ID |

## Neo4j Graph Design (APME)

- **Nodes**: Domains, Subdomains, IPs, Vulnerabilities, Services
- **Edges**: Domain→Subdomain, Service→IP, Vulnerability→Service
- Used for Attack Path Modeling Engine traversal
- Query via `Neo4jManager` in `web/reNgine/graph_utils.py`
- Bolt protocol on `neo4j:7687` (configurable via env)

## LLM Integration

- Centralised AI hub in `reNgine/llm.py`
- PII anonymisation happens **before** any external API call (see `llm_utils.py`)
- Supports: OpenAI, Anthropic Claude, Google Gemini, Ollama (local)
- API keys stored in database via `Dashboard.ExternalAPIKey`

## REST API

- Base: `http://localhost:8000/api/`
- Authentication: JWT via `djangorestframework-simplejwt`
- Permissions: custom role-based via `django-role-permissions`

## WebSocket (Channels)

- Endpoint: `ws://localhost:8000/ws/scan/{scan_id}/`
- Real-time scan progress updates
- Backed by Redis channel layer

## Logging

```python
from reNgine.utils.logger import get_module_logger, format_exception_for_log

logger = get_module_logger(__name__)

# Section-style (preferred for scan pipeline steps)
logger.log_line("[SCAN]", "START", "target %s" % target_id)
logger.log_line("[ERROR]", "FAIL", format_exception_for_log(exc), level="error", exc_info=True)

# Plain logging — always %s style for user-controlled data
logger.info("Activity done for scan %s", scan_id)
```

## Best Practices (summary)

- Security: validation, sanitisation, ORM parameterisation, XSS/CSRF protection
- Performance: `select_related`/`prefetch_related`, Redis caching, connection pooling
- Scalability: Go executor for tool subprocesses, Temporal for distributed task fan-out
- Maintainability: modular layout, structured logging, typed code, test coverage
