---
name: r3ngine-context
description: Provides the r3ngine project technology stack, architecture, and conventions. Use when contributing to r3ngine, implementing features, debugging scans, or when the user asks about the stack, Django, Temporal, Neo4j, React, PostgreSQL, security tools, or the codebase structure.
---

# r3ngine Context

Project context and technology stack for the r3ngine v3 web reconnaissance and vulnerability scanning platform.

## When to Use

- Contributing code, fixing bugs, or adding features in this repository
- User asks about the stack, frameworks, or how the app is built
- Implementing or modifying scans, targets, API, or UI
- Need to know which versions are in use (Django 5.2.3 LTS, Python 3.12, Temporal 1.7.0, React 18+)
- Debugging Temporal workflow failures or scan pipeline issues
- Implementing CPDE (Custom Parameter Discovery Engine) or APME (Attack Path Modeling Engine) features

## Stack Summary

| Layer        | Technology |
|-------------|------------|
| Backend     | Django 5.2.3 LTS, Python 3.12 |
| DB (primary)| PostgreSQL |
| DB (graph)  | Neo4j (APME — Attack Path Modeling Engine; `web/apme/` Django app) |
| Cache/Broker| Redis (Channels, task state, caching) |
| Orchestration | Temporal (Python SDK 1.7.0 + Go executor) |
| Frontend    | React 18+, TypeScript, Vite |
| Async comms | Django Channels + WebSockets |
| Containers  | Docker multi-stage + Docker Compose |
| Quality     | flake8, black, type hints, tests in `web/tests/` |

- **Paths**: App code under `web/`; frontend under `frontend/`.
- **API**: Django REST Framework + JWT auth; `ws://localhost:8000/ws/scan/{scan_id}/` for WebSocket.
- **Temporal UI**: `http://localhost:8080` — workflow history, signals, replay, cancellation.
- **Logging**: `get_module_logger(__name__)` from `reNgine.utils.logger`; use `log_line(prefix, action, msg)` for structured output; `format_exception_for_log(exc)` for safe exception text; `%`-style formatting for user-controlled data in plain log calls.
- **Container name**: `r3ngine-web-1` (use `python3` not `python` inside the container).
- **Frontend build**: Run `npm run build` locally in `frontend/` (NOT inside the container).

## Scan Pipeline (7-Tier Architecture)

| Tier | Purpose |
|------|---------|
| 0 | Target profiling & context enrichment |
| 1 | Subdomain discovery, intel gathering, firewall detection |
| 2 | HTTP crawl, port scanning, screenshotting, URL fetching |
| 3–4 | Directory/file fuzzing (ffuf, dirsearch, katana) |
| 5 | Web API discovery, WAF detection, secret scanning, CPDE (Custom Parameter Discovery Engine) |
| 6 | Vulnerability scanning (Nuclei), WAF bypass, credential brute force |
| 7 | Vulnerability correlation, risk scoring, Neo4j/APME sync, reporting |

Scan entry point: `initiate_scan_temporal()` in `tasks/scan_init.py` → starts `MasterScanWorkflow`.
Import: `from reNgine.tasks import initiate_scan_temporal` (shim) or `from reNgine.tasks.scan_init import initiate_scan_temporal` (direct).

## Key Intelligence Engines

- **APME** (Attack Path Modeling Engine): `web/apme/` Django app — Neo4j-based graph for feasible attack route discovery; orchestration via `apme/orchestrator.py`, engine in `apme/engine/`, graph ops in `apme/graph/`.
- **CPDE** (Custom Parameter Discovery Engine): `web/reNgine/cpde/` — discovers injectable parameters via custom fuzzing; complementary to ffuf/dirsearch at Tier 5.
- **ERL** (Exploitation Readiness Layer): safe, non-destructive validation layer for confirmed vulns.
- **Vigolium**: `web/reNgine/vigolium_tasks.py` — integrated static code scanner dispatched via `CodeScanWorkflow`.

## Key Conventions (from project rules)

- Code and comments in English; SOLID, KISS, DRY.
- Type hints on all new Python code; TypeScript types on all new frontend code.
- Tests for every change; `django.test.TestCase`; anonymise test data.
- Private methods at the bottom of the file.
- No path constructed from user input without validation (resolve + bounds-check).
- No raw exception messages returned to the client.
- `temporal/workflows/__init__.py` must stay deterministic — no DB calls, no I/O, no `datetime.now()`.
- All scanning logic belongs in `temporal/activities/__init__.py` or the Go executor.
- When mocking extracted modules, patch at the **new module path** (e.g. `reNgine.tasks.vuln.stream_command`), not the shim.
- Run tests inside Docker: `docker exec r3ngine-web-1 bash -c "cd /usr/src/app && python3 manage.py test --keepdb --verbosity=2 2>&1 | tail -20"`

## Temporal Quick Reference

- Workflows (deterministic): `web/reNgine/temporal/workflows/__init__.py`
- Activities (side-effecting): `web/reNgine/temporal/activities/__init__.py`
- Shims (backward-compatible): `temporal_workflows.py`, `temporal_activities.py` — re-export from packages above
- Client (start/cancel from Django): `web/reNgine/temporal_client.py`
- Go executor (subprocess tools): `web/executor/main.go` on `go-executor-queue`

## Tasks Package Quick Reference

`from reNgine.tasks import X` works for all names (shim). Direct imports:
- Scan init / scan lifecycle: `reNgine.tasks.scan_init`
- Subdomain discovery: `reNgine.tasks.subdomain`
- HTTP crawl / URL fetch / web API: `reNgine.tasks.crawl`
- Vulnerability scanning (nuclei/dalfox/crlfuzz): `reNgine.tasks.vuln`
- OSINT / dorking / spiderfoot: `reNgine.tasks.osint`
- Port scan / nmap / SSL: `reNgine.tasks.port_scan`
- Endpoint / IP persistence: `reNgine.tasks.persistence`
- Notifications: `reNgine.tasks.notifications`
- Geo / WHOIS: `reNgine.tasks.geo`
- LLM / GPT reports: `reNgine.tasks.llm`
- WAF detection/bypass: `reNgine.tasks.waf`
- Screenshot: `reNgine.tasks.screenshot`
- Result parsers: `reNgine.tasks.parsers`
- Proxy fetch: `reNgine.tasks.proxies`
- Acunetix integration: `reNgine.tasks.acunetix`

## API Views Quick Reference

`from api.views import X` works for all names (shim). Direct imports:
- Scan actions (InitiateScan, StopScan, etc.): `api.views.scan`
- Target management: `api.views.targets`
- Vulnerabilities: `api.views.vulns`
- Recon / OSINT: `api.views.recon`
- LLM endpoints: `api.views.llm`
- Tool management: `api.views.tools`
- Settings / proxy / SOC: `api.views.settings`
- Notifications: `api.views.notifications`
- Workers: `api.views.workers`

## Additional Reference

- Full stack and modules: [reference.md](reference.md)
- Security tools (recon, fuzzers, vuln scanners): [references/tools.md](references/tools.md)
