# r3ngine Project Schema

This document is a code-navigation map for contributors, code reviewers, and AI agents. It explains where major responsibilities live, how requests travel through the stack, and which files usually matter when a feature changes.

## System Snapshot

- Frontend: React + Vite + TypeScript + Material UI + React Query + React Router
- Backend: Django + Django REST Framework
- Primary orchestration: Temporal durable workflows
- Supporting execution: task wrappers in `web/reNgine/tasks.py` and activities in `web/reNgine/temporal_activities.py`
- Data stores: PostgreSQL for operational data, Neo4j for graph and attack-path relationships
- AI/LLM: provider abstraction in `web/reNgine/llm.py`, APME in `web/apme/`, impact generation in Tier 7

## Top-Level Repository Map

```text
r3ngine/
├── frontend/                 React application
├── web/                      Django project root
│   ├── api/                  DRF endpoints, serializers, view orchestration
│   ├── apme/                 Attack Path Modeling Engine domain code
│   ├── dashboard/            Admin/dashboard backend views and models
│   ├── plugins/              Plugin runtime and integrations
│   ├── reNgine/              Core orchestration, workflows, activities, tasks, utilities
│   ├── scanEngine/           Scan engine configuration models and presets
│   ├── startScan/            ScanHistory, SubScan, Endpoint, Subdomain, vuln persistence
│   ├── targetApp/            Domains, organizations, projects, monitoring targets
│   └── templates/            Django-rendered HTML templates
├── docker/                   Service images and runtime containers
├── documents/                Human and AI-oriented technical documentation
└── .github/workflows/        Architecture diagrams and GitHub automation
```

## Backend Ownership Map

| Area | Main location | What belongs there |
|------|---------------|--------------------|
| API entrypoints | `web/api/` | HTTP validation, serializer usage, workflow starts, response shaping |
| Scan orchestration | `web/reNgine/temporal_workflows.py` | Tier ordering, pause/resume, child workflows, finalization rules |
| Activity wrappers | `web/reNgine/temporal_activities.py` | Temporal activity definitions that bridge workflows to task functions |
| Scan task execution | `web/reNgine/tasks.py` | External tool execution, parsing, DB writes, scan-side business logic |
| LLM provider abstraction | `web/reNgine/llm.py` | Provider routing, prompt safety, impact/vuln/report generation |
| Graph sync and APME | `web/apme/` and Tier 7 activities | Neo4j sync, attack-path analysis, graph-assisted intelligence |
| Persistent scan models | `web/startScan/` | ScanHistory, SubScan, findings, correlation and execution metadata |
| Monitoring and schedules | `web/targetApp/` + Temporal schedule APIs | Domain monitoring and recurring scans |

## Frontend Ownership Map

| Area | Main location | Notes |
|------|---------------|-------|
| App shell and routing | `frontend/src/router.tsx` | Route tree and lazy page loading |
| Shared UI | `frontend/src/components/` | Cross-feature widgets, layout blocks, tables, shell tabs |
| Feature domains | `frontend/src/features/` | Preferred place for new product behavior |
| Feature API clients | `frontend/src/features/*/api/index.ts` | React Query hooks and request wiring |
| Page-level views | `frontend/src/pages/` | High-level screens and composition |
| Theme system | `frontend/src/theme/` and `frontend/src/context/ThemeContext.tsx` | Light/dark theme tokens and runtime switching |
| Generated API types | `frontend/src/types/api.ts` | Contract layer mapped from OpenAPI |

## Request-to-Execution Paths

### Full scan flow

1. Frontend triggers scan creation from a feature page.
2. `web/api/views.py` validates the request and calls `initiate_scan_temporal` in `web/reNgine/tasks.py`.
3. `initiate_scan_temporal` constructs workflow context and starts `MasterScanWorkflow`.
4. `MasterScanWorkflow` dispatches activities tier-by-tier through `web/reNgine/temporal_activities.py`.
5. Activities call task functions in `web/reNgine/tasks.py`, which run tools, parse output, and persist results.
6. Tier 7 performs correlation, CVE enrichment, risk scoring, AI impact generation, graph sync, and APME.
7. Frontend reads progress and results via scan/subscan/status endpoints.

### Subscan flow

1. Frontend launches a focused action such as `port_scan`, `fetch_url`, or `vulnerability_scan` for one subdomain.
2. API starts `SubScanWorkflow` with one or more requested task types.
3. The workflow groups requested tasks into the same tier model used by the master flow.
4. Finalization writes per-subscan terminal status even when one task fails.

### On-demand analysis flows

- `ApmeTaskWorkflow`: manual attack-path modeling from API/UI
- `StressTestWorkflow`: durable stress testing with kill switch support
- `HackerOneImportWorkflow` and `HackerOneSyncBookmarkedWorkflow`: bounty ingestion
- `ProxyFetchWorkflow`: background proxy acquisition and validation
- `IdentityEnrichmentWorkflow` and `GeoLocalizeWorkflow`: asynchronous enrichment side flows

## Temporal Workflow Inventory

| Workflow | Purpose | Main trigger |
|----------|---------|--------------|
| `MasterScanWorkflow` | Full 7-tier reconnaissance and assessment pipeline | New scan initiation |
| `NucleiPlannerWorkflow` | Child workflow for sequential vuln scanner stages | Tier 6 of full scan or subscan |
| `SubScanWorkflow` | Scoped task execution for one subdomain | Manual subscan action |
| `StressTestWorkflow` | Endpoint stress tooling with cancellation | Stress testing UI/API |
| `MonitoringWorkflow` | Recurring monitoring check | Temporal schedule |
| `ScheduledScanWorkflow` | Creates context then starts a full scan | Scheduled scan |
| `StartupSyncWorkflow` | Startup maintenance jobs | Orchestrator startup |
| `GoExecutorTaskWorkflow` | Routes heavy tool execution to Go worker queue | Task wrappers/utilities |
| `ApmeTaskWorkflow` | Manual APME execution | APME API |
| `IdentityEnrichmentWorkflow` | Names/emails OSINT enrichment | Enrichment API/tasks |
| `GeoLocalizeWorkflow` | IP geolocation enrichment | Async enrichment from scan tasks |
| `HackerOneImportWorkflow` | Program import | Bounty Hub API |
| `HackerOneSyncBookmarkedWorkflow` | Sync bookmarked programs | Bounty Hub API |
| `ProxyFetchWorkflow` | Proxy harvesting and validation | Proxy API |

## Master Scan Tier Model

For the exact up-to-date diagram, see `.github/workflows/temporal-scan-flow.md`.

| Tier | Responsibility | Important details |
|------|----------------|------------------|
| Step 0 | Target setup | `TargetProfilingActivity` and checkpoint compatibility stub |
| Tier 1 | Discovery | Includes `dns_security`, `osint`, `spiderfoot_scan`, and `baddns` path |
| Tier 2 | Endpoint discovery | `http_crawl`, `port_scan`, optional `vigolium_discovery`, then tier-2 plugins |
| Tier 3 | URL and visual capture | `fetch_url` and `screenshot` run in parallel |
| Tier 4 | Directory/file fuzzing | Depends on URLs prepared by earlier tiers |
| Tier 5 | Analysis | API discovery, WAF detection, secret scanning, optional `vigolium_analysis` |
| Tier 6 | Security assessment | `NucleiPlannerWorkflow` first, then `waf_bypass` and optional `vigolium_scan` |
| Tier 7 | Intelligence | Correlation -> CVE enrichment -> risk scoring -> impact generation -> graph sync -> APME |

## Data and State Boundaries

- `web/startScan/` owns scan execution state, findings, and per-run persistence.
- `web/scanEngine/` owns engine profiles and YAML-driven behavior toggles.
- `web/targetApp/` owns monitored domains, organizations, and schedule-linked targets.
- `web/apme/` and Neo4j integration own graph-side enrichment rather than raw scan ingestion.
- `frontend/src/features/` should stay the first stop for UI logic before shared component extraction.

## Change Impact Guide

| If you change... | Start here |
|------------------|-----------|
| Scan tier ordering or pause/resume behavior | `web/reNgine/temporal_workflows.py` |
| Tool execution or parsing | `web/reNgine/tasks.py` |
| Workflow-to-task bridge logic | `web/reNgine/temporal_activities.py` |
| API request/response contracts | `web/api/` and `frontend/src/types/api.ts` |
| Scan data models | `web/startScan/` and related serializers |
| APME or graph intelligence | `web/apme/`, Tier 7 activities, Neo4j sync code |
| Frontend feature behavior | matching folder in `frontend/src/features/` |
| Scheduled or monitoring behavior | `web/targetApp/`, `web/api/scheduled_scans.py`, workflow definitions |

## Known Architectural Notes

- Temporal is the primary durable orchestration layer; Celery-era assumptions are no longer a safe default when reading scan code.
- `MasterScanWorkflow` and `SubScanWorkflow` intentionally do not share identical Tier 7 behavior in every branch, so compare both before refactoring.
- The generated scan diagram image in `README.md` is a visual overview, but the Mermaid/text docs are the source of truth for code navigation.
- When in doubt, trace behavior in this order: API view -> workflow starter in `tasks.py` -> workflow -> activity -> task function -> model write.
