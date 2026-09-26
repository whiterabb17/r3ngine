# CLAUDE.md
## Current version: 3.7.6

Start with:
1. `README.md`
2. `documents/README.md`
3. `documents/architecture-overview.md`
4. `documents/scan-pipeline.md`
5. `.github/workflows/temporal-scan-flow.md`

Optional local note:
- `documents/PROJECT_SCHEMA.md` can exist as a local untracked project map. Use it if present, but do not rely on it as a tracked source of truth.

## Goal
Build a fast, accurate mental model without rescanning the whole repository.

## Key Facts
- `frontend/`: UI
- `web/api/`: HTTP API; views split into `web/api/views/` domain modules (scan, targets, vulns, recon, llm, tools, settings, etc.)
- `web/reNgine/temporal/workflows/__init__.py`: orchestration (shim: `web/reNgine/temporal_workflows.py`)
- `web/reNgine/temporal/activities/__init__.py`: workflow bridge (shim: `web/reNgine/temporal_activities.py`)
- `web/reNgine/tasks/`: task execution package — domain modules: `scan_init`, `subdomain`, `crawl`, `vuln`, `osint`, `port_scan`, `persistence`, `notifications`, `geo`, `llm`, `waf`, `screenshot`, `parsers`, `acunetix`, `proxies` (shim: `web/reNgine/tasks/__init__.py`)
- `web/startScan/`: persistence
- `web/apme/`: graph and attack-path logic
- `docker/`: compose files and the multi-stage `web/Dockerfile` (the frontend bundle is built there, not in the running container) — drive them with the Makefile: `make up`, `make build-web`, `make restart-apps`, `make migrate`, `make logs`

## Working Heuristic
Trace behavior as:
`API view -> workflow starter -> workflow -> activity -> task function -> model write`

## Theme Guidance
- Prefer `useThemeTokens()`, `useSemanticColors()`, and `frontend/src/theme/semanticColors.ts`.
- Keep theme selectors aligned through `selectableThemes`.
- Reuse shared theme helpers for dialogs, menus, cards, and form fields.
- Avoid introducing new hardcoded UI colors outside `frontend/src/theme/`.

## Validation
- Prefer targeted checks over assuming the full stack can start.
- Good defaults: `npx tsc -b`, `npm run lint`, targeted Django tests, and `python3 -m py_compile` for touched backend modules.
- Run `tsc`/`npm` locally in `frontend/`, never inside `r3ngine-web-1` — `node_modules` there is masked by an anonymous volume.
- Django tests need the container: `docker exec r3ngine-web-1 bash -c "cd /usr/src/app && python3 manage.py test <module> --keepdb --verbosity=2"`.
