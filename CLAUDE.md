# CLAUDE.md
## Current version: 3.7.8

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
- `web/api/`: HTTP API; views in `web/api/views/` domain modules (scan, scan_status, targets, subdomains, endpoints, vulns, recon, notes, llm, tools, settings, etc.), serializers in the `web/api/serializers/` package
- `web/reNgine/temporal/workflows/`: orchestration — flat modules `_common` (retry presets, shared helpers), `master_scan`, `subscan`, `stress`, `jobs`, `recon`, `assessment_workflow`; `__init__.py` re-exports (shim: `web/reNgine/temporal_workflows.py`)
- `web/reNgine/temporal/activities/`: workflow bridge — `core` (`_run_task`, `TemporalTaskProxy`, cancellation), `scan_lifecycle`, `discovery`, `enumeration`, `vuln_scan`, `post_processing`, `intel`, `proxies`, `maintenance`, `plugin_auth`, `stress`, plus assessment/graph/evidence/followups modules; `__init__.py` re-exports (shim: `web/reNgine/temporal_activities.py`)
- `web/reNgine/common_func/`: shared helpers package (db queries, proxies, notifications, url utils, …); `__init__.py` keeps the old star-import surface
- `web/reNgine/tasks/`: task execution package (`osint/` and `crawl/` are sub-packages) — domain modules: `scan_init`, `subdomain`, `crawl`, `vuln`, `osint`, `port_scan`, `persistence`, `notifications`, `geo`, `llm`, `waf`, `screenshot`, `parsers`, `acunetix`, `proxies` (shim: `web/reNgine/tasks/__init__.py`)
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
- Good defaults: `npx tsc -b`, `npm run lint`, `npm test`, targeted Django tests, and `python3 -m py_compile` for touched backend modules.
- Run `tsc`/`npm` locally in `frontend/`, never inside `r3ngine-web-1` — `node_modules` there is masked by an anonymous volume.
- ESLint violations that predate CI are baselined in `frontend/eslint-suppressions.json`; only new ones fail. After fixing some, run `npx eslint . --prune-suppressions`.
- Django tests need the container: `docker exec r3ngine-web-1 bash -c "cd /usr/src/app && python3 manage.py test <module> --keepdb --verbosity=2"`.
- Without the stack, any Postgres on 127.0.0.1:5432 (user/password/db `rengine`) works: `cd web && DJANGO_SETTINGS_MODULE=reNgine.settings_test_local python manage.py test tests --exclude-tag=integration`. Tests tagged `integration` need live network, real tool binaries or the docker stack.
- CI (`.github/workflows/ci.yml`) runs all of the above on every push; the full image build is manual (`docker-image.yml`).
