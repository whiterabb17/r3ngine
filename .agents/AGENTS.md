# AGENTS.md

## Purpose
Concise onboarding for AI agents working in this repository.

## Read First
1. `README.md`
2. `documents/README.md`
3. `documents/architecture-overview.md`
4. `documents/scan-pipeline.md`
5. `.github/workflows/temporal-scan-flow.md`

Optional local aid:
- `documents/PROJECT_SCHEMA.md` may exist in some worktrees as an untracked navigation note. Use it if present, but do not assume it exists in git.

## Mental Model
- `frontend/`: React + Vite + TypeScript UI
- `web/api/`: DRF API entrypoints
- `web/reNgine/temporal/workflows/`: durable orchestration
- `web/reNgine/temporal/activities/`: workflow-to-task bridge
- `web/reNgine/tasks/*`: tool execution, parsing, persistence
- `web/startScan/`: scan persistence and result models
- `web/apme/`: attack-path and graph intelligence

## Navigation Rules
- Prefer targeted reads over broad repo rescans.
- For orchestration changes, start in `web/reNgine/temporal/workflows/`.
- For tool execution or parsing changes, inspect `web/reNgine/tasks/*` and `web/reNgine/temporal/activities/`.
- For frontend changes, start in `frontend/src/features/` before shared components.
- When tracing behavior, use:
  `API view -> workflow starter in tasks modules -> workflow -> activity -> task function -> model write`

## Theme Rules
- Start theme work in `frontend/src/theme/`, `frontend/src/context/ThemeContext.tsx`, and the affected feature screen.
- Prefer `useThemeTokens()`, `useSemanticColors()`, and helpers from `frontend/src/theme/semanticColors.ts`.
- Use `getDialogPaperSx`, `getMenuPaperSx`, `getSurfaceSx`, and `getFieldSx` for shared surfaces and fields.
- Keep theme menus aligned with `selectableThemes`.
- Do not add new hardcoded UI colors outside the theme layer unless the value is intentionally data-driven or brand-specific.

## Practical Notes
- Temporal is the primary orchestration layer; do not assume Celery-era flow.
- Compare `MasterScanWorkflow` and `SubScanWorkflow` before refactoring shared scan behavior.
- Check for running containers to run tests. If local app services arent running check with the user if you can start containers otherwise run static checks such as TypeScript build, lint, and targeted Python compile/tests when validating changes.


# reNgine & Plugins: Temporal and Refactoring Guidelines

## Temporal Activity & Workflow Status Rules
- Whenever updating or defining scan activities, ensure all task status codes used (e.g., `SUCCESS_TASK`, `FAILED_TASK`, `RUNNING_TASK`, `ABORTED_TASK`) are explicitly imported from `reNgine.definitions`. Missing imports will cause workflow-killing `NameErrors`.
- Always use `TemporalClientProvider` from `reNgine.temporal_client` to obtain a Temporal client instance in Python:
  ```python
  from reNgine.temporal_client import TemporalClientProvider
  client = await TemporalClientProvider.get_client()
  ```
- Never use deprecated or removed wrappers such as `TemporalClient` from `reNgine.tasks` or `get_temporal_client_sync` from `reNgine.temporal_client`.

## Refactoring and Import Verification across Core and Plugins
- When performing structural refactorings in the core `reNgine` codebase (such as splitting files, relocating modules, or renaming helper classes/functions), always search and verify imports in both the core `web/` repository and the `r3ngine-plugins/` repository.
- Since plugins are maintained in a separate directory but run inside the core Django runtime context, outdated core imports in plugins will fail during runtime execution.

## Core Import Locations (Post-Restructuring)
- **Network/Extraction Utils:** General HTTP and subdomain extraction tools (`get_http_urls`, `sanitize_url`, `get_subdomain_from_url`) are strictly located in `reNgine.common_func`.
- **Scan Data Persistence & Process Wrappers:** Scan persistence helpers (`save_subdomain`, `save_endpoint`) and process execution wrappers (`run_command`, `stream_command`) are strictly located in `reNgine.utils.task`.
- **Avoid `reNgine.utilities` for these:** Do NOT attempt to import these functions from `reNgine.utilities` or incorrectly cross-import them, as they have been relocated.

## Background Tasks and Orchestration
- **CRITICAL**: This project relies **exclusively** on Temporal for background tasks and orchestration. **Celery is NOT used anymore in this project.** Never assume, suggest, or attempt to use Celery syntax, patterns, or terminology. All task logs and statuses are managed through Temporal workers.

## Vulnerability Parsing & Scan Engine Execution
- **Vigolium CLI Phase Gating**: In the Vigolium CLI, the `--only` flag explicitly dictates active phases and overrides `--skip`. To skip spidering or any other phase in Vigolium tasks, omit the phase name directly from the `--only` parameter (e.g., `--only discovery` instead of `--only spidering,discovery`) rather than combining `--skip spidering` with `--only`.
- **Nmap Vulners Parser**: Vulnerabilities are nested inside the indings list. CVE IDs must be explicitly extracted from this list by filtering for IDs starting with CVE- (e.g., [f['id'] for f in findings if f['id'].startswith('CVE-')]).
- **Nuclei Parser**: Nuclei JSON outputs use **hyphenated keys** in the info.classification dictionary (e.g., cve-id, cwe-id, cvss-score). Do not use underscore variants (cve_id) when parsing Nuclei outputs without falling back to the hyphenated version.
- **Nuclei Tag Splitting**: When  uto_update_templates is enabled, the 
uclei -update-templates command overwrites split templates on disk. To prevent breaking batch tags (like cve_1), the tag splitter script (docker/scripts/nuclei_tag_splitter.py) must be executed immediately *after* the template update and *before* the scan runs.

## Frontend UI (Vulnerabilities)
- **Grouping Logic**: In VulnerabilityTable.tsx, vulnerabilities are grouped by their name. For generic infrastructure issues that generate dozens of individual vulnerabilities (like TLS cipher weaknesses: TLS: cipher-*), group them dynamically by target/domain (e.g., TLS: Ciphers (domain.com)) to keep the table clean.
- **Frontend Build**: The UI is a React application located in the rontend directory. It uses Vite and can be built/verified using 
pm run build.

## Configuration & Scan Engines
- **Engine Toggles**: When adding new scanner tools or configuration flags, update both `web/full_yaml_config.yaml` (the reference) AND `web/fixtures/default_yaml_config.yaml`.
- **Default Engine Types**: r3ngine predefines default scan engines (like Comprehensive, Web API Discovery, etc.). If your new tools should be available in these defaults, you MUST also update the specific YAML files in `web/fixtures/scan_engines/`.
- **Database Fixtures**: When using `manage.py dumpdata` inside the Docker container from a Windows PowerShell host, avoid shell redirection (`>`), as PowerShell may corrupt the output to UTF-16. Instead, explicitly use the `-o` parameter (e.g., `python manage.py dumpdata --indent 2 -o web/scanEngine/fixtures/engine_types.json`).

## Git Practices
- **Committing Changes**: When asked to commit "the files you worked on", DO NOT use `git add -u` or `git add .`. Explicitly list the specific files that were modified for the specific task to prevent staging unrelated tracked changes.

## Frontend UI (General)
- **MUI Stack Component**: When using the `Stack` component from `@mui/material`, avoid passing `alignItems` directly as a prop, as it causes TypeScript compilation errors (`TS2769`). Always place it inside the `sx` prop instead (e.g., `<Stack sx={{ alignItems: 'center' }}>`).

## Reporting & Data Models
- **Directory Scans**: The `DirectoryScan` model does not contain file or URL details directly. It links to `DirectoryFile` objects via the `directory_files` ManyToMany field. When querying for actual discovered directory URLs on a subdomain, you must query the `DirectoryFile` model (e.g., `DirectoryFile.objects.filter(directory_files__directories__in=subdomains)`).
- **Report Generation Tasks**: `generate_report_task` in `reNgine.tasks.report` is a synchronous background task that expects a `report_id` (the ID of a `ScanReport` instance), NOT a `scan_id`. It is not a Temporal Activity.

## Local Execution & manage.py
- **CRITICAL**: Never run `python manage.py` (or any other Python backend script) directly on the local Windows host. 
- All Django utility commands (e.g., `check`, `flake8`, `makemigrations`, `migrate`, `dumpdata`, `test`) MUST be executed inside the `web` container using `docker compose exec web python manage.py <command>`.
- The local environment does not have the required Python dependencies, environment variables, or paths configured; all backend code evaluation must happen within the container context.
