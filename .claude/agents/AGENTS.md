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
- Local app services may not start reliably in every workspace. Prefer static checks such as TypeScript build, lint, and targeted Python compile/tests when validating changes.
