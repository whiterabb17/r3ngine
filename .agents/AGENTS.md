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
