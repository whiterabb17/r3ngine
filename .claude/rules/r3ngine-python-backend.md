---
description: Python and Django backend coding conventions for r3ngine — services, views, tasks, Temporal activities, and error handling.
---

# r3ngine – Python backend conventions

## Scope

Apply these guidelines when working on Python/Django backend code in `web/` (views, serializers, task functions, Temporal activities, management commands).

## Architecture and layering

Organise modules to avoid circular dependencies:

- Leaf modules (e.g. `definitions.py`, `common_func.py`, `utils/`) sit at the bottom.
- Core business logic (task functions in `reNgine/tasks/` package, activity implementations in `reNgine/temporal/activities/`, graph utilities in `graph_utils.py`) sits in the middle.
- Orchestration layers (`reNgine/temporal/workflows/`, HTTP views in `api/views/`, Django Channels consumers) sit at the top.

**Temporal-specific**: `temporal/workflows/__init__.py` must remain a thin orchestrator — no scanning logic, no DB calls, no I/O. All side-effecting work belongs in `temporal/activities/__init__.py` or the Go executor. See `r3ngine-temporal.md` for determinism rules.

**Shims**: `temporal_workflows.py` and `temporal_activities.py` are backward-compatible shims (`from reNgine.temporal.* import *`). New code should import directly from the package paths.

## Python code style

- Prefer simple, explicit code following KISS, DRY and SOLID.
- Use type hints on all new functions and class methods.
- Prefer f-strings for string formatting (exception: log messages with user-controlled data — see `r3ngine-security.md` Rule 2.1).
- Replace nested `if` chains with combined conditions when it improves readability.
- Avoid temporary variables that are immediately returned.
- Raise specific exceptions instead of generic `Exception` / `BaseException`.
- Place private methods at the bottom of the file.

### Example — simplify control flow

```python
# ❌ Before
if not user.is_active:
    return
if user.is_admin:
    do_admin_action(user)

# ✅ After
if user.is_active and user.is_admin:
    do_admin_action(user)
```

## Logging

There are **two** logging patterns in this codebase. Use the right one based on where the code lives.

### Pattern 1 — Scan task modules (tasks/ package, *_tasks.py, common_func.py, etc.)

Use the standard `logging.getLogger(__name__)`. The `task` log handler in `settings.py` automatically formats output as:

```
module.funcName                    | INFO    | message
```

```python
import logging

logger = logging.getLogger(__name__)

# ✅ Always use %s style — never f-strings with externally-controlled data
logger.info("Starting port scan for %s", target)
logger.warning("Proxy %s validation failed", proxy_name)
logger.error("Nmap command shlex split failed: %s", e)

# ❌ Never — f-string with user/DB/exception data
logger.info(f"Scanning {domain_name}")
logger.error(f"Failed: {e}")
```

All modules under `reNgine.*` are routed to the `task` handler via the catch-all entry in `settings.py` — **no extra registration needed** for new task files under `web/reNgine/`. The `task` handler is also a `StreamHandler` so output goes to stdout; Docker logs include timestamps automatically.

### Pattern 2 — Temporal activities (temporal/activities/__init__.py)

Use `get_module_logger` from `reNgine.utils.logger` for structured section-style logging. This routes to `temporal.log` in addition to stdout:

```python
from reNgine.utils.logger import get_module_logger, format_exception_for_log

logger = get_module_logger(__name__)

# ✅ Section-style log with grep-filterable prefix
logger.log_line("[SCAN]", "START", "beginning port scan for %s" % target_id)
logger.log_line("[FUZZING]", "RESULT", "found %d paths" % count, level="info")
logger.log_line("[NUCLEI]", "ERROR", format_exception_for_log(exc), level="error", exc_info=True)

# ✅ Plain calls also work for simple messages
logger.info("Activity completed for scan %s", scan_id)
```

Use `format_exception_for_log(exc)` to produce a safe `"ExcType: message"` string for log output. Never pass `str(exc)` directly into f-strings in log messages — use `%s` formatting (see security Rule 2.1).

**Section prefixes in use** (grep-filterable in Docker logs):
`[SCAN]`, `[SUBSCAN]`, `[FUZZING]`, `[NUCLEI]`, `[PORT_SCAN]`, `[HTTP_CRAWL]`, `[OSINT]`, `[TEMPORAL]`, `[NEO4J]`, `[LLM]`

### Log format reference

| Context | Logger init | Output format | Settings handler |
|---------|-------------|---------------|-----------------|
| Scan tasks (`tasks/` package, `*_tasks.py`, `common_func.py`) | `logging.getLogger(__name__)` | `module.funcName \| LEVEL \| message` | `reNgine` catch-all → `task` |
| Temporal activities (`temporal/activities/__init__.py`) | `get_module_logger(__name__)` | `[PREFIX] ACTION \| message` | `reNgine.temporal.activities` → `temporal_file` |
| Plugins (`plugins_data.*`) | `logging.getLogger(__name__)` | `module.funcName \| LEVEL \| message` | `plugins` → `task` |

## Django ORM

- Use `select_related` / `prefetch_related` to avoid N+1 queries.
- Never access ORM in a Temporal workflow (workflows are deterministic; DB calls are activities).
- Wrap bulk writes in `transaction.atomic()` where consistency matters.

## General backend practices

- Keep all code and comments in English.
- Do not describe the refactor in comments; only explain non-obvious intent.
- Do not make radical changes without explicit discussion.
- Do not add new dependencies without approval.
- All tests must run inside the Docker container (see `r3ngine-tests.md`).