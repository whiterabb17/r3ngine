# Compatibility shim — preserved so existing callers (utils/task.py, tasks/__init__.py,
# run_temporal_orchestrator.py, test files) continue to resolve without changes.
# New code should import from reNgine.temporal.activities directly.
from reNgine.temporal.activities import *
from reNgine.temporal.activities import (
    TemporalTaskProxy,
    _run_task,
    _PERMITTED_GENERIC_TASKS,
)