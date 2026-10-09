"""Temporal task-queue names for the current process.

A remote worker host runs its own Python orchestrator and its own Go executor,
both named by ``WORKER_NAME`` (``docker/docker-compose.worker.yml``). Each
host's tool runs have to stay on that host: the Python task that parses a
tool's output reads it from the ``scan_results`` volume of the machine it
runs on, so the Go executor that wrote the output must be the co-located one.
The queue names therefore carry the worker name:

==================  ===========================  ===============================
process             master (``WORKER_NAME`` unset)  worker ``w1``
==================  ===========================  ===============================
Python orchestrator ``python-orchestrator-queue`` ``w1``
Go executor         ``go-executor-queue``          ``go-executor-queue-w1``
==================  ===========================  ===============================

The Python queue is the bare worker name because ``ScanWorker.task_queue`` is
set to the name at registration and the master starts a scan on that queue.
``web/executor/queue.go`` derives the Go name with the same rule and the same
worker-name charset; keep the two in step.

This is a leaf module: no Django, no Temporal imports. Workflow code must not
call it (it reads the environment); activities and task functions pass the
queue name into a workflow's input instead.
"""

import os
import re

PYTHON_ORCHESTRATOR_QUEUE = "python-orchestrator-queue"
GO_EXECUTOR_QUEUE = "go-executor-queue"

WORKER_NAME_ENV = "WORKER_NAME"

# A worker name is a Temporal task-queue name and a compose/CLI argument, so it
# is restricted to a shell- and URL-safe charset. Same pattern as
# ``workerNamePattern`` in ``web/executor/queue.go``.
WORKER_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$"
_WORKER_NAME_RE = re.compile(WORKER_NAME_PATTERN)


def validate_worker_name(name: str) -> str:
    """Return ``name`` if it is a valid worker name, else raise ``ValueError``."""
    if not isinstance(name, str) or not _WORKER_NAME_RE.match(name):
        raise ValueError(
            "invalid worker name %r: use 1-100 characters from A-Z, a-z, 0-9, "
            "'.', '_' and '-', starting with a letter or digit" % (name,)
        )
    return name


def get_worker_name() -> str:
    """Return this process's worker name from ``WORKER_NAME``, or '' on the master.

    Raises ``ValueError`` when the variable is set to an invalid name, so a
    misconfigured worker fails at startup rather than routing to a queue nobody
    polls.
    """
    name = os.environ.get(WORKER_NAME_ENV, "").strip()
    return validate_worker_name(name) if name else ""


def configure_worker_name(flag_value: str | None) -> str:
    """Resolve the worker name for a worker process and export it to ``WORKER_NAME``.

    The command-line value wins over the environment (the Go executor applies
    the same precedence). Exporting it makes :func:`get_worker_name` — and so
    every routing decision taken later in this process — agree with the queue
    the worker actually polls. Returns '' for the master.
    """
    name = (flag_value or "").strip()
    if name:
        validate_worker_name(name)
        os.environ[WORKER_NAME_ENV] = name
        return name
    return get_worker_name()


def python_orchestrator_queue(worker_name: str | None = None) -> str:
    """Python task queue for ``worker_name`` (default: this process's worker)."""
    name = get_worker_name() if worker_name is None else worker_name
    return name or PYTHON_ORCHESTRATOR_QUEUE


def go_executor_queue(worker_name: str | None = None) -> str:
    """Go executor task queue for ``worker_name`` (default: this process's worker)."""
    name = get_worker_name() if worker_name is None else worker_name
    return f"{GO_EXECUTOR_QUEUE}-{name}" if name else GO_EXECUTOR_QUEUE
