"""Resolve and probe scan tools where they are installed.

Entrypoint-installed binaries (kr, trufflehog, …) live on the Temporal worker
containers, which run from the same image as ``web`` but finish installing
tools in their entrypoints. The probes therefore run *inside* a worker:

* In the Python orchestrator (``R3NGINE_WORKER_ROLE`` is set by
  ``run_temporal_orchestrator``) every function here works locally with
  ``shutil.which`` and ``subprocess``.
* Anywhere else (the web container, a management command) the same call is
  sent to the orchestrator as a ``ToolProbeWorkflow`` on the Python task queue
  and the worker answers with what it found. No Docker socket is involved.

Paths found on a worker are stored encoded as ``<role>:<path>``
(``python:/usr/local/bin/kr``) so a later sync knows which side reported them.
The ``go`` role stays decodable for rows written before the Go executor shared
the orchestrator's image; both roles are probed by the orchestrator today.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import socket
import subprocess
import uuid
from datetime import timedelta
from typing import Any, Optional

from reNgine.utils.task_queues import PYTHON_ORCHESTRATOR_QUEUE

logger = logging.getLogger(__name__)

WORKER_ROLE_ENV = 'R3NGINE_WORKER_ROLE'
DEFAULT_LOCAL_ROLE = 'python'
WORKER_ROLES: tuple[str, ...] = ('go', 'python')

TOOL_PROBE_WORKFLOW = 'ToolProbeWorkflow'
TOOL_PROBE_ACTIVITY = 'ToolProbeActivity'

# Dirs searched when `command -v` misses (venv / github clones).
_REMOTE_PATH_DIRS: tuple[str, ...] = (
    '/usr/local/bin',
    '/usr/bin',
    '/go/bin',
    '/root/go/bin',
    '/root/.local/bin',
    '/usr/src/github/theHarvester/.venv/bin',
    '/usr/src/github/theHarvester/bin',
)

_HELP_FLAGS: tuple[str, ...] = ('--help', '-h', 'help')
_HELP_TIMEOUT_SEC = float(os.environ.get('R3NGINE_TOOL_HELP_TIMEOUT', '20') or 20)
_VERSION_TIMEOUT_SEC = 15.0

# A whole inventory sync runs dozens of version probes; the workflow bound
# covers that plus a slow worker pick-up.
_DISPATCH_TIMEOUT_SEC = {
    'resolve': 60.0,
    'version': 60.0,
    'help': 180.0,
    'summary': 30.0,
    'sync': 900.0,
}

# Cobra/clap CLIs where root --help is only a command index; probe the
# subcommand(s) the scan pipeline actually invokes.
_HELP_SUBCOMMANDS: dict[str, tuple[str, ...]] = {
    'kiterunner': ('scan',),
    'kr': ('scan',),
    'dalfox': ('scan',),
}

# Short-lived process cache: (role preference, candidate tuple) → resolve result.
_resolve_cache: dict[tuple[Any, ...], Optional[dict[str, str]]] = {}


class ToolProbeError(RuntimeError):
    """The orchestrator could not be reached to run a probe."""


def clear_resolve_cache() -> None:
    _resolve_cache.clear()


def help_subcommands_for(tool_name: str) -> tuple[str, ...]:
    key = (tool_name or '').strip().lower()
    return _HELP_SUBCOMMANDS.get(key, ())


def local_role() -> Optional[str]:
    """Worker role of this process, or None when it is not a tool host."""
    role = (os.environ.get(WORKER_ROLE_ENV) or '').strip().lower()
    return role or None


def probe_is_local() -> bool:
    return local_role() is not None


def encode_worker_path(role: str, path: str) -> str:
    return f'{role}:{path}'


def decode_worker_path(value: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Parse `go:/usr/local/bin/kr` → ('go', '/usr/local/bin/kr'). Plain paths → (None, path)."""
    if not value:
        return None, None
    text = str(value).strip()
    if text.startswith(tuple(f'{role}:' for role in WORKER_ROLES)):
        role, _, path = text.partition(':')
        return role, path or None
    return None, text


def prefer_roles_for_tool(tool_name: str) -> tuple[str, ...]:
    """Role order for a tool. One worker answers today; kept for callers and rows."""
    key = (tool_name or '').strip().lower()
    pythonish = {
        'theharvester', 'wafw00f', 'arjun', 'semgrep', 'wpscan', 'sqlmap',
        'dirsearch', 'linkfinder', 'paramspider', 'holehe', 'maigret',
        'bbot', 'xnldorker', 'postleaksng', 'porch-pirate',
    }
    if key in pythonish or 'harvest' in key:
        return ('python', 'go')
    return ('go', 'python')


# ---------------------------------------------------------------------------
# Local implementation — runs on the worker that has the tools
# ---------------------------------------------------------------------------

def _probe_env() -> dict[str, str]:
    return {
        **os.environ,
        'PATH': os.pathsep.join([*_REMOTE_PATH_DIRS, os.environ.get('PATH', ''), '/usr/sbin', '/sbin', '/bin']),
    }


def _run_local(argv: list[str], *, timeout: float) -> tuple[int, str]:
    """Run argv here; return (exit_code, combined stdout+stderr).

    A run that could not produce output (missing binary, timeout, OS error)
    yields empty text and a conventional exit code, so callers never mistake
    the failure reason for tool output.
    """
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            env=_probe_env(),
        )
        return proc.returncode, (proc.stdout or '') + '\n' + (proc.stderr or '')
    except FileNotFoundError:
        return 127, ''
    except subprocess.TimeoutExpired:
        logger.debug('local exec %s timed out after %ss', argv[:2], timeout)
        return 124, ''
    except Exception as exc:
        logger.debug('local exec %s failed: %s', argv[:2], exc)
        return 1, ''


def _is_executable(path: str) -> bool:
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


def which_local(candidates: list[str]) -> Optional[str]:
    """Absolute path of the first candidate executable on this host."""
    search_path = _probe_env()['PATH']
    for candidate in candidates:
        if not candidate:
            continue
        found = shutil.which(candidate, path=search_path)
        if found and _is_executable(found):
            return found
        for directory in _REMOTE_PATH_DIRS:
            probe = os.path.join(directory, candidate)
            if _is_executable(probe):
                return probe
        # Case-insensitive scan of key dirs (theHarvester vs theharvester).
        lowered = candidate.lower()
        for directory in _REMOTE_PATH_DIRS:
            try:
                names = os.listdir(directory)
            except OSError:
                continue
            for name in names:
                full = os.path.join(directory, name)
                if name.lower() == lowered and _is_executable(full):
                    return full
    return None


def _help_looks_substantive(text: str) -> bool:
    """True when help text exposes more than a cobra/clap command index."""
    lower = (text or '').lower()
    if (
        ('available commands:' in lower or '\ncommands:' in lower or lower.startswith('commands:'))
        and lower.count('--') < 10
    ):
        return False
    return lower.count('--') >= 5 or 'flags:' in lower or 'options:' in lower


def help_on_path_local(
    path: str,
    *,
    timeout: float = _HELP_TIMEOUT_SEC,
    subcommands: tuple[str, ...] = (),
) -> tuple[str, str]:
    """Return (help_text, flag_used) for a binary on this host."""
    # Prefer pipeline subcommands (e.g. `kr scan --help`) before thin root help.
    ordered_subs = list(subcommands)
    if 'scan' not in ordered_subs:
        ordered_subs.append('scan')

    best_root = ('', '')
    for sub in ordered_subs:
        for flag in ('--help', '-h'):
            _, text = _run_local([path, sub, flag], timeout=timeout)
            if text.strip() and _help_looks_substantive(text):
                return text, f'{sub} {flag}'

    for flag in _HELP_FLAGS:
        _, text = _run_local([path, flag], timeout=timeout)
        if text.strip() and _help_looks_substantive(text):
            return text, flag
        if text.strip() and not best_root[0]:
            best_root = (text, flag)
    return best_root


def version_argv(path: str, version_lookup_command: Optional[str]) -> list[str]:
    """argv for a version probe: the configured command re-anchored on ``path``."""
    parts = (version_lookup_command or '').strip().split()
    if not parts:
        return [path, '--version']
    first = parts[0]
    base = os.path.basename(path.rstrip('/'))
    if first == base or os.path.basename(first) == base:
        return [path, *parts[1:]]
    if first.startswith('/'):
        return parts
    return [path, *parts[1:]] if len(parts) > 1 else [path, '--version']


def _resolve_local(candidates: list[str]) -> Optional[dict[str, str]]:
    path = which_local(candidates)
    if not path:
        return None
    return {
        'role': local_role() or DEFAULT_LOCAL_ROLE,
        'container': socket.gethostname(),
        'path': path,
    }


def _version_local(path: str, version_lookup_command: Optional[str]) -> tuple[str, Optional[str]]:
    if not _is_executable(path):
        return '', f'{path} is not present on this worker'
    code, text = _run_local(version_argv(path, version_lookup_command), timeout=_VERSION_TIMEOUT_SEC)
    if not text.strip():
        return '', f'empty version output (exit {code})'
    return text, None


def _help_local(
    tool_name: str,
    candidates: list[str],
    encoded_path: Optional[str],
    timeout: float,
) -> tuple[str, str, Optional[str]]:
    role = local_role() or DEFAULT_LOCAL_ROLE
    subcommands = help_subcommands_for(tool_name)
    _, hinted = decode_worker_path(encoded_path)
    paths: list[str] = []
    if hinted and _is_executable(hinted):
        paths.append(hinted)
    # Always allow rediscovery in case the stored path went stale.
    located = which_local(candidates)
    if located and located not in paths:
        paths.append(located)
    for path in paths:
        text, flag = help_on_path_local(path, timeout=timeout, subcommands=subcommands)
        if text.strip():
            return text, flag, encode_worker_path(role, path)
    return '', '', None


def _summary_local() -> dict[str, Any]:
    role = local_role() or DEFAULT_LOCAL_ROLE
    return {
        'mode': 'local',
        'role': role,
        'workers': [{'role': role, 'name': socket.gethostname()}],
    }


def run_probe_op(op: str, payload: Optional[dict] = None) -> dict[str, Any]:
    """Execute one probe operation on this host. Body of ``ToolProbeActivity``.

    Ops: ``resolve`` {candidates}, ``version`` {path, version_lookup_command},
    ``help`` {tool_name, candidates, encoded_path, timeout}, ``summary`` {},
    ``sync`` {probe_versions}. Every result is JSON-serialisable.
    """
    payload = payload or {}
    if op == 'resolve':
        return {'found': _resolve_local(list(payload.get('candidates') or []))}
    if op == 'version':
        text, error = _version_local(str(payload.get('path') or ''), payload.get('version_lookup_command'))
        return {'output': text, 'error': error}
    if op == 'help':
        text, flag, encoded = _help_local(
            str(payload.get('tool_name') or ''),
            list(payload.get('candidates') or []),
            payload.get('encoded_path'),
            float(payload.get('timeout') or _HELP_TIMEOUT_SEC),
        )
        return {'help_text': text, 'flag': flag, 'encoded_path': encoded}
    if op == 'summary':
        return _summary_local()
    if op == 'sync':
        from reNgine.tool_inventory import sync_installed_tools
        return sync_installed_tools(probe_versions=bool(payload.get('probe_versions', True)))
    raise ValueError(f'unknown tool probe op {op!r}')


# ---------------------------------------------------------------------------
# Remote dispatch — from web to the orchestrator over Temporal
# ---------------------------------------------------------------------------

def dispatch_probe(op: str, payload: Optional[dict] = None) -> dict[str, Any]:
    """Run ``op`` on the Python orchestrator and return its result.

    Raises ``ToolProbeError`` when Temporal or the worker cannot answer, so
    callers can fall back to whatever this host knows.
    """
    from reNgine.temporal_client import TemporalClientProvider, run_and_close

    timeout = _DISPATCH_TIMEOUT_SEC.get(op, 120.0)

    async def _execute():
        client = await TemporalClientProvider.get_client()
        return await client.execute_workflow(
            TOOL_PROBE_WORKFLOW,
            args=[op, payload or {}],
            id=f'tool-probe-{op}-{uuid.uuid4().hex[:12]}',
            task_queue=PYTHON_ORCHESTRATOR_QUEUE,
            execution_timeout=timedelta(seconds=timeout),
        )

    try:
        result = run_and_close(asyncio.new_event_loop(), _execute())
    except Exception as exc:
        logger.warning('tool probe %s could not run on the orchestrator: %s', op, exc)
        raise ToolProbeError(f'tool probe {op} failed') from exc
    if not isinstance(result, dict):
        raise ToolProbeError(f'tool probe {op} returned {type(result).__name__}')
    return result


# ---------------------------------------------------------------------------
# Public API used by tool_inventory / tool_args
# ---------------------------------------------------------------------------

def resolve_on_workers(
    tool_name: str,
    candidates: list[str],
    *,
    prefer_roles: Optional[tuple[str, ...]] = None,
) -> Optional[dict[str, str]]:
    """Find tool_name on the tool host. Returns {role, container, path} or None."""
    order = prefer_roles or WORKER_ROLES
    cache_key = (tuple(order), tuple(c for c in candidates if c))
    if cache_key in _resolve_cache:
        return _resolve_cache[cache_key]

    found: Optional[dict[str, str]]
    if probe_is_local():
        found = _resolve_local(candidates)
    else:
        try:
            found = dispatch_probe('resolve', {'candidates': candidates}).get('found') or None
        except ToolProbeError:
            # Not an answer: leave the cache alone so the next call retries.
            return None
    _resolve_cache[cache_key] = found
    return found


def run_help_on_workers(
    *,
    tool_name: str,
    candidates: list[str],
    encoded_path: Optional[str] = None,
    timeout: float = _HELP_TIMEOUT_SEC,
) -> tuple[str, str, Optional[str]]:
    """Run --help/-h on the tool host. Returns (help_text, flag_used, encoded_worker_path)."""
    if probe_is_local():
        return _help_local(tool_name, candidates, encoded_path, timeout)
    try:
        result = dispatch_probe('help', {
            'tool_name': tool_name,
            'candidates': candidates,
            'encoded_path': encoded_path,
            'timeout': timeout,
        })
    except ToolProbeError:
        return '', '', None
    return (
        str(result.get('help_text') or ''),
        str(result.get('flag') or ''),
        result.get('encoded_path') or None,
    )


def run_version_on_workers(
    *,
    role: str,
    path: str,
    version_lookup_command: Optional[str] = None,
) -> tuple[str, Optional[str]]:
    """Return (combined_output, error) of the version probe for an encoded path."""
    if role not in WORKER_ROLES:
        return '', f'unknown worker role {role!r}'
    if probe_is_local():
        return _version_local(path, version_lookup_command)
    try:
        result = dispatch_probe('version', {'path': path, 'version_lookup_command': version_lookup_command})
    except ToolProbeError as exc:
        return '', str(exc)
    return str(result.get('output') or ''), result.get('error')


def worker_probe_summary() -> dict[str, Any]:
    """Where probes run: ``mode`` is 'local' on a worker, 'remote' when the
    orchestrator answered, 'unavailable' when it could not be reached."""
    if probe_is_local():
        return _summary_local()
    try:
        result = dispatch_probe('summary')
    except ToolProbeError:
        return {'mode': 'unavailable', 'role': None, 'workers': []}
    return {'mode': 'remote', 'role': result.get('role'), 'workers': list(result.get('workers') or [])}
