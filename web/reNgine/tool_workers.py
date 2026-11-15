"""Resolve and probe scan tools where they are installed.

Scan CLIs live on the ``r3ngine-python`` / ``r3ngine-go-executor`` role images
(not on ``r3ngine-web``). Probes therefore run *inside* a worker:

* In the Python orchestrator (``R3NGINE_WORKER_ROLE`` is set by
  ``run_temporal_orchestrator``) every function here works locally with
  ``shutil.which`` and ``subprocess``.
* Anywhere else (the web container, a management command) the same call is
  sent to the orchestrator as a ``ToolProbeWorkflow`` on the Python task queue
  and the worker answers with what it found. No Docker socket is involved.
  ``run`` / ``remove`` ops cover Tool Arsenal updates and interactive recon.

Paths found on a worker are stored encoded as ``<role>:<path>``
(``python:/usr/local/bin/kr`` or ``go:/usr/local/bin/kr``) so a later sync
knows which side reported them.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shlex
import shutil
import socket
import subprocess
import uuid
from datetime import timedelta
from typing import Any, Optional

from reNgine.utils.task_queues import PYTHON_ORCHESTRATOR_QUEUE, python_orchestrator_queue

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
    'run': 600.0,
    'remove': 120.0,
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
    """Role order for a tool after the three-image split.

    Python-native / pipx tools prefer the python orchestrator. Compiled PATH
    CLIs prefer go-executor (and are listed in ROUTED_TOOLS for scan execution).
    """
    key = (tool_name or '').strip().lower()
    pythonish = {
        'theharvester', 'wafw00f', 'arjun', 'sqlmap',
        'linkfinder', 'paramspider', 'holehe', 'maigret',
        'bbot', 'xnldorker', 'postleaksng', 'porch-pirate',
        'cmseek', 'spiderfoot', 'oneforall', 'sublist3r',
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


def _tool_name_from_run_payload(payload: dict) -> str:
    """Best-effort binary name from a run payload (argv or shell command)."""
    argv = payload.get('argv')
    if isinstance(argv, list) and argv:
        return os.path.basename(str(argv[0])).lower()
    command = payload.get('command')
    if isinstance(command, str) and command.strip():
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()
        if parts:
            return os.path.basename(parts[0]).lower()
    return ''


def _prefers_go_host(tool_name: str = '', *, install_command: str = '') -> bool:
    """True when the binary or install style belongs on go-executor."""
    from reNgine.utils.task import ROUTED_TOOLS

    key = (tool_name or '').strip().lower()
    if key in ROUTED_TOOLS:
        return True
    if 'go install' in (install_command or '').lower():
        return True
    if key and prefer_roles_for_tool(key)[0] == 'go':
        return True
    return False


def _execute_on_go_executor(command: str, *, timeout: float = 300.0) -> dict[str, Any]:
    """Run a shell command on go-executor via GoExecutorTaskWorkflow."""
    from reNgine.temporal_client import TemporalClientProvider, run_and_close
    from reNgine.utils.task import _go_executor_workflow_input

    async def _run():
        client = await TemporalClientProvider.get_client()
        return await client.execute_workflow(
            'GoExecutorTaskWorkflow',
            _go_executor_workflow_input(command, timeout=timeout),
            id=f'tool-go-run-{uuid.uuid4().hex[:12]}',
            task_queue=python_orchestrator_queue(),
            execution_timeout=timedelta(seconds=max(timeout + 60.0, 120.0)),
        )

    try:
        result = run_and_close(asyncio.new_event_loop(), _run())
    except Exception as exc:
        logger.warning('go-executor run failed: %s', exc)
        return {'exit_code': -1, 'output': '', 'error': str(exc)}
    if not isinstance(result, dict):
        return {'exit_code': -1, 'output': '', 'error': 'go-executor returned non-dict'}
    return {
        'exit_code': int(result.get('exit_code') or 0),
        'output': (result.get('stdout') or '') + '\n' + (result.get('stderr') or ''),
        'error': None,
    }


def _resolve_on_go(candidates: list[str]) -> Optional[dict[str, str]]:
    """Ask go-executor for the first resolvable candidate path."""
    for cand in candidates:
        name = os.path.basename(cand) if cand else ''
        if not name or name in ('.', '..'):
            continue
        res = _execute_on_go_executor(f'command -v {shlex.quote(name)} 2>/dev/null || true', timeout=30)
        for line in (res.get('output') or '').splitlines():
            path = line.strip()
            if path.startswith('/'):
                return {'role': 'go', 'container': 'go-executor', 'path': path}
    return None


def _run_shell_local(payload: dict) -> dict[str, Any]:
    """Run argv or a shell command on this worker; used by web Tool Arsenal / recon."""
    timeout = float(payload.get('timeout') or 300)
    shell = bool(payload.get('shell'))
    argv = payload.get('argv')
    command = payload.get('command')
    # Compiled CLIs live on go-executor — forward even when this activity runs on python.
    if local_role() != 'go' and _prefers_go_host(_tool_name_from_run_payload(payload), install_command=str(command or '')):
        if shell:
            if not command or not isinstance(command, str):
                return {'exit_code': -1, 'output': '', 'error': 'shell run requires command string'}
            return _execute_on_go_executor(command, timeout=timeout)
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            return {'exit_code': -1, 'output': '', 'error': 'run requires argv list of strings'}
        return _execute_on_go_executor(shlex.join(str(x) for x in argv), timeout=timeout)
    if shell:
        if not command or not isinstance(command, str):
            return {'exit_code': -1, 'output': '', 'error': 'shell run requires command string'}
        code, text = _run_local(['bash', '-lc', command], timeout=timeout)
        return {'exit_code': code, 'output': text, 'error': None}
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        return {'exit_code': -1, 'output': '', 'error': 'run requires argv list of strings'}
    code, text = _run_local(list(argv), timeout=timeout)
    return {'exit_code': code, 'output': text, 'error': None}


def _remove_path_local(payload: dict) -> dict[str, Any]:
    """Delete an installed binary or github checkout on this worker."""
    kind = str(payload.get('kind') or '')
    if kind == 'binary':
        path = str(payload.get('path') or '')
        if not path.startswith('/usr/local/bin/') or '/' in path[len('/usr/local/bin/'):]:
            return {'ok': False, 'error': 'binary path must be under /usr/local/bin'}
        # Go-installed binaries live on go-executor's filesystem, not python's.
        if local_role() != 'go':
            res = _execute_on_go_executor(f'rm -f -- {shlex.quote(path)}', timeout=60)
            if res.get('error') or int(res.get('exit_code') or 0) != 0:
                return {'ok': False, 'error': res.get('error') or res.get('output') or 'go remove failed'}
            return {'ok': True, 'error': None}
        if os.path.isfile(path):
            os.remove(path)
        return {'ok': True, 'error': None}
    if kind == 'github':
        from reNgine.utilities import is_safe_path
        clone_path = str(payload.get('path') or '')
        root = os.path.realpath('/usr/src/github')
        if not clone_path or os.path.realpath(clone_path) == root or not is_safe_path(root, clone_path):
            return {'ok': False, 'error': 'checkout is not inside /usr/src/github'}
        shutil.rmtree(clone_path, ignore_errors=True)
        return {'ok': True, 'error': None}
    return {'ok': False, 'error': f'unknown remove kind {kind!r}'}


def run_probe_op(op: str, payload: Optional[dict] = None) -> dict[str, Any]:
    """Execute one probe operation on this host. Body of ``ToolProbeActivity``.

    Ops: ``resolve`` {candidates}, ``version`` {path, version_lookup_command},
    ``help`` {tool_name, candidates, encoded_path, timeout}, ``summary`` {},
    ``sync`` {probe_versions}, ``run`` {argv|command, shell, timeout},
    ``remove`` {kind, path}. Every result is JSON-serialisable.

    ``run`` / binary ``remove`` / go-preferred ``resolve`` forward to
    go-executor when this activity is on python.
    """
    payload = payload or {}
    if op == 'resolve':
        candidates = list(payload.get('candidates') or [])
        tool_hint = str(payload.get('tool_name') or '') or (
            os.path.basename(str(candidates[0])) if candidates else ''
        )
        order = prefer_roles_for_tool(tool_hint)
        found = None
        for role in order:
            if role == 'go' and local_role() != 'go':
                found = _resolve_on_go(candidates)
            else:
                found = _resolve_local(candidates)
            if found:
                break
        return {'found': found}
    if op == 'version':
        path = str(payload.get('path') or '')
        encoded = str(payload.get('encoded_path') or '')
        role, raw_path = decode_worker_path(encoded) if encoded else (None, None)
        target = raw_path or path
        go_path = (
            local_role() != 'go'
            and (
                role == 'go'
                or (not role and target.startswith('/usr/local/bin/'))
            )
        )
        if go_path:
            cmd = shlex.join(version_argv(target, payload.get('version_lookup_command')))
            res = _execute_on_go_executor(cmd, timeout=_VERSION_TIMEOUT_SEC)
            text = (res.get('output') or '').strip()
            err = res.get('error')
            if not text and not err:
                err = f'empty version output (exit {res.get("exit_code")})'
            return {'output': text, 'error': err}
        text, error = _version_local(target, payload.get('version_lookup_command'))
        return {'output': text, 'error': error}
    if op == 'help':
        text, flag, encoded = _help_local(
            str(payload.get('tool_name') or ''),
            list(payload.get('candidates') or []),
            payload.get('encoded_path'),
            float(payload.get('timeout') or _HELP_TIMEOUT_SEC),
        )
        if not text.strip() and local_role() != 'go':
            # Fall back to go-executor for compiled CLIs missing on python.
            tool_name = str(payload.get('tool_name') or '')
            if _prefers_go_host(tool_name):
                found = _resolve_on_go(list(payload.get('candidates') or [tool_name]))
                if found and found.get('path'):
                    for flag in _HELP_FLAGS:
                        res = _execute_on_go_executor(
                            shlex.join([found['path'], flag]),
                            timeout=float(payload.get('timeout') or _HELP_TIMEOUT_SEC),
                        )
                        help_text = (res.get('output') or '').strip()
                        if help_text:
                            return {
                                'help_text': help_text,
                                'flag': flag,
                                'encoded_path': encode_worker_path('go', found['path']),
                            }
        return {'help_text': text, 'flag': flag, 'encoded_path': encoded}
    if op == 'summary':
        return _summary_local()
    if op == 'sync':
        from reNgine.tool_inventory import sync_installed_tools
        return sync_installed_tools(probe_versions=bool(payload.get('probe_versions', True)))
    if op == 'run':
        return _run_shell_local(payload)
    if op == 'remove':
        return _remove_path_local(payload)
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
    order = prefer_roles or prefer_roles_for_tool(tool_name)
    cache_key = (tuple(order), tuple(c for c in candidates if c))
    if cache_key in _resolve_cache:
        return _resolve_cache[cache_key]

    found: Optional[dict[str, str]] = None
    if probe_is_local():
        for role in order:
            if role == 'go' and local_role() != 'go':
                found = _resolve_on_go(candidates)
            else:
                found = _resolve_local(candidates)
            if found:
                break
    else:
        try:
            found = dispatch_probe('resolve', {
                'candidates': candidates,
                'tool_name': tool_name,
            }).get('found') or None
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


def run_on_workers(
    *,
    argv: Optional[list[str]] = None,
    command: Optional[str] = None,
    shell: bool = False,
    timeout: float = 300.0,
) -> tuple[int, str]:
    """Run a command on the tool host (orchestrator). Returns (exit_code, output)."""
    payload: dict[str, Any] = {'shell': shell, 'timeout': timeout}
    if shell:
        payload['command'] = command or ''
    else:
        payload['argv'] = list(argv or [])
    if probe_is_local():
        result = _run_shell_local(payload)
    else:
        try:
            result = dispatch_probe('run', payload)
        except ToolProbeError as exc:
            return -1, str(exc)
    return int(result.get('exit_code') or 0), str(result.get('output') or '')


def remove_on_workers(*, kind: str, path: str) -> tuple[bool, Optional[str]]:
    """Delete an installed tool path on the tool host."""
    payload = {'kind': kind, 'path': path}
    if probe_is_local():
        result = _remove_path_local(payload)
    else:
        try:
            result = dispatch_probe('remove', payload)
        except ToolProbeError as exc:
            return False, str(exc)
    return bool(result.get('ok')), result.get('error')


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
