"""Resolve and probe scan tools on go-executor / python-orchestrator workers.

Entrypoint-installed binaries (kr, trufflehog, …) and most Go toolchain tools live
on the Temporal worker containers — not on `web`. Schema/help refresh must docker-exec
into those workers via the mounted Docker socket.
"""
from __future__ import annotations

import logging
import os
import shlex
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Substring matched against docker container Names (compose project prefix varies).
_WORKER_SPECS: tuple[tuple[str, str], ...] = (
    ('go', 'temporal-go-executor'),
    ('python', 'temporal-python-orchestrator'),
)

# In-container dirs searched when `command -v` misses (venv / github clones).
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

# Cobra/clap CLIs where root --help is only a command index; probe the
# subcommand(s) the scan pipeline actually invokes.
_HELP_SUBCOMMANDS: dict[str, tuple[str, ...]] = {
    'kiterunner': ('scan',),
    'kr': ('scan',),
    'dalfox': ('scan',),
}

# Short-lived process cache: (role preference, candidate tuple) → resolve result.
_resolve_cache: dict[tuple[Any, ...], Optional[dict[str, str]]] = {}


def clear_resolve_cache() -> None:
    _resolve_cache.clear()


def help_subcommands_for(tool_name: str) -> tuple[str, ...]:
    key = (tool_name or '').strip().lower()
    return _HELP_SUBCOMMANDS.get(key, ())


def _docker_client():
    try:
        import docker
    except ImportError:
        return None
    try:
        return docker.from_env()
    except Exception as exc:
        logger.debug('docker client unavailable: %s', exc)
        return None


def list_worker_containers() -> list[dict[str, str]]:
    """Return [{role, name, id}, ...] for running go/python workers."""
    client = _docker_client()
    if client is None:
        return []
    found: list[dict[str, str]] = []
    try:
        containers = client.containers.list(filters={'status': 'running'})
    except Exception as exc:
        logger.warning('docker containers.list failed: %s', exc)
        return []
    for role, marker in _WORKER_SPECS:
        for container in containers:
            names = list(container.attrs.get('Names') or [])
            label = f"{' '.join(names)} {getattr(container, 'name', '')}".lower()
            if marker.lower() not in label:
                continue
            found.append({
                'role': role,
                'name': container.name,
                'id': container.short_id,
            })
            break
    return found


def encode_worker_path(role: str, path: str) -> str:
    return f'{role}:{path}'


def decode_worker_path(value: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Parse `go:/usr/local/bin/kr` → ('go', '/usr/local/bin/kr'). Plain paths → (None, path)."""
    if not value:
        return None, None
    text = str(value).strip()
    if text.startswith(('go:', 'python:')):
        role, _, path = text.partition(':')
        return role, path or None
    return None, text


def _exec(container, argv: list[str], *, timeout: float = 15.0) -> tuple[int, str]:
    """Run argv in container; return (exit_code, combined stdout+stderr)."""
    try:
        # demux=False → single bytes stream
        result = container.exec_run(
            argv,
            demux=False,
            workdir=None,
            environment={
                'PATH': os.pathsep.join([*_REMOTE_PATH_DIRS, '/usr/sbin', '/sbin', '/bin']),
            },
        )
        code = int(result.exit_code if result.exit_code is not None else 1)
        raw = result.output or b''
        if isinstance(raw, tuple):
            raw = (raw[0] or b'') + b'\n' + (raw[1] or b'')
        text = raw.decode('utf-8', errors='replace') if isinstance(raw, (bytes, bytearray)) else str(raw)
        return code, text
    except Exception as exc:
        logger.debug('exec_run %s failed: %s', argv[:2], exc)
        return 1, str(exc)


def _container_by_role(role: str):
    client = _docker_client()
    if client is None:
        return None
    marker = dict(_WORKER_SPECS).get(role)
    if not marker:
        return None
    try:
        for container in client.containers.list(filters={'status': 'running'}):
            label = f"{' '.join(container.attrs.get('Names') or [])} {container.name}".lower()
            if marker.lower() in label:
                return container
    except Exception as exc:
        logger.debug('container lookup failed: %s', exc)
    return None


def which_on_container(container, candidates: list[str]) -> Optional[str]:
    """Return absolute path to the first candidate executable on the container."""
    for candidate in candidates:
        if not candidate:
            continue
        # Prefer command -v (honours PATH).
        code, out = _exec(container, ['sh', '-lc', f'command -v {shlex.quote(candidate)}'])
        path = (out or '').strip().splitlines()[0].strip() if out.strip() else ''
        if code == 0 and path.startswith('/'):
            return path
        for directory in _REMOTE_PATH_DIRS:
            probe = f'{directory.rstrip("/")}/{candidate}'
            code, _ = _exec(container, ['sh', '-lc', f'test -x {shlex.quote(probe)}'])
            if code == 0:
                return probe
        # Case-insensitive scan of key dirs.
        for directory in _REMOTE_PATH_DIRS:
            script = (
                f'd={shlex.quote(directory)}; '
                f'c={shlex.quote(candidate.lower())}; '
                'test -d "$d" || exit 1; '
                'for f in "$d"/*; do '
                '  [ -x "$f" ] || continue; '
                '  b=$(basename "$f"); '
                '  if [ "$(echo "$b" | tr "[:upper:]" "[:lower:]")" = "$c" ]; then echo "$f"; exit 0; fi; '
                'done; exit 1'
            )
            code, out = _exec(container, ['sh', '-lc', script])
            path = (out or '').strip().splitlines()[0].strip() if out.strip() else ''
            if code == 0 and path.startswith('/'):
                return path
    return None


def resolve_on_workers(
    tool_name: str,
    candidates: list[str],
    *,
    prefer_roles: Optional[tuple[str, ...]] = None,
) -> Optional[dict[str, str]]:
    """Find tool_name on go/python workers.

    Returns {role, container, path} or None.
    """
    order = prefer_roles or tuple(role for role, _ in _WORKER_SPECS)
    cache_key = (tuple(order), tuple(c for c in candidates if c))
    if cache_key in _resolve_cache:
        return _resolve_cache[cache_key]

    client = _docker_client()
    if client is None:
        _resolve_cache[cache_key] = None
        return None
    for role in order:
        container = _container_by_role(role)
        if container is None:
            continue
        path = which_on_container(container, candidates)
        if path:
            found = {'role': role, 'container': container.name, 'path': path}
            _resolve_cache[cache_key] = found
            return found
    _resolve_cache[cache_key] = None
    return None


def run_help_on_workers(
    *,
    tool_name: str,
    candidates: list[str],
    encoded_path: Optional[str] = None,
    timeout: float = _HELP_TIMEOUT_SEC,
) -> tuple[str, str, Optional[str]]:
    """Run --help/-h on a worker that has the binary.

    Returns (help_text, flag_used, encoded_worker_path).
    """
    role, path = decode_worker_path(encoded_path)
    targets: list[tuple[Optional[str], Optional[str]]] = []
    if role and path:
        targets.append((role, path))
    # Always allow rediscovery in case encoded path went stale.
    targets.append((None, None))
    subcommands = help_subcommands_for(tool_name)

    seen: set[tuple[str, str]] = set()
    for role_hint, path_hint in targets:
        if role_hint and path_hint:
            container = _container_by_role(role_hint)
            if container is None:
                continue
            key = (role_hint, path_hint)
            if key in seen:
                continue
            seen.add(key)
            text, flag = _help_on_path(
                container, path_hint, timeout=timeout, subcommands=subcommands,
            )
            if text.strip():
                return text, flag, encode_worker_path(role_hint, path_hint)
        located = resolve_on_workers(tool_name, candidates)
        if not located:
            continue
        key = (located['role'], located['path'])
        if key in seen:
            continue
        seen.add(key)
        container = _container_by_role(located['role'])
        if container is None:
            continue
        text, flag = _help_on_path(
            container, located['path'], timeout=timeout, subcommands=subcommands,
        )
        if text.strip():
            return text, flag, encode_worker_path(located['role'], located['path'])
    return '', '', None


def _help_looks_substantive(text: str) -> bool:
    """True when help text exposes more than a cobra/clap command index."""
    lower = (text or '').lower()
    # Root help that is mostly a command index + a few global flags.
    if (
        ('available commands:' in lower or '\ncommands:' in lower or lower.startswith('commands:'))
        and lower.count('--') < 10
    ):
        return False
    return lower.count('--') >= 5 or 'flags:' in lower or 'options:' in lower


def _help_on_path(
    container,
    path: str,
    *,
    timeout: float,
    subcommands: tuple[str, ...] = (),
) -> tuple[str, str]:
    # Prefer pipeline subcommands (e.g. `kr scan --help`) before thin root help.
    ordered_subs = list(subcommands)
    # Generic fallback for clap/cobra tools that expose a `scan` command.
    if 'scan' not in ordered_subs:
        ordered_subs.append('scan')

    best_root = ('', '')
    for sub in ordered_subs:
        for flag in ('--help', '-h'):
            argv = [path, sub, flag]
            code, text = _exec(container, argv, timeout=timeout)
            if text.strip() and _help_looks_substantive(text):
                return text, f'{sub} {flag}'

    for flag in _HELP_FLAGS:
        argv = [path, flag]
        code, text = _exec(container, argv, timeout=timeout)
        if text.strip() and _help_looks_substantive(text):
            return text, flag
        if text.strip() and not best_root[0]:
            best_root = (text, flag)
        if flag == 'help':
            code, text = _exec(container, [path, 'help'], timeout=timeout)
            if text.strip() and _help_looks_substantive(text):
                return text, 'help'
            if text.strip() and not best_root[0]:
                best_root = (text, 'help')
    return best_root


def prefer_roles_for_tool(tool_name: str) -> tuple[str, ...]:
    """Python/OSINT-ish tools prefer the python orchestrator; Go CLIs prefer go-executor."""
    key = (tool_name or '').strip().lower()
    pythonish = {
        'theharvester', 'wafw00f', 'arjun', 'semgrep', 'wpscan', 'sqlmap',
        'dirsearch', 'linkfinder', 'paramspider', 'holehe', 'maigret',
        'bbot', 'xnldorker', 'postleaksng', 'porch-pirate',
    }
    if key in pythonish or 'harvest' in key:
        return ('python', 'go')
    return ('go', 'python')


def run_version_on_workers(
    *,
    role: str,
    path: str,
    version_lookup_command: Optional[str] = None,
) -> tuple[str, Optional[str]]:
    """Return (combined_output, error)."""
    container = _container_by_role(role)
    if container is None:
        return '', f'worker role {role!r} not running'
    if version_lookup_command:
        parts = version_lookup_command.strip().split()
        if parts:
            first = parts[0]
            base = os.path.basename(path.rstrip('/'))
            if first == base or os.path.basename(first) == base:
                argv = [path, *parts[1:]]
            elif first.startswith('/'):
                argv = parts
            else:
                argv = [path, *parts[1:]] if len(parts) > 1 else [path, '--version']
        else:
            argv = [path, '--version']
    else:
        argv = [path, '--version']
    code, text = _exec(container, argv)
    if not text.strip():
        return '', f'empty version output (exit {code})'
    return text, None


def worker_probe_summary() -> dict[str, Any]:
    workers = list_worker_containers()
    return {
        'docker_available': _docker_client() is not None,
        'workers': workers,
    }
