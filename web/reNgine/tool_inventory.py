"""Reconcile InstalledExternalTool rows against binaries on this host.

Only probes a curated allowlist derived from fixture/catalog names — never
auto-registers arbitrary PATH binaries.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Optional

from django.utils import timezone

logger = logging.getLogger(__name__)

# Known PATH locations used by the web image.
_EXTRA_PATH_DIRS = (
    '/usr/local/bin',
    '/usr/bin',
    '/go/bin',
    '/root/go/bin',
    '/home/rengine/go/bin',
)

# name (lowercase) -> candidate binary names on disk
_BINARY_ALIASES: dict[str, list[str]] = {
    'nuclei': ['nuclei'],
    'httpx': ['httpx'],
    'naabu': ['naabu'],
    'nmap': ['nmap'],
    'subfinder': ['subfinder'],
    'ffuf': ['ffuf'],
    'katana': ['katana'],
    'gau': ['gau'],
    'hakrawler': ['hakrawler'],
    'gospider': ['gospider'],
    'amass': ['amass'],
    'dalfox': ['dalfox'],
    'wafw00f': ['wafw00f'],
    'tlsx': ['tlsx'],
    'dnsx': ['dnsx'],
    'chaos': ['chaos'],
    'kiterunner': ['kr', 'kiterunner'],
    'kr': ['kr', 'kiterunner'],
    'arjun': ['arjun'],
    'linkfinder': ['linkfinder'],
    'paramspider': ['paramspider'],
    'semgrep': ['semgrep'],
    'gitleaks': ['gitleaks'],
    'trufflehog': ['trufflehog'],
    'wpscan': ['wpscan'],
    'sqlmap': ['sqlmap'],
    'testssl.sh': ['testssl.sh', 'testssl'],
    'dirsearch': ['dirsearch'],
    'baddns': ['baddns'],
    'gosearch': ['gosearch'],
    'betterleaks': ['betterleaks'],
    'username-anarchy': ['username-anarchy'],
    'vulnx': ['vulnx'],
    'gowitness': ['gowitness'],
    'crlfuzz': ['crlfuzz'],
    'whatweb': ['whatweb'],
    # Cloned under /usr/src/github/theHarvester; binary is camelCase in .venv/bin.
    'theharvester': ['theHarvester', 'theharvester'],
}

_GITHUB_CLONE_ROOT = '/usr/src/github'


def _candidate_binaries(tool_name: str) -> list[str]:
    raw = (tool_name or '').strip()
    key = raw.lower()
    if key in _BINARY_ALIASES:
        return list(_BINARY_ALIASES[key])
    out: list[str] = []
    for candidate in (raw, key, raw.replace(' ', '-'), key.replace(' ', '-')):
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def _looks_executable(path: str) -> bool:
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


def _match_in_dir(directory: str, candidates: list[str]) -> Optional[str]:
    if not directory or not os.path.isdir(directory):
        return None
    for candidate in candidates:
        direct = os.path.join(directory, candidate)
        if _looks_executable(direct):
            return direct
    # Case-insensitive fallback (Linux FS is case-sensitive; fixtures vary).
    try:
        names = os.listdir(directory)
    except OSError:
        return None
    lower_map = {name.lower(): name for name in names}
    for candidate in candidates:
        real = lower_map.get(candidate.lower())
        if not real:
            continue
        full = os.path.join(directory, real)
        if _looks_executable(full):
            return full
    return None


def _executable_in_clone(clone_dir: str, candidates: list[str]) -> Optional[str]:
    """Prefer a real binary inside a github clone (venv/bin, bin/, root)."""
    if not clone_dir or not os.path.isdir(clone_dir):
        return None
    for sub in (
        os.path.join(clone_dir, '.venv', 'bin'),
        os.path.join(clone_dir, 'bin'),
        clone_dir,
    ):
        found = _match_in_dir(sub, candidates)
        if found:
            return found
    return None


def _default_github_clone(tool_name: str) -> Optional[str]:
    raw = (tool_name or '').strip()
    if not raw:
        return None
    for name in (raw, raw.lower()):
        path = os.path.join(_GITHUB_CLONE_ROOT, name)
        if os.path.isdir(path):
            return path
    return None


def resolve_binary_path(tool_name: str, github_clone_path: Optional[str] = None) -> Optional[str]:
    """Return location of the primary binary.

    Prefers Temporal worker containers (go-executor / python-orchestrator) where
    entrypoint-installed tools live. Returns an encoded worker path
    (`go:/usr/local/bin/kr` or `python:/…`) when found remotely.

    Falls back to a local absolute path only when Docker workers are unreachable
    (dev/tests without the socket). Never returns a directory.
    """
    from reNgine.tool_workers import (
        encode_worker_path,
        prefer_roles_for_tool,
        resolve_on_workers,
    )

    candidates = _candidate_binaries(tool_name)
    remote = resolve_on_workers(
        tool_name,
        candidates,
        prefer_roles=prefer_roles_for_tool(tool_name),
    )
    if remote:
        return encode_worker_path(remote['role'], remote['path'])

    # Local fallback (web image may still ship some Go binaries).
    search_path = os.pathsep.join(
        [*(d for d in _EXTRA_PATH_DIRS if os.path.isdir(d)), os.environ.get('PATH', '')]
    )
    for candidate in candidates:
        found = shutil.which(candidate, path=search_path)
        if found and _looks_executable(found):
            return found
    for d in _EXTRA_PATH_DIRS:
        hit = _match_in_dir(d, candidates)
        if hit:
            return hit

    clone = github_clone_path if github_clone_path and os.path.isdir(github_clone_path) else None
    if not clone:
        clone = _default_github_clone(tool_name)
    found = _executable_in_clone(clone, candidates) if clone else None
    if found:
        return found
    return None


def _run_argv(argv: list[str], *, timeout: float = 8.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            env={**os.environ, 'PATH': os.pathsep.join([*_EXTRA_PATH_DIRS, os.environ.get('PATH', '')])},
        )
        return proc.returncode, proc.stdout or '', proc.stderr or ''
    except FileNotFoundError:
        return 127, '', 'not found'
    except subprocess.TimeoutExpired:
        return 124, '', 'timeout'
    except Exception as exc:
        return 1, '', str(exc)[:200]


def probe_version(
    *,
    resolved_path: str,
    version_lookup_command: Optional[str],
    version_match_regex: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """Return (version_string, error). Uses argv-only execution (local or worker)."""
    from reNgine.tool_workers import decode_worker_path, run_version_on_workers

    role, remote_path = decode_worker_path(resolved_path)
    if role and remote_path:
        text, err = run_version_on_workers(
            role=role,
            path=remote_path,
            version_lookup_command=version_lookup_command,
        )
        if err and not text:
            return None, err
        return _extract_version(text, version_match_regex), None

    argv: list[str]
    if version_lookup_command:
        parts = version_lookup_command.strip().split()
        if not parts:
            argv = [resolved_path, '--version']
        else:
            first = parts[0]
            base = os.path.basename(resolved_path.rstrip('/'))
            if os.path.isfile(resolved_path) and (
                first == base or first.endswith('/' + base) or os.path.basename(first) == base
            ):
                argv = [resolved_path, *parts[1:]]
            elif os.path.isabs(first) and os.path.isfile(first):
                argv = parts
            else:
                argv = [resolved_path if os.path.isfile(resolved_path) else first, *parts[1:]]
    else:
        if not os.path.isfile(resolved_path):
            return None, None
        argv = [resolved_path, '--version']

    code, out, err = _run_argv(argv)
    text = (out + '\n' + err).strip()
    if not text:
        return None, f'empty version output (exit {code})' if code else None
    return _extract_version(text, version_match_regex), None


def _extract_version(text: str, version_match_regex: Optional[str]) -> Optional[str]:
    if not text:
        return None
    pattern = version_match_regex or r'[vV]?\d+\.\d+(?:\.\d+)?'
    try:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    except re.error:
        m = re.search(r'[vV]?\d+\.\d+(?:\.\d+)?', text)
    if m:
        return m.group(0)
    line = next((ln.strip() for ln in text.splitlines() if ln.strip()), None)
    return (line[:180] if line else None)


def ensure_db_connection() -> None:
    """Reconnect only when the DB handle is dead.

    Long docker.exec probes can outlive Postgres idle timeouts. Calling
    ``close_old_connections()`` unconditionally breaks Django ``TestCase``
    (it closes the transactional connection). Ping first; recover only on failure.
    """
    from django.db import close_old_connections, connection

    try:
        connection.ensure_connection()
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
    except Exception:
        close_old_connections()
        connection.ensure_connection()


def sync_installed_tools(*, probe_versions: bool = True) -> dict[str, Any]:
    """Upsert presence/version on all InstalledExternalTool rows.

    Presence is determined primarily on go-executor / python-orchestrator workers
    (entrypoint-installed tools). Does not create tools from arbitrary PATH entries.

    Resolve/probe happens in a DB-free phase so docker exec cannot strand an open
    queryset cursor; writes happen afterward with a safe reconnect.
    """
    from scanEngine.models import InstalledExternalTool
    from reNgine.tool_workers import decode_worker_path, worker_probe_summary

    now = timezone.now()
    present = 0
    missing = 0
    errors = 0
    workers = worker_probe_summary()

    # Phase 1 — snapshot rows (short DB window). Keepalive before long docker.
    ensure_db_connection()
    snapshots = list(
        InstalledExternalTool.objects.order_by('id').values(
            'id',
            'name',
            'github_clone_path',
            'version_lookup_command',
            'version_match_regex',
            'resolved_path',
        )
    )

    # Phase 2 — resolve + optional version probe (docker; no DB).
    updates: list[dict[str, Any]] = []
    for idx, row in enumerate(snapshots):
        tool_id = row['id']
        # Heartbeat so idle-in-transaction / idle timeouts do not kill the session
        # while we docker-exec across dozens of tools.
        if idx and idx % 8 == 0:
            try:
                ensure_db_connection()
            except Exception:
                pass
        try:
            # Reuse a still-encoded worker path from a prior sync when possible.
            prior = row.get('resolved_path') or ''
            role_prior, remote_prior = decode_worker_path(prior)
            if role_prior and remote_prior:
                path = prior
            else:
                path = resolve_binary_path(row['name'], row['github_clone_path'])
            version = None
            sync_err = None
            if path:
                role, remote = decode_worker_path(path)
                can_probe = bool(role and remote) or os.path.isfile(path)
                if probe_versions and can_probe:
                    version, sync_err = probe_version(
                        resolved_path=path,
                        version_lookup_command=row['version_lookup_command'],
                        version_match_regex=row['version_match_regex'],
                    )
            updates.append({
                'id': tool_id,
                'path': path,
                'version': version,
                'sync_err': sync_err,
                'exc': None,
            })
        except Exception as exc:
            logger.exception('resolve/probe failed for tool id=%s', tool_id)
            updates.append({
                'id': tool_id,
                'path': None,
                'version': None,
                'sync_err': None,
                'exc': str(exc)[:500],
            })

    # Phase 3 — write results (reconnect only if the idle connection died).
    ensure_db_connection()
    for update in updates:
        tool_id = update['id']
        try:
            tool = InstalledExternalTool.objects.get(pk=tool_id)
            if update['exc']:
                tool.last_sync_error = update['exc']
                tool.save(update_fields=['last_sync_error'])
                errors += 1
                continue
            path = update['path']
            if not path:
                tool.is_present = False
                tool.resolved_path = None
                tool.detected_version = None
                tool.last_sync_error = 'binary not found on workers/host'
                tool.save(update_fields=[
                    'is_present', 'resolved_path', 'detected_version', 'last_sync_error',
                ])
                missing += 1
                continue

            tool.is_present = True
            tool.resolved_path = path
            tool.detected_version = update['version']
            tool.last_seen_at = now
            tool.last_sync_error = update['sync_err']
            tool.save(update_fields=[
                'is_present', 'resolved_path', 'detected_version',
                'last_seen_at', 'last_sync_error',
            ])
            present += 1
        except Exception as exc:
            logger.exception('sync write failed for tool id=%s', tool_id)
            try:
                ensure_db_connection()
                tool = InstalledExternalTool.objects.get(pk=tool_id)
                tool.last_sync_error = str(exc)[:500]
                tool.save(update_fields=['last_sync_error'])
            except Exception:
                pass
            errors += 1

    return {
        'present': present,
        'missing': missing,
        'errors': errors,
        'total': present + missing,
        'synced_at': now.isoformat(),
        'workers': workers,
    }


def ensure_catalog_from_fixture_names(extra_names: Optional[list[dict]] = None) -> int:
    """Create missing default rows for known platform tools not yet in DB.

    `extra_names` is a list of dicts with at least `name` and `install_command`.
    Used to backfill migration-only tools without relying on loaddata alone.
    """
    from scanEngine.models import InstalledExternalTool

    created = 0
    for entry in extra_names or []:
        name = entry.get('name')
        if not name:
            continue
        _, was_created = InstalledExternalTool.objects.get_or_create(
            name=name,
            defaults={
                'description': entry.get('description') or name,
                'github_url': entry.get('github_url') or '',
                'install_command': entry.get('install_command') or f'which {name}',
                'version_lookup_command': entry.get('version_lookup_command'),
                'update_command': entry.get('update_command'),
                'is_default': entry.get('is_default', True),
                'is_subdomain_gathering': entry.get('is_subdomain_gathering', False),
                'is_github_cloned': entry.get('is_github_cloned', False),
                'github_clone_path': entry.get('github_clone_path'),
                'subdomain_gathering_command': entry.get('subdomain_gathering_command'),
            },
        )
        if was_created:
            created += 1
    return created
