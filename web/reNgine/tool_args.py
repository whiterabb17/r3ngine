"""Discover, cache, and validate CLI args for singular tool runs.

Schemas come from the installed binary's help output when present; otherwise a
small seed fallback. User-supplied tool_args are validated against the schema
and converted to safe argv extras — never free-form shell strings.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import time
from typing import Any, Optional

from django.utils import timezone

from reNgine.tool_inventory import (
    _EXTRA_PATH_DIRS,
    ensure_db_connection,
    probe_version,
    resolve_binary_path,
    sync_installed_tools,
)

logger = logging.getLogger(__name__)

HELP_TIMEOUT_SEC = 12.0
REFRESH_COOLDOWN_SEC = 30.0
MAX_STRING_LEN = 512
MAX_ARGS = 40

# Pipeline tool -> primary binaries (ordered preference)
PIPELINE_BINARIES: dict[str, list[str]] = {
    'port_scan': ['naabu', 'nmap'],
    'nuclei_scan': ['nuclei'],
    'vulnerability_scan': ['nuclei'],
    'dir_file_fuzz': ['ffuf', 'dirsearch'],
    'fetch_url': ['katana', 'gau', 'gospider'],
    'http_crawl': ['httpx'],
    'waf_detection': ['wafw00f'],
    'dalfox_xss_scan': ['dalfox'],
    # Playwright-embedded screenshot — no CLI binary; YAML intensity only.
    'screenshot': [],
    'osint': ['theHarvester', 'subfinder'],
    'subdomain_discovery': ['subfinder', 'amass'],
    'secret_scanning': ['gitleaks', 'trufflehog'],
    'waf_bypass': ['ffuf'],
    'web_api_discovery': ['kiterunner', 'arjun'],
    'param_discovery': ['arjun', 'ParamSpider'],
}

# Flags that must never be exposed / accepted (filesystem, updates, retargeting)
_FLAG_DENYLIST = frozenset({
    'update', 'update-templates', 'ut', 'duc', 'offline-http',
    'config', 'config-directory', 'pd', 'provider-config',
    'l', 'list', 'linput', 'target', 'targets', 'u', 'url', 'urls',
    'host', 'hosts', 'domain', 'domains', 'd',
    'o', 'output', 'json-export', 'markdown-export', 'sarif-export',
    'store-resp', 'store-response', 'srd', 'sresponse',
    'env-vars', 'secret-file', 'auth', 'token',
    'c',  # often -c config for some tools — still allow concurrency via long form
    'resume', 'resume-cfg',
    'interactsh-url', 'interactions-cache-size',
    'health-check', 'hc',
    'validate', 'tl', 'templates', 't',  # template path injection — use yaml overlay instead
    'w', 'wordlist',  # path injection for fuzzers — use engine yaml
    'proxy-file',
    'system-resolvers',
    'help', 'h',  # meta flags / cobra command index noise
})

# Long-form denylist (normalized without leading dashes)
_LONG_DENYLIST = frozenset({
    'update', 'update-templates', 'config', 'config-directory', 'list',
    'target', 'targets', 'url', 'urls', 'host', 'hosts', 'domain', 'domains',
    'output', 'json-export', 'markdown-export', 'sarif-export',
    'store-response', 'store-resp-dir', 'env-vars', 'secret-file',
    'resume', 'templates', 'template-url', 'wordlist', 'proxy-file',
    'input', 'input-file',
    'help',
})

_TARGETISH = frozenset({
    'target', 'targets', 'url', 'urls', 'host', 'hosts', 'domain', 'domains',
    'list', 'l', 'u', 'd',
})

# Seed schemas when binary help is unavailable (yaml-oriented knobs)
_SEED_SCHEMAS: dict[str, list[dict[str, Any]]] = {
    'port_scan': [
        {'name': 'rate', 'long_flag': '-rate', 'type': 'int', 'takes_value': True,
         'description': 'Packets/requests per second (naabu -rate)', 'dangerous': False},
        {'name': 'threads', 'long_flag': '-c', 'type': 'int', 'takes_value': True,
         'description': 'Concurrency (naabu -c)', 'dangerous': False},
        {'name': 'ports', 'long_flag': '-p', 'type': 'string', 'takes_value': True,
         'description': 'Port list/range (comma-separated) or top-100 / top-1000 / full', 'dangerous': False},
        {'name': 'timeout', 'long_flag': '--timeout', 'type': 'int', 'takes_value': True,
         'description': 'Timeout seconds', 'dangerous': False},
    ],
    'nuclei_scan': [
        {'name': 'severity', 'long_flag': '-s', 'type': 'string', 'takes_value': True,
         'description': 'Severity filter (comma-separated)', 'dangerous': False},
        {'name': 'tags', 'long_flag': '-tags', 'type': 'string', 'takes_value': True,
         'description': 'Template tags', 'dangerous': False},
        {'name': 'rate-limit', 'long_flag': '-rl', 'type': 'int', 'takes_value': True,
         'description': 'Max requests per second', 'dangerous': False},
        {'name': 'concurrency', 'long_flag': '-c', 'type': 'int', 'takes_value': True,
         'description': 'Parallel templates', 'dangerous': False},
        {'name': 'timeout', 'long_flag': '-timeout', 'type': 'int', 'takes_value': True,
         'description': 'Timeout seconds', 'dangerous': False},
    ],
    'vulnerability_scan': [
        {'name': 'severity', 'long_flag': '-s', 'type': 'string', 'takes_value': True,
         'description': 'Severity filter', 'dangerous': False},
        {'name': 'tags', 'long_flag': '-tags', 'type': 'string', 'takes_value': True,
         'description': 'Template tags', 'dangerous': False},
        {'name': 'rate-limit', 'long_flag': '-rl', 'type': 'int', 'takes_value': True,
         'description': 'Max requests per second', 'dangerous': False},
        {'name': 'concurrency', 'long_flag': '-c', 'type': 'int', 'takes_value': True,
         'description': 'Parallel templates', 'dangerous': False},
    ],
    'dir_file_fuzz': [
        {'name': 'rate', 'long_flag': '-rate', 'type': 'int', 'takes_value': True,
         'description': 'Requests per second', 'dangerous': False},
        {'name': 'threads', 'long_flag': '-t', 'type': 'int', 'takes_value': True,
         'description': 'Threads', 'dangerous': False},
        {'name': 'timeout', 'long_flag': '-timeout', 'type': 'int', 'takes_value': True,
         'description': 'Timeout seconds', 'dangerous': False},
    ],
    'fetch_url': [
        {'name': 'threads', 'long_flag': '', 'type': 'int', 'takes_value': True,
         'description': 'Threads for gau/gospider/katana (YAML)', 'dangerous': False},
        {'name': 'timeout', 'long_flag': '', 'type': 'int', 'takes_value': True,
         'description': 'Timeout seconds (YAML)', 'dangerous': False},
    ],
    'http_crawl': [
        {'name': 'threads', 'long_flag': '-t', 'type': 'int', 'takes_value': True,
         'description': 'Threads (httpx -t)', 'dangerous': False},
        {'name': 'timeout', 'long_flag': '-timeout', 'type': 'int', 'takes_value': True,
         'description': 'Timeout seconds', 'dangerous': False},
    ],
    # wafw00f singular runs use a fixed command; only YAML-safe toggles are exposed.
    'waf_detection': [
        {'name': 'enable_http_crawl', 'long_flag': '', 'type': 'bool', 'takes_value': False,
         'description': 'Prefer alive endpoints from prior crawl', 'dangerous': False},
    ],
    'screenshot': [
        {'name': 'intensity', 'long_flag': '', 'type': 'string', 'takes_value': True,
         'description': 'Scan intensity (normal/deep) — Playwright embedded', 'dangerous': False},
    ],
    'dalfox_xss_scan': [
        {'name': 'worker', 'long_flag': '--workers', 'type': 'int', 'takes_value': True,
         'description': 'Workers', 'dangerous': False},
        {'name': 'delay', 'long_flag': '--delay', 'type': 'int', 'takes_value': True,
         'description': 'Delay ms', 'dangerous': False},
        {'name': 'timeout', 'long_flag': '--timeout', 'type': 'int', 'takes_value': True,
         'description': 'Timeout seconds', 'dangerous': False},
    ],
}

# Map common CLI names into yaml_configuration keys under the task section
_YAML_KEY_MAP: dict[str, str] = {
    'rate-limit': 'rate_limit',
    'rate_limit': 'rate_limit',
    'rl': 'rate_limit',
    'concurrency': 'concurrency',
    'threads': 'threads',
    'timeout': 'timeout',
    # Nuclei reads vulnerability_scan.nuclei.severities (NUCLEI_SEVERITY)
    'severity': 'severities',
    'severities': 'severities',
    'tags': 'tags',
    'ports': 'ports',
    'rate': 'rate',  # naabu uses port_scan.rate (NAABU_RATE)
    'depth': 'depth',
    'worker': 'threads',  # dalfox --workers from yaml threads
    'delay': 'delay',
    'enable_http_crawl': 'enable_http_crawl',
    'intensity': 'intensity',
}

_NUMERIC_CAPS = {
    'rate_limit': 5000,
    'concurrency': 500,
    'threads': 500,
    'timeout': 600,
    'depth': 20,
    'delay': 10000,
}

_HELP_FLAG_RE = re.compile(
    r'^\s*(?:(-[a-zA-Z0-9][\w-]*),?\s*)?(--?[a-zA-Z][\w-]*)(?:[ =](\S+))?\s{2,}(.+)$'
)
_HELP_FLAG_RE_ALT = re.compile(
    r'^\s*(--?[a-zA-Z][\w-]*)(?:[ =<>[\]]+(\S+))?\s+(.*)$'
)

_last_refresh_at: dict[str, float] = {}


class ToolArgsError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _normalize_flag_key(flag: str) -> str:
    return (flag or '').lstrip('-').strip().lower()


def _is_denied(flag: str) -> bool:
    key = _normalize_flag_key(flag)
    if key in _LONG_DENYLIST or key in _FLAG_DENYLIST or key in _TARGETISH:
        return True
    if key.startswith('update') or key.endswith('-file') or key.endswith('-dir'):
        if key in ('rate-limit',):
            return False
        if 'template' in key or 'config' in key or 'wordlist' in key or 'output' in key:
            return True
    return False


def parse_help_text(help_text: str) -> list[dict[str, Any]]:
    """Parse GNU/Cobra-ish help lines into schema entries."""
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for line in (help_text or '').splitlines():
        line = line.rstrip()
        if not line.strip() or line.strip().startswith('Usage'):
            continue
        m = _HELP_FLAG_RE.match(line) or _HELP_FLAG_RE_ALT.match(line)
        if not m:
            continue
        if m.re is _HELP_FLAG_RE:
            short, longf, value_hint, desc = m.group(1), m.group(2), m.group(3), m.group(4)
        else:
            short, longf, value_hint, desc = None, m.group(1), m.group(2), m.group(3)
        if not longf:
            continue
        key = _normalize_flag_key(longf)
        if not key or key in seen or _is_denied(key):
            continue
        seen.add(key)
        takes_value = bool(value_hint) and value_hint not in ('', '[flags]')
        # Heuristic: bool flags often have no value token
        if value_hint and value_hint.lower() in ('true', 'false'):
            ftype = 'bool'
            takes_value = False
        elif takes_value and re.search(r'int|num|count|second|rate|thread|timeout|depth|port', (desc or '') + (value_hint or ''), re.I):
            ftype = 'int'
        elif takes_value:
            ftype = 'string'
        else:
            ftype = 'bool'
        out.append({
            'name': key,
            'long_flag': longf if longf.startswith('-') else f'--{longf}',
            'short_flag': short,
            'type': ftype,
            'takes_value': takes_value if ftype != 'bool' else False,
            'description': (desc or '')[:300].strip(),
            'dangerous': False,
            'default': None,
        })
        if len(out) >= 80:
            break
    return out


def _run_help(binary_path: str, *, tool_name: str = '') -> tuple[str, str]:
    """Local --help fallback when a plain filesystem path is available."""
    from reNgine.tool_workers import help_subcommands_for

    env = {**os.environ, 'PATH': os.pathsep.join([*_EXTRA_PATH_DIRS, os.environ.get('PATH', '')])}
    attempts: list[list[str]] = []
    for sub in help_subcommands_for(tool_name or os.path.basename(binary_path)):
        attempts.append([binary_path, sub, '--help'])
        attempts.append([binary_path, sub, '-h'])
    attempts.extend([
        [binary_path, '--help'],
        [binary_path, '-h'],
        [binary_path, 'help'],
    ])
    for args in attempts:
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=HELP_TIMEOUT_SEC,
                check=False, shell=False, env=env,
            )
            text = (proc.stdout or '') + '\n' + (proc.stderr or '')
            if text.strip():
                return text, ' '.join(args[1:])
        except Exception:
            continue
    return '', ''


def _probe_help_text(
    *,
    primary: str,
    encoded_or_local_path: Optional[str],
) -> tuple[str, str, Optional[str]]:
    """Fetch --help from go/python workers first; local path only as last resort.

    Returns (help_text, flag_used, resolved_encoded_or_local_path).
    """
    from reNgine.tool_inventory import _candidate_binaries
    from reNgine.tool_workers import decode_worker_path, run_help_on_workers

    candidates = _candidate_binaries(primary)
    help_text, flag, encoded = run_help_on_workers(
        tool_name=primary,
        candidates=candidates,
        encoded_path=encoded_or_local_path,
        timeout=HELP_TIMEOUT_SEC,
    )
    if help_text.strip():
        return help_text, flag, encoded or encoded_or_local_path

    role, path = decode_worker_path(encoded_or_local_path)
    if not role and path and os.path.isfile(path):
        text, used = _run_help(path, tool_name=primary)
        return text, used, path
    return '', '', encoded_or_local_path


def _path_is_present(path: Optional[str]) -> bool:
    if not path:
        return False
    from reNgine.tool_workers import decode_worker_path
    role, remote = decode_worker_path(path)
    if role and remote:
        return True
    return os.path.isfile(path)


def _help_hash(text: str) -> str:
    return hashlib.sha256((text or '').encode('utf-8', errors='replace')).hexdigest()


def _rate_limited(key: str) -> bool:
    last = _last_refresh_at.get(key, 0)
    return (time.monotonic() - last) < REFRESH_COOLDOWN_SEC


def _mark_refreshed(key: str) -> None:
    _last_refresh_at[key] = time.monotonic()


def _seed_schema(pipeline_tool: str) -> list[dict[str, Any]]:
    base = _SEED_SCHEMAS.get(pipeline_tool) or _SEED_SCHEMAS.get('fetch_url') or []
    return [dict(x) for x in base]


def _tool_row(binary_name: str):
    from scanEngine.models import InstalledExternalTool
    return (
        InstalledExternalTool.objects.filter(name__iexact=binary_name).first()
        or InstalledExternalTool.objects.filter(name__icontains=binary_name).first()
    )


def get_or_refresh_schema(
    pipeline_tool: str,
    *,
    force: bool = False,
    sync_first: bool = False,
) -> dict[str, Any]:
    """Return schema payload for a pipeline tool (cached help or seed)."""
    from scanEngine.models import ToolArgSchemaCache
    from reNgine.capabilities import get_pipeline_tool, resolve_retry_task_name

    if not get_pipeline_tool(pipeline_tool) and pipeline_tool not in PIPELINE_BINARIES:
        raise ToolArgsError(f'Unknown pipeline tool: {pipeline_tool}', 404)

    if sync_first:
        try:
            sync_installed_tools(probe_versions=True)
        except Exception:
            logger.exception('sync_installed_tools during schema refresh failed')

    binaries = PIPELINE_BINARIES.get(pipeline_tool)
    if binaries is None:
        binaries = [pipeline_tool]
    # Empty list = YAML-only seed schema (no CLI binary to probe).
    if not binaries:
        schema = _seed_schema(pipeline_tool)
        retry_name = resolve_retry_task_name(pipeline_tool) if get_pipeline_tool(pipeline_tool) else pipeline_tool
        return {
            'pipeline_tool': pipeline_tool,
            'retry_task_name': retry_name,
            'binaries': [],
            'binary_name': '',
            'binary_path': '',
            'version': None,
            'source': 'seed',
            'schema': schema,
            'fetched_at': None,
        }

    primary = binaries[0]
    row = _tool_row(primary)
    binary_path = (row.resolved_path if row and row.is_present else None) or resolve_binary_path(primary)
    version = None
    if row and row.detected_version:
        version = row.detected_version
    elif binary_path and _path_is_present(binary_path):
        version, _ = probe_version(
            resolved_path=binary_path,
            version_lookup_command=row.version_lookup_command if row else None,
            version_match_regex=row.version_match_regex if row else None,
        )
        ensure_db_connection()

    cache = ToolArgSchemaCache.objects.filter(
        pipeline_tool=pipeline_tool, binary_name=primary,
    ).first()

    version_fp = version or ''
    needs_refresh = (
        force
        or cache is None
        or (version_fp and cache.version_fingerprint and cache.version_fingerprint != version_fp)
        or (
            cache
            and cache.source == ToolArgSchemaCache.SOURCE_SEED
            and _path_is_present(binary_path)
        )
    )

    rate_key = f'{pipeline_tool}:{primary}'
    if needs_refresh and force and _rate_limited(rate_key):
        needs_refresh = False  # serve cache under cooldown unless empty
        if cache is None:
            needs_refresh = True

    if needs_refresh:
        _mark_refreshed(rate_key)
        schema: list[dict[str, Any]]
        source = ToolArgSchemaCache.SOURCE_SEED
        help_hash = ''
        help_text, _, resolved = _probe_help_text(
            primary=primary,
            encoded_or_local_path=binary_path,
        )
        if resolved:
            binary_path = resolved
        parsed = parse_help_text(help_text) if help_text else []
        if parsed:
            schema = parsed
            source = ToolArgSchemaCache.SOURCE_HELP
            help_hash = _help_hash(help_text)
        else:
            schema = _seed_schema(pipeline_tool)

        # Worker docker exec can drop the idle DB handle; reconnect only if needed.
        ensure_db_connection()
        cache, _ = ToolArgSchemaCache.objects.update_or_create(
            pipeline_tool=pipeline_tool,
            binary_name=primary,
            defaults={
                'binary_path': binary_path or '',
                'version_fingerprint': version_fp,
                'schema': schema,
                'raw_help_hash': help_hash,
                'fetched_at': timezone.now(),
                'source': source,
            },
        )

    assert cache is not None
    retry_name = resolve_retry_task_name(pipeline_tool) if get_pipeline_tool(pipeline_tool) else pipeline_tool
    return {
        'pipeline_tool': pipeline_tool,
        'retry_task_name': retry_name,
        'binaries': binaries,
        'binary_name': cache.binary_name,
        'binary_path': cache.binary_path,
        'version': cache.version_fingerprint or None,
        'is_present': _path_is_present(binary_path or cache.binary_path),
        'cached': True,
        'source': cache.source,
        'fetched_at': cache.fetched_at.isoformat() if cache.fetched_at else None,
        'schema': cache.schema or [],
    }


def _coerce_value(entry: dict[str, Any], raw: Any) -> Any:
    ftype = entry.get('type') or 'string'
    if ftype == 'bool':
        if isinstance(raw, bool):
            return raw
        if str(raw).lower() in ('1', 'true', 'yes', 'on'):
            return True
        if str(raw).lower() in ('0', 'false', 'no', 'off'):
            return False
        raise ToolArgsError(f'{entry.get("name")}: expected boolean')
    if ftype == 'int':
        try:
            val = int(raw)
        except (TypeError, ValueError) as exc:
            raise ToolArgsError(f'{entry.get("name")}: expected integer') from exc
        yaml_key = _YAML_KEY_MAP.get(_normalize_flag_key(entry.get('name', '')), '')
        cap = _NUMERIC_CAPS.get(yaml_key) or _NUMERIC_CAPS.get(entry.get('name', ''))
        if cap is not None and (val < 0 or val > cap):
            raise ToolArgsError(f'{entry.get("name")}: must be between 0 and {cap}')
        return val
    if ftype == 'float':
        try:
            return float(raw)
        except (TypeError, ValueError) as exc:
            raise ToolArgsError(f'{entry.get("name")}: expected number') from exc
    # string
    if raw is None:
        raise ToolArgsError(f'{entry.get("name")}: value required')
    s = str(raw)
    if len(s) > MAX_STRING_LEN:
        raise ToolArgsError(f'{entry.get("name")}: value too long')
    # No whitespace: extras are joined into shell=True commands; spaces become new tokens.
    if re.search(r'\s', s):
        raise ToolArgsError(f'{entry.get("name")}: whitespace not allowed in values')
    if s.startswith('-'):
        raise ToolArgsError(f'{entry.get("name")}: value must not look like a CLI flag')
    if any(ch in s for ch in ('\0', ';', '|', '&', '`', '$', '(', ')', '<', '>', '\\', '"', "'")):
        raise ToolArgsError(f'{entry.get("name")}: value contains forbidden characters')
    return s


def validate_tool_args(
    pipeline_tool: str,
    tool_args: Optional[dict],
    *,
    schema_payload: Optional[dict] = None,
) -> dict[str, Any]:
    """Validate tool_args against cached schema.

    Returns {sanitized: dict, extra_cli_args: list[str], yaml_overlay: dict}.
    """
    if not tool_args:
        return {'sanitized': {}, 'extra_cli_args': [], 'yaml_overlay': {}}
    if not isinstance(tool_args, dict):
        raise ToolArgsError('tool_args must be an object')
    if len(tool_args) > MAX_ARGS:
        raise ToolArgsError(f'max {MAX_ARGS} tool_args allowed')

    payload = schema_payload or get_or_refresh_schema(pipeline_tool, force=False)
    by_name: dict[str, dict] = {}
    for entry in payload.get('schema') or []:
        by_name[_normalize_flag_key(entry.get('name') or '')] = entry
        lf = _normalize_flag_key(entry.get('long_flag') or '')
        if lf:
            by_name[lf] = entry

    sanitized: dict[str, Any] = {}
    extra: list[str] = []
    yaml_overlay: dict[str, Any] = {}

    for raw_key, raw_val in tool_args.items():
        key = _normalize_flag_key(str(raw_key))
        if not key or _is_denied(key):
            raise ToolArgsError(f'argument not allowed: {raw_key}')
        entry = by_name.get(key)
        if not entry:
            raise ToolArgsError(f'unknown argument for {pipeline_tool}: {raw_key}')
        value = _coerce_value(entry, raw_val)
        if entry.get('type') == 'bool' and value is False:
            continue
        sanitized[key] = value
        flag = (entry.get('long_flag') or '').strip()
        # Empty long_flag => YAML-only knob (do not invent a CLI flag).
        if flag:
            if entry.get('type') == 'bool':
                extra.append(flag)
            else:
                extra.extend([flag, str(value)])
        yk = _YAML_KEY_MAP.get(key) or _YAML_KEY_MAP.get(_normalize_flag_key(key))
        if yk:
            if yk == 'ports' and isinstance(value, str):
                # Engine port_scan expects an iterable of tokens, not a raw CSV string.
                parts = [p.strip() for p in value.replace(' ', ',').split(',') if p.strip()]
                yaml_overlay[yk] = parts or [value]
            elif yk == 'severities' and isinstance(value, str):
                # nuclei joins severities; a raw CSV string would be character-joined.
                parts = [p.strip() for p in value.split(',') if p.strip()]
                yaml_overlay[yk] = parts or [value]
            elif yk == 'tags' and isinstance(value, str):
                parts = [p.strip() for p in value.split(',') if p.strip()]
                yaml_overlay[yk] = parts or [value]
            else:
                yaml_overlay[yk] = value
        # http_crawl reads threads from YAML; accept concurrency as an alias.
        if pipeline_tool == 'http_crawl' and key == 'concurrency' and 'threads' not in yaml_overlay:
            yaml_overlay['threads'] = value

    return {
        'sanitized': sanitized,
        'extra_cli_args': extra,
        'yaml_overlay': yaml_overlay,
    }


def merge_yaml_overlay(base_yaml: dict, pipeline_tool: str, overlay: dict) -> dict:
    """Deep-merge overlay into the task section of engine yaml."""
    from reNgine.capabilities import resolve_retry_task_name, get_pipeline_tool

    out = dict(base_yaml or {})
    if not overlay:
        return out
    section = pipeline_tool
    if get_pipeline_tool(pipeline_tool):
        section = resolve_retry_task_name(pipeline_tool)
    # nuclei knobs often live under vulnerability_scan.nuclei
    if section in ('vulnerability_scan', 'nuclei_scan'):
        vs = dict(out.get('vulnerability_scan') or {})
        nuclei = dict(vs.get('nuclei') or {})
        overlay_n = dict(overlay)
        for list_key in ('severities', 'tags'):
            val = overlay_n.get(list_key)
            if isinstance(val, str):
                overlay_n[list_key] = [p.strip() for p in val.split(',') if p.strip()] or [val]
        nuclei.update(overlay_n)
        vs['nuclei'] = nuclei
        # also top-level rate/concurrency used by some paths
        for k in ('rate_limit', 'concurrency', 'timeout', 'threads'):
            if k in overlay_n:
                vs[k] = overlay_n[k]
        out['vulnerability_scan'] = vs
        return out
    if section == 'dalfox_xss_scan':
        # dalfox_xss_scan() reads vulnerability_scan.dalfox, not a top-level block.
        vs = dict(out.get('vulnerability_scan') or {})
        dalfox = dict(vs.get('dalfox') or {})
        dalfox.update(overlay)
        vs['dalfox'] = dalfox
        out['vulnerability_scan'] = vs
        return out
    if section == 'port_scan':
        ps = dict(out.get('port_scan') or {})
        # Naabu reads rate from key "rate" (NAABU_RATE), not rate_limit.
        if 'rate_limit' in overlay and 'rate' not in overlay:
            ps['rate'] = overlay['rate_limit']
        if 'rate' in overlay:
            ps['rate'] = overlay['rate']
        ports_val = overlay.get('ports')
        if isinstance(ports_val, str):
            overlay = {
                **overlay,
                'ports': [p.strip() for p in ports_val.replace(' ', ',').split(',') if p.strip()] or [ports_val],
            }
        ps.update(overlay)
        out['port_scan'] = ps
        return out
    block = dict(out.get(section) or {})
    block.update(overlay)
    out[section] = block
    return out


def append_extra_cli_args(cmd: list[str] | str, extra: list[str]) -> list[str] | str:
    """Append validated extras to a command list (preferred) or space-joined string."""
    import shlex

    if not extra:
        return cmd
    cleaned: list[str] = []
    for tok in extra:
        t = str(tok)
        # Defense in depth — validate_tool_args should already reject these.
        if not t or re.search(r'\s', t):
            raise ToolArgsError('extra CLI token contains whitespace')
        cleaned.append(t)
    if isinstance(cmd, list):
        return [*cmd, *cleaned]
    # string form — quote each token so shell=True cannot split injected values
    return (cmd.rstrip() + ' ' + ' '.join(shlex.quote(t) for t in cleaned)).strip()


def refresh_all_present_schemas(*, probe_versions: bool = True) -> dict[str, Any]:
    """Sync inventory then refresh schemas for present pipeline binaries."""
    sync_result = sync_installed_tools(probe_versions=probe_versions)
    ensure_db_connection()
    refreshed = []
    errors = []
    for tool in PIPELINE_BINARIES:
        try:
            get_or_refresh_schema(tool, force=True, sync_first=False)
            refreshed.append(tool)
        except Exception as exc:
            errors.append({'tool': tool, 'error': str(exc)})
            ensure_db_connection()
    return {'sync': sync_result, 'refreshed': refreshed, 'errors': errors}
