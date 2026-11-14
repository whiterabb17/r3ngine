"""Allowlisted Metasploit auxiliary/post catalog — server-side validation only.

Canonical seed lives in sibling r3ngine-copilot/data/msf_aux_catalog.json.
Django vendors a copy under web/copilot/data/ (refreshed by install-copilot).
"""
from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_MODULE_RE = re.compile(r'^(auxiliary|post)/[a-z0-9_./\-]+$', re.I)
_FORBIDDEN_OPTION_RE = re.compile(
    r'^(PAYLOAD|LHOST|LPORT|DisablePayloadHandler|EXITFUNC|PrependMigrate|'
    r'AutoRunScript|InitialAutoRunScript)$',
    re.I,
)
_ALLOWED_KINDS = frozenset({'auxiliary', 'post'})


class MsfCatalogError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _catalog_path() -> Path:
    override = os.environ.get('COPILOT_MSF_CATALOG_PATH', '').strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parent / 'data' / 'msf_aux_catalog.json'


@lru_cache(maxsize=1)
def load_catalog() -> list[dict[str, Any]]:
    path = _catalog_path()
    if not path.is_file():
        logger.error('msf catalog missing at %s', path)
        return []
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error('msf catalog unreadable %s: %s', path, exc)
        return []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        module = str(row.get('module') or '').strip()
        kind = str(row.get('kind') or '').strip().lower()
        if not module or kind not in _ALLOWED_KINDS:
            continue
        if not _MODULE_RE.match(module):
            continue
        if not module.lower().startswith(f'{kind}/'):
            continue
        out.append(row)
    return out


def reload_catalog() -> list[dict[str, Any]]:
    load_catalog.cache_clear()
    return load_catalog()


def get_module_entry(module: str) -> dict[str, Any] | None:
    needle = (module or '').strip().lower()
    if not needle:
        return None
    for row in load_catalog():
        if str(row.get('module') or '').lower() == needle:
            return row
    return None


def list_modules() -> list[str]:
    return [str(r['module']) for r in load_catalog() if r.get('module')]


def normalize_options(options: dict[str, Any] | None) -> dict[str, str]:
    if not options or not isinstance(options, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in options.items():
        k = str(key).strip()
        if not k or len(k) > 64:
            raise MsfCatalogError(f'invalid option name: {k!r}')
        if _FORBIDDEN_OPTION_RE.match(k):
            raise MsfCatalogError(f'forbidden option: {k}')
        if value is None:
            continue
        s = str(value).strip()
        if len(s) > 512:
            raise MsfCatalogError(f'option {k} value too long')
        # Reject newlines/control chars so console resource lines cannot inject
        # extra MSF commands beyond the allowlisted module + options.
        if any(ord(ch) < 32 for ch in s):
            raise MsfCatalogError(f'option {k} contains control characters')
        out[k] = s
    return out


def validate_module_options(
    module: str,
    options: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Return (catalog_entry, normalized_options) or raise MsfCatalogError."""
    entry = get_module_entry(module)
    if not entry:
        raise MsfCatalogError(
            f'module not in allowlist: {module}',
            status=400,
        )
    kind = str(entry.get('kind') or '').lower()
    if kind not in _ALLOWED_KINDS:
        raise MsfCatalogError('only auxiliary/post modules allowed')
    mod = str(entry['module'])
    if mod.lower().startswith('exploit/') or mod.lower().startswith('payload/'):
        raise MsfCatalogError('exploit/payload modules are forbidden')
    opts = normalize_options(options)
    required = entry.get('required_options') or []
    if isinstance(required, list):
        for req in required:
            if str(req) not in opts:
                raise MsfCatalogError(f'missing required option: {req}')
    allowed = set()
    for bucket in ('required_options', 'optional_options'):
        vals = entry.get(bucket) or []
        if isinstance(vals, list):
            allowed.update(str(v) for v in vals)
    if allowed:
        unknown = sorted(k for k in opts if k not in allowed)
        if unknown:
            raise MsfCatalogError(f'unknown options for module: {", ".join(unknown)}')
    return entry, opts


def extract_rhosts(options: dict[str, str]) -> list[str]:
    raw = options.get('RHOSTS') or options.get('RHOST') or ''
    if not raw:
        return []
    hosts: list[str] = []
    for part in re.split(r'[\s,;]+', raw):
        part = part.strip()
        if not part:
            continue
        if '://' in part:
            host = urlparse(part).hostname or ''
        elif '/' in part and not part.replace('.', '').replace('/', '').isdigit():
            # CIDR or path-ish — keep left side host token
            host = part.split('/')[0]
        else:
            host = part.split('/')[0]
        if host:
            hosts.append(host.lower())
    return hosts


def playbooks_from_catalog() -> list[dict[str, Any]]:
    """Shape catalog rows as sidecar playbook documents for RAG."""
    playbooks = []
    for row in load_catalog():
        module = row.get('module')
        playbooks.append({
            'id': f'msf:{module}',
            'finding_class': f'msf_aux:{module}',
            'title': row.get('summary') or module,
            'module': module,
            'kind': row.get('kind'),
            'required_options': row.get('required_options') or [],
            'optional_options': row.get('optional_options') or [],
            'matches': row.get('matches') or {},
            'tags': ['metasploit', 'msf_aux', str(row.get('kind') or '')],
            'text': (
                f"Metasploit {row.get('kind')} module {module}: {row.get('summary')}. "
                f"Matches: {json.dumps(row.get('matches') or {})}"
            ),
        })
    return playbooks
