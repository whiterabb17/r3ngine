"""Local Django settings for running tests against the dockerized Postgres.

Uses the already-running `r3ngine-db-1` on 127.0.0.1:5432 (host-mapped), with
in-memory cache/channels so Redis/Neo4j are optional. Point manage.py at this
module:

    set DJANGO_SETTINGS_MODULE=reNgine.settings_test_local
    set PYTHONPATH=web
    .venv\\Scripts\\python web\\manage.py test tests.test_scan_init

Paths under web/.local_test/ are created on import and are gitignored.
Credentials default from the repo-root .env when present; POSTGRES_HOST is
forced to 127.0.0.1 so the host venv can reach the published container port.
"""
from __future__ import annotations

import os
from pathlib import Path

_WEB_ROOT = Path(__file__).resolve().parent.parent
_REPO_ROOT = _WEB_ROOT.parent
_LOCAL = _WEB_ROOT / '.local_test'
_LOCAL.mkdir(parents=True, exist_ok=True)
(_LOCAL / 'results').mkdir(exist_ok=True)
(_LOCAL / 'assessments').mkdir(exist_ok=True)

# Load compose .env if present (POSTGRES_*, NEO4J_*, etc.) without overriding
# values already set in the shell.
_env_file = _REPO_ROOT / '.env'
if not _env_file.is_file():
    # Worktree may not have its own .env — fall back to the main checkout.
    _env_file = _REPO_ROOT.parent / 'r3ngine' / '.env'
if _env_file.is_file():
    for _line in _env_file.read_text(encoding='utf-8').splitlines():
        _line = _line.strip()
        if not _line or _line.startswith('#') or '=' not in _line:
            continue
        _key, _, _val = _line.partition('=')
        _key = _key.strip()
        _val = _val.strip().strip('"').strip("'")
        os.environ.setdefault(_key, _val)

# Must be set before importing reNgine.settings — env() has no defaults for these.
_defaults = {
    'RENGINE_HOME': str(_LOCAL),
    'RENGINE_RESULTS': str(_LOCAL / 'results'),
    'ASSESSMENTS_ROOT': str(_LOCAL / 'assessments'),
    'EVIDENCE_STORAGE_ROOT': str(_LOCAL / 'assessments' / 'evidence'),
    'POSTGRES_DB': 'rengine',
    'POSTGRES_USER': 'rengine',
    'POSTGRES_PASSWORD': 'rengine',
    # Host-mapped docker port, not the compose service name.
    'POSTGRES_HOST': '127.0.0.1',
    'POSTGRES_PORT': '5432',
    'POSTGRES_SSLMODE': 'disable',
    'DEBUG': 'True',
    'DOMAIN_NAME': 'localhost:8000',
    'NEO4J_PASSWORD': 'unused',
    'REDIS_URL': 'redis://127.0.0.1:6379/0',
}
for key, value in _defaults.items():
    os.environ.setdefault(key, value)

# Always prefer the published localhost port when running outside compose.
os.environ['POSTGRES_HOST'] = '127.0.0.1'
os.environ.setdefault('POSTGRES_SSLMODE', 'disable')


# ---------------------------------------------------------------------------
# Stub heavy optional third-party imports that the URLconf pulls in transitively
# (llm.py → langchain; report views → weasyprint). Unit tests under this
# settings module do not exercise those code paths.
# ---------------------------------------------------------------------------
import sys
import types


def _ensure_stub(name: str, **attrs) -> types.ModuleType:
    mod = sys.modules.get(name)
    if mod is None:
        mod = types.ModuleType(name)
        sys.modules[name] = mod
    for key, value in attrs.items():
        setattr(mod, key, value)
    return mod


_ensure_stub('langchain_community')
_ensure_stub('langchain_community.llms', Ollama=type('Ollama', (), {}))
_ensure_stub(
    'weasyprint',
    HTML=type('HTML', (), {'__init__': lambda *a, **k: None}),
    CSS=type('CSS', (), {'__init__': lambda *a, **k: None}),
)


from reNgine.settings import *  # noqa: E402,F403

# Re-assert Postgres against the running container (settings already read env).
DATABASES['default'].update({  # noqa: F405
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': os.environ['POSTGRES_DB'],
    'USER': os.environ['POSTGRES_USER'],
    'PASSWORD': os.environ['POSTGRES_PASSWORD'],
    'HOST': '127.0.0.1',
    'PORT': os.environ.get('POSTGRES_PORT', '5432'),
    'CONN_MAX_AGE': 0,
    'OPTIONS': {
        'sslmode': 'disable',
    },
    # Separate test databases let two suites run side by side (None keeps
    # Django's default, test_<NAME>).
    'TEST': {'NAME': os.environ.get('RENGINE_TEST_DB_NAME') or None},
})


class _DisableMigrations(dict):
    """Tell Django to invent schema from models instead of applying migrations."""

    def __contains__(self, item):  # type: ignore[override]
        return True

    def __getitem__(self, item):  # type: ignore[override]
        return None


MIGRATION_MODULES = _DisableMigrations()

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'r3ngine-test-local',
    }
}

CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    }
}

# Cookies marked Secure break some client tests on http://testserver.
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False

# Container log paths do not exist on a Windows host.
LOGGING['handlers']['error_file']['filename'] = str(_LOCAL / 'errors.log')  # noqa: F405
LOGGING['handlers']['temporal_file']['filename'] = str(_LOCAL / 'temporal.log')  # noqa: F405

# A passing suite printed ~9k lines of INFO/DEBUG from the code under test,
# burying the failures. Console output is limited to errors; assertLogs attaches
# its own handler, so tests that check log output are unaffected.
for _handler in ('console', 'task'):
    LOGGING['handlers'][_handler]['level'] = os.environ.get('RENGINE_TEST_LOG_LEVEL', 'ERROR')  # noqa: F405
