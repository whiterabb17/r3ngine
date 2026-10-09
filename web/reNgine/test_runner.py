"""Test runner that turns off persistent database connections.

`CONN_MAX_AGE` is set for production, where a reused connection saves a TCP and
TLS handshake per request. Under test it buys nothing: every test opens and
discards its own state, and a connection carried across a `TransactionTestCase`
boundary is one more thing that can be stale when the next test picks it up.

Honest caveat on why this exists: it was added while chasing a wave of
`OperationalError: could not receive data from server: Bad file descriptor`
failures that appeared after CONN_MAX_AGE was raised. Those failures were later
reproduced and traced to interactions between individual tests, not to
persistent connections, and Django has no connection pool that could have
handed a closed connection back — the original explanation was wrong. The
setting is still right for tests on its own merits, so it stays, but it should
not be credited with fixing anything.

Django has no setting for "persistent connections except in tests", so the
runner is the explicit place to say it once, for every way tests are started.

The runner also installs test-only guards for the same reason — one place,
every way tests are started:

- ``open()``/``os.mkdir``/``os.open`` refuse paths built from mock objects, so
  a task proxy without a real ``results_dir`` fails instead of writing into the
  working directory;
- ``tldextract.extract`` uses the bundled Public Suffix List snapshot instead
  of downloading the live list.
"""
import builtins
import io
import os
import re
import unittest
from unittest.mock import NonCallableMock

import tldextract.tldextract
from django.conf import settings
from django.db import connections
from django.test.runner import DiscoverRunner

_real_open = builtins.open
_real_os_open = os.open
_real_mkdir = os.mkdir
_real_tld_extractor = tldextract.tldextract.TLD_EXTRACTOR

# repr() of Mock/MagicMock/NonCallableMagicMock/AsyncMock, which is what an
# f-string path built from an unconfigured mock attribute contains.
_MOCK_REPR = re.compile(r"<\w*Mock (?:name|spec|id)='")
_CREATE_MODE_CHARS = frozenset('wax+')

# Violations are also recorded here, because a production helper that wraps
# the call in a broad ``except Exception`` would otherwise swallow the
# TypeError and the test would pass after writing into the working directory.
_mock_path_violations: list[str] = []


def _open_rejecting_mocks(file, *args, **kwargs):
    """``open()`` that refuses mock objects as the file argument.

    ``MagicMock.__index__`` returns 1, so ``open(task_proxy.output_path, 'w')``
    on an unconfigured mock opens stdout, and closing it closes fd 1. The next
    Postgres connection then reuses fd 1 and dies with "could not receive data
    from server: Bad file descriptor" in whichever test runs later — this is
    the cross-test failure described in the module docstring.
    """
    if isinstance(file, NonCallableMock):
        raise TypeError(
            'open() received a mock object; it would open file descriptor 1 '
            '(stdout). Give the mocked task proxy a real output_path.'
        )
    mode = args[0] if args else kwargs.get('mode', 'r')
    if isinstance(mode, str) and _CREATE_MODE_CHARS.intersection(mode):
        _reject_mock_path('open', file)
    return _real_open(file, *args, **kwargs)


def _is_mock_path(path) -> bool:
    if isinstance(path, NonCallableMock):
        return True
    try:
        text = os.fsdecode(path)
    except TypeError:
        return False
    return bool(_MOCK_REPR.search(text))


def _reject_mock_path(func_name: str, path) -> None:
    """Refuse to create a file or directory whose path came from a mock.

    ``f'{task.results_dir}/x'`` on an unconfigured ``MagicMock`` task proxy
    yields ``"<MagicMock name='mock.results_dir' id=...>/x"``, a relative path,
    so the code under test creates that directory in the current working
    directory — the repository checkout — and fails outright where the
    checkout is not writable. Give the mocked proxy a real temporary
    ``results_dir`` instead.
    """
    if not _is_mock_path(path):
        return
    message = (
        f'{func_name}() received a path built from a mock object: {path!r}. '
        'Give the mocked task proxy a real (temporary) results_dir/output_path.'
    )
    _mock_path_violations.append(message)
    raise TypeError(message)


def _mkdir_rejecting_mocks(path, *args, **kwargs):
    """``os.mkdir`` guard; ``os.makedirs`` and ``Path.mkdir`` call it too."""
    _reject_mock_path('mkdir', path)
    return _real_mkdir(path, *args, **kwargs)


def _os_open_rejecting_mocks(path, flags, *args, **kwargs):
    """``os.open`` guard for file creation (``Path.touch``, ``tempfile``-style code)."""
    if flags & os.O_CREAT:
        _reject_mock_path('os.open', path)
    return _real_os_open(path, flags, *args, **kwargs)


class _MockPathGuardResultMixin:
    """Turn a swallowed mock-path violation into an error on the test that caused it."""

    def startTest(self, test):
        self._mock_path_mark = len(_mock_path_violations)
        self._mock_path_problems = len(self.errors) + len(self.failures)
        super().startTest(test)

    def stopTest(self, test):
        new = _mock_path_violations[getattr(self, '_mock_path_mark', 0):]
        already_failed = len(self.errors) + len(self.failures) > getattr(
            self, '_mock_path_problems', 0
        )
        if new and not already_failed:
            error = TypeError('\n'.join(new))
            self.addError(test, (TypeError, error, None))
        super().stopTest(test)


class RengineTestRunner(DiscoverRunner):
    """DiscoverRunner with CONN_MAX_AGE forced to 0 for every alias."""

    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        builtins.open = _open_rejecting_mocks
        # pathlib writes through io.open, which is a separate name for open().
        io.open = _open_rejecting_mocks
        os.mkdir = _mkdir_rejecting_mocks
        os.open = _os_open_rejecting_mocks
        # tldextract.extract() fetches the live Public Suffix List on first use
        # and caches it under ~/.cache. Tests use the snapshot bundled with the
        # package instead: no network, no cache directory. Production keeps the
        # module default (live list, cached).
        tldextract.tldextract.TLD_EXTRACTOR = tldextract.TLDExtract(
            suffix_list_urls=(), cache_dir=None
        )

    def teardown_test_environment(self, **kwargs):
        builtins.open = _real_open
        io.open = _real_open
        os.mkdir = _real_mkdir
        os.open = _real_os_open
        tldextract.tldextract.TLD_EXTRACTOR = _real_tld_extractor
        super().teardown_test_environment(**kwargs)

    def get_resultclass(self):
        base = super().get_resultclass() or unittest.TextTestResult
        return type('RengineTestResult', (_MockPathGuardResultMixin, base), {})

    def setup_databases(self, **kwargs):
        for alias in connections:
            # settings_dict is the same object as settings.DATABASES[alias], so
            # one assignment would do; both are written to keep the intent
            # obvious if Django ever stops sharing them.
            settings.DATABASES[alias]['CONN_MAX_AGE'] = 0
            connections[alias].settings_dict['CONN_MAX_AGE'] = 0
            # Production Postgres sets statement_timeout=5m. TransactionTestCase
            # teardown TRUNCATE of a freshly migrated schema can exceed that on a
            # busy host and cancel the flush mid-suite.
            db_options = settings.DATABASES[alias].setdefault('OPTIONS', {})
            existing = db_options.get('options', '')
            if 'statement_timeout' not in existing:
                extra = '-c statement_timeout=0'
                db_options['options'] = f'{existing} {extra}'.strip()
            connections[alias].settings_dict['OPTIONS'] = db_options
        connections.close_all()
        return super().setup_databases(**kwargs)
