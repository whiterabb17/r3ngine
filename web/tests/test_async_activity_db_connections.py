"""Async Temporal activities must reach the ORM through a connection-aware wrapper.

Async activities run their ORM calls in an asgiref thread. The Temporal worker's
DjangoAwareThreadPoolExecutor closes connections for sync activities, but it
never sees that thread, so with asgiref's plain `sync_to_async` nothing ever
refreshed the connection cached there. Once Postgres closed it — an idle-session
timeout, a restart — every later call raised

    django.db.utils.InterfaceError: connection already closed

CheckScanQueueStatusActivity is the first step of MasterScanWorkflow, so three
scans sat at 0% for more than a day while reading RUNNING.

`channels.db.database_sync_to_async` runs `close_old_connections()` around each
call, which with CONN_HEALTH_CHECKS drops a dead connection and opens a fresh one.
"""
import os
import re
import unittest

from channels.db import DatabaseSyncToAsync, database_sync_to_async

ACTIVITIES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'reNgine', 'temporal', 'activities',
)

_PLAIN_IMPORT = re.compile(r'^\s*from\s+asgiref\.sync\s+import\s+.*\bsync_to_async\b', re.M)
_PLAIN_DECORATOR = re.compile(r'^\s*@sync_to_async\b', re.M)
_PLAIN_CALL = re.compile(r'(?<![\w.])sync_to_async\s*\(')


def _activity_sources():
    for name in sorted(os.listdir(ACTIVITIES_DIR)):
        if name.endswith('.py'):
            path = os.path.join(ACTIVITIES_DIR, name)
            with open(path, encoding='utf-8') as handle:
                yield name, handle.read()


class TestNoPlainSyncToAsyncInActivities(unittest.TestCase):

    def test_modules_were_found(self):
        self.assertTrue(list(_activity_sources()), 'no activity modules found to check')

    def test_no_module_imports_the_plain_wrapper(self):
        offenders = [name for name, src in _activity_sources() if _PLAIN_IMPORT.search(src)]
        self.assertEqual(
            offenders, [],
            'use channels.db.database_sync_to_async for ORM access in async activities',
        )

    def test_no_function_is_decorated_with_the_plain_wrapper(self):
        offenders = [name for name, src in _activity_sources() if _PLAIN_DECORATOR.search(src)]
        self.assertEqual(offenders, [])

    def test_no_function_is_wrapped_with_the_plain_wrapper(self):
        offenders = [name for name, src in _activity_sources() if _PLAIN_CALL.search(src)]
        self.assertEqual(offenders, [])


class TestTheQueueGateUsesTheSafeWrapper(unittest.TestCase):
    """The activity that actually failed, pinned by name."""

    def test_check_scan_queue_status_imports_database_sync_to_async(self):
        with open(os.path.join(ACTIVITIES_DIR, '__init__.py'), encoding='utf-8') as handle:
            source = handle.read()
        start = source.index('def check_scan_queue_status_activity')
        body = source[start:start + 6000]
        self.assertIn('from channels.db import database_sync_to_async', body)
        self.assertIn('@database_sync_to_async\n    def _get_queue_state', body)
        self.assertIn('@database_sync_to_async\n    def _get_workflow_id', body)


class TestTheWrapperRefreshesConnections(unittest.TestCase):
    """Guard the property the fix relies on, in case channels ever changes it."""

    def test_wrapper_is_the_connection_aware_class(self):
        self.assertIs(database_sync_to_async, DatabaseSyncToAsync)

    def test_thread_handler_is_overridden(self):
        from asgiref.sync import SyncToAsync
        self.assertIsNot(DatabaseSyncToAsync.thread_handler, SyncToAsync.thread_handler)
