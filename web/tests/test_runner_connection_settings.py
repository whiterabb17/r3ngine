"""Persistent connections must be off while tests run.

CONN_MAX_AGE=60 is right for production but breaks TransactionTestCase: the
framework closes connections between tests and the pool keeps returning the
closed one, which shows up as "could not receive data from server: Bad file
descriptor" across whole test classes rather than in one obvious place.
"""
from django.db import connections
from django.test import TestCase, TransactionTestCase


class ConnectionMaxAgeTests(TestCase):

    def test_persistent_connections_are_disabled_in_tests(self) -> None:
        for alias in connections:
            self.assertEqual(
                connections[alias].settings_dict['CONN_MAX_AGE'], 0,
                f'{alias}: the test runner must clear CONN_MAX_AGE',
            )

    def test_runner_is_the_project_one(self) -> None:
        from django.conf import settings
        self.assertEqual(settings.TEST_RUNNER, 'reNgine.test_runner.RengineTestRunner')


class TransactionalConnectionReuseTests(TransactionTestCase):
    """The case that actually broke: a query after a transactional teardown."""

    def test_query_after_transaction_teardown_succeeds(self) -> None:
        from startScan.models import ScanActivity
        self.assertEqual(ScanActivity.objects.count(), 0)
        self.assertEqual(ScanActivity.objects.filter(name='nothing').count(), 0)
