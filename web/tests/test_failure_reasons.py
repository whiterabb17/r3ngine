"""Tests for ``reNgine.failure_reasons.classify_failure``.

Every message asserted here is a shape this codebase really writes into
``ScanActivity.error_message``; each sample carries the file and line it comes
from. Two properties are load-bearing:

* an unrecognised message must land in ``unknown`` — the classifier never
  invents a cause;
* a hint must be safe for every role. ``error_message`` is served to all roles
  by the scan summary API while ``traceback`` is restricted to
  sys_admin/penetration_tester, so a hint may never echo a URL, host,
  credential or raw exception text (security rule 8.1).

Hosts and domains below are anonymised (RFC 2606 / RFC 5737 ranges).
"""
import unittest

from reNgine.failure_reasons import CATEGORY_HINTS, classify_failure

# (label, error_message, traceback, expected category).
# Messages are quoted as stored: ``_run_task`` writes ``repr(exc)`` into
# ``error_message`` (reNgine/temporal/activities/core.py:517).
SAMPLES: list[tuple[str, str, str, str]] = [
    (
        # acunetix.py:309 reason, wrapped by activities/core.py:505.
        'acunetix missing vault keys',
        'Exception(\'Task acunetix_scan failed: Acunetix API keys not fully '
        'configured in vault.\')',
        '',
        'missing_configuration',
    ),
    (
        # tasks/__init__.py:302 — a disabled feature, not a broken tool.
        'llm disabled',
        'Exception("Task generate_impact_assessment failed: LLM disabled '
        '(LLM_ENABLED unset) — skipping")',
        '',
        'missing_configuration',
    ),
    (
        # activities/core.py:506 — the generic "gave up" shape. vigolium's
        # phases take this path: their proxy retry only reaches the log
        # (tasks/vigolium.py:299-302), never self.error.
        'task returned False',
        "Exception('Task vigolium_analysis execution returned False/failed.')",
        '',
        'tool_failure',
    ),
    (
        # acunetix.py:380 — the tool never finished within its own retry budget.
        'acunetix exhausted its retries',
        'Exception(\'Task acunetix_scan failed: Acunetix scan for '
        'shop.example.com timed out after 120 retries.\')',
        '',
        'tool_failure',
    ),
    (
        # acunetix.py:494-497 — the class name is exposed, the AWVS URL is not.
        'acunetix could not reach AWVS',
        'Exception(\'Task acunetix_scan failed: Acunetix scan for '
        'shop.example.com failed with ConnectionError. See the server logs '
        'for details.\')',
        '',
        'network_error',
    ),
    (
        # activities/core.py:385-389, copied onto the row by
        # activities/scan_lifecycle.py:430-432.
        'user aborted the scan',
        "ApplicationError('[port_scan] Scan 42 was aborted by the user. "
        "Workflow cancelled.')",
        '',
        'temporal_cancelled',
    ),
    (
        # activities/core.py:378-383.
        'scan deleted mid-run',
        "ApplicationError('[subdomain_discovery] ScanHistory 42 no longer "
        "exists — scan was deleted. Workflow cancelled.')",
        '',
        'temporal_cancelled',
    ),
    (
        # activities/scan_lifecycle.py:417, fanned out to every RUNNING/INITIATED
        # row at :432 — what an operator sees after the box rebooted.
        'workflow crashed with the container',
        'Scan workflow crashed.',
        '',
        'worker_restart',
    ),
    (
        # startScan/views.py:1164 — same family, different producer.
        'process killed by a restart',
        'Report generation timed out. The process may have been interrupted '
        'by a server restart.',
        '',
        'worker_restart',
    ),
    (
        # Temporal's own text when the heartbeat thread in
        # activities/core.py:410-469 stops reaching the server
        # (heartbeat_timeout is set on every activity call in
        # temporal/workflows/master_scan.py, e.g. :145).
        'heartbeat timeout',
        'ActivityError: activity Heartbeat timeout',
        '',
        'heartbeat_timeout',
    ),
    (
        # Temporal's start_to_close expiry for the same activity calls.
        'activity timeout',
        'ActivityError: activity StartToClose timeout',
        '',
        'activity_timeout',
    ),
    (
        # A proxy from get_random_proxy (common_func.py:1305) that is refused.
        # The keywords mirror _PROXY_DEAD_KEYWORDS (common_func.py:910).
        'proxy refused the connection',
        'Exception(\'Task http_crawl failed: ProxyError(MaxRetryError('
        '"HTTPSConnectionPool(host=\\\'api.example.net\\\', port=443): Max '
        'retries exceeded with url: / (Caused by ProxyError(\\\'Cannot '
        'connect to proxy.\\\'))"))\')',
        '',
        'proxy_failure',
    ),
    (
        'postgres unavailable',
        'OperationalError(\'could not connect to server: Connection refused\\n'
        '\\tIs the server running on host "db" and accepting TCP/IP '
        'connections on port 5432?\')',
        '',
        'database_error',
    ),
    (
        # reNgine/utils/graph.py sync path — Neo4j down during SyncGraphActivity.
        'neo4j unavailable',
        "ServiceUnavailable('Unable to retrieve routing information')",
        '',
        'database_error',
    ),
    (
        'target unreachable',
        'ConnectionError(\'HTTPConnectionPool(host=\\\'198.51.100.7\\\', '
        'port=80): Max retries exceeded\')',
        '',
        'network_error',
    ),
    (
        # temporal/workflows/master_scan.py:860 — the fallback the workflow uses
        # when it captured no reason. It names no cause, so neither do we.
        'workflow failed with no captured reason',
        'Workflow failed during execution',
        '',
        'unknown',
    ),
    (
        'unrecognised message',
        "Exception('boom')",
        '',
        'unknown',
    ),
    (
        # No message at all: the traceback is the only signal left.
        'classified from the traceback alone',
        '',
        'Traceback (most recent call last):\n'
        '  File "/usr/src/app/reNgine/tasks/osint.py", line 82, in osint\n'
        '    resp = requests.get(url)\n'
        'requests.exceptions.ConnectionError: [Errno -2] Name or service not '
        'known\n',
        'network_error',
    ),
    (
        # Regression: every _run_task traceback contains TemporalTaskProxy
        # frames (activities/core.py:65, :515). That word must not drag an
        # unrelated failure into proxy_failure.
        'proxy frames in the traceback are not a proxy failure',
        "Exception('kaboom')",
        'Traceback (most recent call last):\n'
        '  File "/usr/src/app/reNgine/temporal/activities/core.py", line '
        '515, in _run_task\n'
        '    proxy.update_scan_activity(FAILED_TASK)\n'
        "AttributeError: 'TemporalTaskProxy' object has no attribute 'foo'\n",
        'unknown',
    ),
]

# Substrings that must never reach an operator through a hint: the dynamic
# parts of the samples above, plus exception syntax.
FORBIDDEN_IN_HINTS: tuple[str, ...] = (
    '://',
    'http',
    'example.com',
    'example.net',
    '198.51.100.7',
    'exception(',
    'error(',
    'traceback',
    'proxyerror',
    'vigolium',
    'acunetix',
    '5432',
    '42',
)


class ClassifyFailureTests(unittest.TestCase):
    """The category is derived from the real message shapes, never guessed."""

    def test_real_message_shapes_get_their_category(self) -> None:
        for label, message, trace, expected in SAMPLES:
            with self.subTest(label):
                result = classify_failure(message, trace)
                self.assertIsNotNone(result)
                self.assertEqual(result['category'], expected)

    def test_nothing_to_classify_returns_none(self) -> None:
        for message, trace in ((None, None), ('', ''), ('   ', '\n')):
            with self.subTest(message=message, traceback=trace):
                self.assertIsNone(classify_failure(message, trace))

    def test_unknown_hint_does_not_claim_a_cause(self) -> None:
        result = classify_failure("Exception('boom')", '')
        self.assertEqual(result['category'], 'unknown')
        self.assertIn('No known failure pattern matched', result['hint'])


class HintSafetyTests(unittest.TestCase):
    """The hint is shown to every role, so it must carry no input data."""

    def test_hint_is_the_fixed_phrase_for_its_category(self) -> None:
        for label, message, trace, _expected in SAMPLES:
            with self.subTest(label):
                result = classify_failure(message, trace)
                self.assertEqual(
                    result['hint'], CATEGORY_HINTS[result['category']],
                    'the hint must come from the fixed table, not the input',
                )

    def test_hint_never_echoes_the_error_text(self) -> None:
        for label, message, trace, _expected in SAMPLES:
            with self.subTest(label):
                hint = classify_failure(message, trace)['hint'].lower()
                for forbidden in FORBIDDEN_IN_HINTS:
                    self.assertNotIn(
                        forbidden, hint,
                        'a hint must not expose a URL, host or exception text',
                    )

    def test_every_hint_is_one_short_safe_sentence(self) -> None:
        for category, hint in CATEGORY_HINTS.items():
            with self.subTest(category):
                self.assertTrue(hint.endswith('.'))
                self.assertLessEqual(len(hint), 160)
                for forbidden in FORBIDDEN_IN_HINTS:
                    self.assertNotIn(forbidden, hint.lower())
