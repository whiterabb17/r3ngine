"""grpcurl must probe ports the scan found, not the port the URL happened to use.

Every discovered web host used to be probed as `grpcurl -plaintext host:443`.
That cannot succeed whatever is listening: -plaintext speaks cleartext and 443
is a TLS port. It cost a three-second connect timeout per host and filled the
command log with "Failed to dial".
"""
import os
from unittest import TestCase

from reNgine.tasks.crawl import grpc_probe_targets

CRAWL_SOURCE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'reNgine', 'tasks', 'crawl', 'api_discovery.py'
)


def _grpcurl_block():
    with open(CRAWL_SOURCE, encoding='utf-8') as handle:
        source = handle.read()
    start = source.index('# grpcurl')
    return source[start:source.index("grpcurl: finished", start)]


class TestPortSelection(TestCase):

    def test_well_known_grpc_port_is_probed_in_plaintext(self):
        self.assertEqual(
            grpc_probe_targets([(50051, None)], 443, True),
            [(50051, False)],
        )

    def test_tls_port_is_probed_with_tls(self):
        self.assertEqual(
            grpc_probe_targets([(443, 'https')], 443, True),
            [(443, True)],
        )

    def test_service_name_marks_a_port_worth_probing(self):
        """An unusual port whose service says grpc is still a candidate."""
        self.assertEqual(
            grpc_probe_targets([(7777, 'grpc')], 80, False),
            [(7777, False)],
        )

    def test_service_name_marks_tls_on_an_unusual_port(self):
        self.assertEqual(
            grpc_probe_targets([(7777, 'grpc-ssl')], 80, False),
            [(7777, True)],
        )

    def test_uninteresting_open_ports_are_not_probed(self):
        """The port scan ran and found nothing gRPC-shaped — probe nothing."""
        self.assertEqual(
            grpc_probe_targets([(22, 'ssh'), (25, 'smtp'), (3306, 'mysql')], 443, True),
            [],
        )

    def test_results_are_ordered_and_capped(self):
        ports = [(p, None) for p in (50052, 50051, 9443, 9091, 9090, 8443, 8081, 8080, 443)]
        targets = grpc_probe_targets(ports, 443, True)
        self.assertEqual(len(targets), 5)
        self.assertEqual([p for p, _ in targets], sorted(p for p, _ in targets))
        self.assertEqual(targets[0], (443, True))

    def test_duplicate_port_entries_collapse(self):
        """The same port can arrive once per IP address of the host."""
        self.assertEqual(
            grpc_probe_targets([(50051, None), (50051, None)], 80, False),
            [(50051, False)],
        )


class TestFallbackWithoutPortScanData(TestCase):
    """A scan configured without port_scan must not lose gRPC coverage."""

    def test_https_url_falls_back_to_tls_not_plaintext(self):
        self.assertEqual(grpc_probe_targets([], 443, True), [(443, True)])

    def test_http_url_falls_back_to_plaintext(self):
        self.assertEqual(grpc_probe_targets([], 80, False), [(80, False)])

    def test_explicit_url_port_is_kept(self):
        self.assertEqual(grpc_probe_targets([], 8090, False), [(8090, False)])


class TestEveryProbeIsBounded(TestCase):
    """-connect-timeout bounds the handshake only.

    A host that completes the handshake and then never answers the reflection
    request holds grpcurl open indefinitely. Two such hosts consumed the whole
    four-hour Tier 3 budget of a scan, three attempts running, because
    run_command's default timeout is 43200 seconds.
    """

    def setUp(self):
        self.block = _grpcurl_block()

    def test_call_carries_an_overall_deadline(self):
        self.assertIn('-max-time', self.block)

    def test_call_still_bounds_the_handshake(self):
        self.assertIn('-connect-timeout', self.block)

    def test_subprocess_has_its_own_timeout(self):
        self.assertIn('timeout=_GRPC_COMMAND_TIMEOUT', self.block)

    def test_the_bounds_are_ordered(self):
        from reNgine.tasks.crawl import (
            _GRPC_COMMAND_TIMEOUT, _GRPC_CONNECT_TIMEOUT, _GRPC_MAX_TIME,
        )
        self.assertLess(_GRPC_CONNECT_TIMEOUT, _GRPC_MAX_TIME)
        self.assertLess(_GRPC_MAX_TIME, _GRPC_COMMAND_TIMEOUT)

    def test_worst_case_per_host_stays_small(self):
        """Five ports at the subprocess bound must not approach a tier budget."""
        from reNgine.tasks.crawl import _GRPC_COMMAND_TIMEOUT, _GRPC_MAX_PORTS_PER_HOST
        self.assertLessEqual(_GRPC_COMMAND_TIMEOUT * _GRPC_MAX_PORTS_PER_HOST, 300)


class TestTheOriginalDefect(TestCase):

    def test_plaintext_is_never_chosen_for_443(self):
        for open_ports in ([], [(443, 'https')], [(443, None)]):
            for port, use_tls in grpc_probe_targets(open_ports, 443, True):
                if port == 443:
                    self.assertTrue(
                        use_tls,
                        'port 443 must never be probed with -plaintext',
                    )
