"""Nuclei -stats JSON from go-executor must not fail parsing."""
from django.test import SimpleTestCase

from reNgine.tasks.parsers import is_nuclei_finding, parse_nuclei_result


# Real -stats line shape from nuclei -j -stats (go-executor stdout).
STATS_LINE = {
	'duration': '0:43:05',
	'errors': '81155',
	'hosts': '1266',
	'matched': '0',
	'percent': '37',
	'requests': '93802',
	'rps': '36',
	'startedAt': '2026-09-24T23:20:08.944665892Z',
	'templates': '61',
	'total': '251934',
}

FINDING_LINE = {
	'template': 'http/misconfiguration/http-missing-security-headers.yaml',
	'template-url': 'https://example/template',
	'template-id': 'http-missing-security-headers',
	'info': {
		'name': 'HTTP Missing Security Headers',
		'severity': 'info',
		'description': 'Missing headers',
		'tags': ['misc', 'misconfig'],
		'classification': {},
		'reference': [],
	},
	'type': 'http',
	'matched-at': 'https://example.com/',
}


class NucleiStatsParseTests(SimpleTestCase):
	def test_stats_line_is_not_a_finding(self):
		self.assertFalse(is_nuclei_finding(STATS_LINE))
		self.assertIsNone(parse_nuclei_result(STATS_LINE))

	def test_finding_line_parses(self):
		self.assertTrue(is_nuclei_finding(FINDING_LINE))
		vuln = parse_nuclei_result(FINDING_LINE)
		self.assertIsNotNone(vuln)
		self.assertEqual(vuln['template_id'], 'http-missing-security-headers')
		self.assertEqual(vuln['name'], 'HTTP Missing Security Headers')

	def test_non_dict_rejected(self):
		self.assertFalse(is_nuclei_finding('[INF] Templates loaded'))
		self.assertIsNone(parse_nuclei_result('[INF] Templates loaded'))
		self.assertFalse(is_nuclei_finding({'info': 'not-a-dict'}))
