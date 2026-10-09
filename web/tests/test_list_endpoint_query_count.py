"""Query-count regression tests for the heavy list endpoints the UI pages through.

Each test requests a list endpoint with one fully-populated row, then with
five, and asserts both requests cost the same number of queries. A per-row
query (a SerializerMethodField that filters, a nested relation that was not
prefetched) makes the counts diverge; the failure message lists the SQL that
grew so the offending field is easy to find.

Absolute numbers are deliberately not asserted: the invariant is that the
cost of a page does not depend on how many rows are on it.
"""
import re
from collections import Counter

from django.contrib.auth import get_user_model
from django.db import connection
from django.core.cache import cache
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from dashboard.models import Project
from recon_note.models import TodoNote
from scanEngine.models import EngineType, InterestingLookupModel
from startScan.models import (
	AuthCandidate, CountryISO, CveId, CweId, DirectoryFile, DirectoryScan,
	EndPoint, Exposure, IpAddress, Parameter, Port, ScanActivity, ScanHistory,
	Screenshot, SubScan, Subdomain, Technology, TemporalSchedule,
	ValidationResult, Vulnerability, VulnerabilityReference, VulnerabilityTags,
	Waf, WafBypassFinding,
)
from targetApp.models import (
	DNSRecord, Domain, DomainInfo, DomainRegistration, HistoricalIP, NameServer,
	Organization, Registrar, RelatedDomain, WhoisStatus,
)
from reNgine.definitions import RUNNING_TASK, SUCCESS_TASK

SLUG = 'list-query-count'

def _normalise(sql):
	"""Collapse literals so the same statement for different rows compares equal."""
	sql = re.sub(r"'[^']*'", "'?'", sql)
	sql = re.sub(r'\b\d+\b', '?', sql)
	# Prefetch IN lists differ in length between the two runs; fold them away.
	folded = None
	while folded != sql:
		folded, sql = sql, re.sub(r'\(\?(?:, \?)*\)', '?', sql)
	return sql


class ListQueryCountMixin:
	"""Shared fixtures and the one-row versus N-row comparison."""

	url = None
	extra_rows = 4

	@classmethod
	def setUpTestData(cls):
		cls.user = get_user_model().objects.create_superuser(
			username='qc-admin', email='qc-admin@example.test', password='unused',
		)
		cls.project = Project.objects.create(
			name='list-query-count', slug=SLUG, insert_date=timezone.now()
		)
		cls.engine = EngineType.objects.create(
			engine_name='qc-list-engine', yaml_configuration=''
		)
		cls.country = CountryISO.objects.create(iso='ZZ', name='Testland')
		# Both a default and a custom lookup, so is_interesting runs its full path.
		InterestingLookupModel.objects.create(keywords='admin', custom_type=False)
		InterestingLookupModel.objects.create(keywords='portal', custom_type=True)

	def setUp(self):
		# The throttle history lives in the cache and persists across tests in
		# one process; a query-count test must never measure a 429.
		cache.clear()
		self.client = APIClient()
		self.client.force_login(self.user)
		self.client.force_authenticate(user=self.user)
		self.row_index = 0
		self.subscans = {}

	def add_rows(self, count):
		for _ in range(count):
			self.add_row(self.row_index)
			self.row_index += 1

	def add_row(self, index):
		raise NotImplementedError

	def query_params(self):
		return {}

	def fetch(self):
		params = {'format': 'json', **self.query_params()}
		with CaptureQueriesContext(connection) as captured:
			response = self.client.get(self.url, params)
		self.assertEqual(response.status_code, 200, response.content[:500])
		return captured, response

	def row_count(self, response):
		payload = response.json()
		if isinstance(payload, dict):
			for key in ('results', 'data'):
				if key in payload:
					return len(payload[key])
		return len(payload)

	def assert_flat(self):
		self.add_rows(1)
		one, response = self.fetch()
		self.assertEqual(self.row_count(response), 1)

		self.add_rows(self.extra_rows)
		many, response = self.fetch()
		self.assertEqual(self.row_count(response), 1 + self.extra_rows)

		grown = Counter(_normalise(q['sql']) for q in many.captured_queries)
		grown.subtract(Counter(_normalise(q['sql']) for q in one.captured_queries))
		growth = '\n'.join(
			f'  +{delta}: {sql[:300]} ... {sql[-200:]}' for sql, delta in grown.items() if delta > 0
		)
		self.assertEqual(
			len(one), len(many),
			f'{self.url} cost {len(many)} queries for {1 + self.extra_rows} rows '
			f'against {len(one)} for one. Statements that grew:\n{growth}'
		)

	# Fixture helpers shared by the endpoint-specific cases.

	def make_domain(self, index):
		contact = DomainRegistration.objects.create(name=f'contact-{index}')
		info = DomainInfo.objects.create(
			registrar=Registrar.objects.create(name=f'registrar-{index}'),
			registrant=contact, admin=contact, tech=contact,
		)
		info.status.add(WhoisStatus.objects.create(name=f'ok-{index}'))
		info.name_servers.add(NameServer.objects.create(name=f'ns{index}.example.test'))
		info.dns_records.add(
			DNSRecord.objects.create(name=f'192.0.2.{index + 1}', type='a')
		)
		related = RelatedDomain.objects.create(name=f'related{index}.example.test')
		info.related_domains.add(related)
		info.related_tlds.add(related)
		info.similar_domains.add(related)
		info.historical_ips.add(HistoricalIP.objects.create(
			ip=f'192.0.2.{index + 101}', location='-', owner='-', last_seen='-',
		))
		schedule = TemporalSchedule.objects.create(
			schedule_id=f'qc-schedule-{index}', name='qc', workflow_type='MasterScanWorkflow',
		)
		domain = Domain.objects.create(
			name=f'target{index}.example.test', project=self.project,
			insert_date=timezone.now(), domain_info=info,
			monitor_engine=self.engine, temporal_schedule=schedule,
		)
		schedule.domain = domain
		schedule.save()
		Organization.objects.create(
			name=f'org-{index}', project=self.project, insert_date=timezone.now(),
		).domains.add(domain)
		return domain

	def make_scan(self, domain):
		scan = ScanHistory.objects.create(
			domain=domain, scan_type=self.engine, scan_status=SUCCESS_TASK,
			start_scan_date=timezone.now(), stop_scan_date=timezone.now(),
			initiated_by=self.user, tasks=['subdomain_discovery'],
		)
		ScanActivity.objects.create(
			scan_of=scan, name='subdomain_discovery', title='Subdomain Discovery',
			tier=1, status=SUCCESS_TASK, time=timezone.now(),
		)
		return scan

	def make_subdomain(self, scan, domain, index):
		subdomain = Subdomain.objects.create(
			scan_history=scan, target_domain=domain,
			name=f'portal{index}.example.test', page_title='Admin portal',
			http_status=200,
		)
		port = Port.objects.create(number=443, service_name='https')
		ip = IpAddress.objects.create(address=f'192.0.2.{index + 1}', geo_iso=self.country)
		ip.ports.add(port)
		subdomain.ip_addresses.add(ip)
		subdomain.technologies.add(Technology.objects.create(name=f'nginx-{index}'))
		subdomain.waf.add(Waf.objects.create(name=f'waf-{index}'))
		dirscan = DirectoryScan.objects.create(command_line='ffuf')
		dirscan.directory_files.add(DirectoryFile.objects.create(name='admin', url='/admin'))
		subdomain.directories.add(dirscan)
		WafBypassFinding.objects.create(subdomain=subdomain, technique='case')
		Screenshot.objects.create(
			subdomain=subdomain, scan_history=scan,
			url=f'https://portal{index}.example.test/', screenshot_path='shot.png',
		)
		TodoNote.objects.create(
			title='check', scan_history=scan, subdomain=subdomain, is_done=False,
			project=self.project,
		)
		subscan = SubScan.objects.create(
			scan_history=scan, subdomain=subdomain, engine=self.engine,
			status=RUNNING_TASK, start_scan_date=timezone.now(),
		)
		subscan.subdomain_subscan_ids.add(subdomain)
		ip.ip_subscan_ids.add(subscan)
		dirscan.dir_subscan_ids.add(subscan)
		self.subscans[subdomain.id] = subscan
		return subdomain

	def make_endpoint(self, scan, domain, subdomain, index):
		endpoint = EndPoint.objects.create(
			scan_history=scan, target_domain=domain, subdomain=subdomain,
			http_url=f'https://portal{index}.example.test/login', http_status=200,
		)
		endpoint.techs.add(Technology.objects.create(name=f'php-{index}'))
		endpoint.endpoint_subscan_ids.add(self.subscans[subdomain.id])
		Parameter.objects.create(endpoint=endpoint, name='next', scan_history=scan)
		AuthCandidate.objects.create(
			scan_history=scan, subdomain=subdomain, endpoint=endpoint,
			target=endpoint.http_url, protocol='http', port=443,
		)
		return endpoint

	def make_vulnerability(self, scan, domain, subdomain, endpoint, index, severity=2):
		exposure = Exposure.objects.create(
			scan_history=scan, target_domain=domain, subdomain=subdomain,
			endpoint=endpoint, type=['Login page'],
		)
		vuln = Vulnerability.objects.create(
			scan_history=scan, target_domain=domain, subdomain=subdomain,
			endpoint=endpoint, exposure=exposure, name=f'finding-{index}',
			severity=severity, http_url=endpoint.http_url,
			discovered_date=timezone.now(),
		)
		vuln.tags.add(VulnerabilityTags.objects.create(name=f'tag-{index}'))
		vuln.references.add(
			VulnerabilityReference.objects.create(url=f'https://ref.example.test/{index}')
		)
		cve = CveId.objects.create(name=f'CVE-2000-{1000 + index}')
		cve.related_cves.add(CveId.objects.create(name=f'CVE-2000-{5000 + index}'))
		vuln.cve_ids.add(cve)
		vuln.cwe_ids.add(CweId.objects.create(name=f'CWE-{100 + index}'))
		vuln.vuln_subscan_ids.add(self.subscans[subdomain.id])
		ValidationResult.objects.create(vulnerability=vuln, tool='replay')
		return vuln


class SubdomainDatatableQueryCountTests(ListQueryCountMixin, TestCase):
	url = '/api/listDatatableSubdomain/'

	def setUp(self):
		super().setUp()
		self.domain = self.make_domain(0)
		self.scan = self.make_scan(self.domain)

	def add_row(self, index):
		subdomain = self.make_subdomain(self.scan, self.domain, index)
		endpoint = self.make_endpoint(self.scan, self.domain, subdomain, index)
		for severity in range(5):
			self.make_vulnerability(
				self.scan, self.domain, subdomain, endpoint, index * 10 + severity, severity
			)

	def query_params(self):
		return {'project': SLUG, 'scan_id': self.scan.id}

	def test_list_cost_is_flat(self):
		self.assert_flat()

	def test_counts_match_the_model_properties(self):
		"""The annotated counts must agree with the per-row properties they replace."""
		self.add_rows(2)
		_, response = self.fetch()
		rows = {row['id']: row for row in response.json()['results']}
		for subdomain in Subdomain.objects.filter(scan_history=self.scan):
			row = rows[subdomain.id]
			self.assertEqual(row['endpoint_count'], subdomain.get_endpoint_count)
			self.assertEqual(row['info_count'], subdomain.get_info_count)
			self.assertEqual(row['low_count'], subdomain.get_low_count)
			self.assertEqual(row['medium_count'], subdomain.get_medium_count)
			self.assertEqual(row['high_count'], subdomain.get_high_count)
			self.assertEqual(row['critical_count'], subdomain.get_critical_count)
			self.assertEqual(row['directories_count'], subdomain.get_directories_count)
			self.assertEqual(row['subscan_count'], subdomain.get_subscan_count)
			self.assertEqual(
				row['todos_count'],
				len(subdomain.get_todos.filter(is_done=False)),
			)
			self.assertTrue(row['is_interesting'])


class EndpointListQueryCountTests(ListQueryCountMixin, TestCase):
	url = '/api/listEndpoints/'

	def setUp(self):
		super().setUp()
		self.domain = self.make_domain(0)
		self.scan = self.make_scan(self.domain)

	def add_row(self, index):
		subdomain = self.make_subdomain(self.scan, self.domain, index)
		self.make_endpoint(self.scan, self.domain, subdomain, index)

	def query_params(self):
		return {'scan_history': self.scan.id}

	def test_list_cost_is_flat(self):
		self.assert_flat()


class VulnerabilityListQueryCountTests(ListQueryCountMixin, TestCase):
	url = '/api/listVulnerability/'

	def setUp(self):
		super().setUp()
		self.domain = self.make_domain(0)
		self.scan = self.make_scan(self.domain)

	def add_row(self, index):
		subdomain = self.make_subdomain(self.scan, self.domain, index)
		endpoint = self.make_endpoint(self.scan, self.domain, subdomain, index)
		self.make_vulnerability(self.scan, self.domain, subdomain, endpoint, index)

	def query_params(self):
		return {'scan_history': self.scan.id}

	def test_list_cost_is_flat(self):
		self.assert_flat()


class VulnerabilityCompactListQueryCountTests(VulnerabilityListQueryCountTests):
	"""`?compact=1` must stay flat too, and cost less than the default format."""

	def query_params(self):
		return {**super().query_params(), 'compact': '1'}

	def test_compact_costs_fewer_queries_than_default(self):
		self.add_rows(5)
		compact, _ = self.fetch()
		with CaptureQueriesContext(connection) as default:
			response = self.client.get(self.url, {'format': 'json', 'scan_history': self.scan.id})
		self.assertEqual(response.status_code, 200)
		self.assertLess(len(compact), len(default))
		# Session/user lookups, count, page, then one query per prefetched relation.
		self.assertLessEqual(len(compact), 8, [q['sql'][:200] for q in compact.captured_queries])


class ScanHistoryListMixin(ListQueryCountMixin):

	def add_row(self, index):
		domain = self.make_domain(index)
		scan = self.make_scan(domain)
		subdomain = self.make_subdomain(scan, domain, index)
		endpoint = self.make_endpoint(scan, domain, subdomain, index)
		self.make_vulnerability(scan, domain, subdomain, endpoint, index, severity=3)

	def query_params(self):
		return {'project': SLUG}

	def test_list_cost_is_flat(self):
		self.assert_flat()

	def test_counts_match_the_unannotated_result(self):
		from api.serializers import ScanHistorySerializer
		self.add_rows(2)
		_, response = self.fetch()
		payload = response.json()
		rows = payload['results'] if isinstance(payload, dict) else payload
		for row in rows:
			plain = ScanHistorySerializer(ScanHistory.objects.get(pk=row['id'])).data
			for field in ('subdomain_count', 'endpoint_count', 'vulnerability_count',
						  'max_severity', 'organizations', 'engine_name'):
				self.assertEqual(row[field], plain[field], field)


class ScanHistoryViewSetQueryCountTests(ScanHistoryListMixin, TestCase):
	url = '/api/listScans/'


class ListScanHistoryQueryCountTests(ScanHistoryListMixin, TestCase):
	url = '/api/listScanHistory/'


class TargetListQueryCountTests(ListQueryCountMixin, TestCase):
	url = '/api/listTargets/'

	def add_row(self, index):
		domain = self.make_domain(index)
		for _ in range(2):
			scan = self.make_scan(domain)
		subdomain = self.make_subdomain(scan, domain, index)
		endpoint = self.make_endpoint(scan, domain, subdomain, index)
		self.make_vulnerability(scan, domain, subdomain, endpoint, index)

	def query_params(self):
		return {'slug': SLUG}

	def test_list_cost_is_flat(self):
		self.assert_flat()

	def test_derived_fields_match_the_unannotated_result(self):
		from api.serializers import DomainSerializer
		self.add_rows(2)
		_, response = self.fetch()
		for row in response.json()['results']:
			plain = DomainSerializer(Domain.objects.get(pk=row['id'])).data
			for field in ('vuln_count', 'vulnerability_count', 'subdomain_count',
						  'organization', 'most_recent_scan', 'most_recent_scan_status',
						  'most_recent_scan_progress', 'domain_info'):
				self.assertEqual(row[field], plain[field], field)


class DirectoryListQueryCountTests(ListQueryCountMixin, TestCase):
	"""/api/listDirectories/ without subdomain_id lists subdomains with a directory count."""

	url = '/api/listDirectories/'

	def setUp(self):
		super().setUp()
		self.domain = self.make_domain(0)
		self.scan = self.make_scan(self.domain)
		self.other_scan = self.make_scan(self.domain)

	def add_row(self, index):
		subdomain = Subdomain.objects.create(
			scan_history=self.scan, target_domain=self.domain,
			name=f'files{index}.example.test',
		)
		for path in ('a', 'b', 'c'):
			EndPoint.objects.create(
				scan_history=self.scan, target_domain=self.domain, subdomain=subdomain,
				http_url=f'https://files{index}.example.test/{path}',
			)
		# Linked to this subdomain but recorded by another scan: not counted.
		EndPoint.objects.create(
			scan_history=self.other_scan, target_domain=self.domain, subdomain=subdomain,
			http_url=f'https://files{index}.example.test/elsewhere',
		)

	def query_params(self):
		return {'scan_history': self.scan.id}

	def test_list_cost_is_flat(self):
		self.assert_flat()

	def test_counts_are_per_scan_and_not_multiplied(self):
		self.add_rows(2)
		Subdomain.objects.create(
			scan_history=self.scan, target_domain=self.domain,
			name='empty.example.test',
		)
		_, response = self.fetch()
		payload = response.json()
		self.assertEqual(payload['count'], 2)
		self.assertIsNone(payload['next'])
		self.assertIsNone(payload['previous'])
		self.assertEqual(
			payload['results'],
			[
				{'id': subdomain.id, 'name': subdomain.name, 'directory_count': 3}
				for subdomain in Subdomain.objects.filter(
					scan_history=self.scan, name__startswith='files',
				).order_by('id')
			],
		)

	def test_write_methods_are_rejected(self):
		self.add_rows(1)
		endpoint = EndPoint.objects.filter(scan_history=self.scan).first()
		detail = f'{self.url}{endpoint.id}/'
		payload = {'http_url': 'https://files0.example.test/changed'}

		self.assertEqual(self.client.post(self.url, payload, format='json').status_code, 405)
		self.assertEqual(self.client.put(detail, payload, format='json').status_code, 405)
		self.assertEqual(self.client.patch(detail, payload, format='json').status_code, 405)
		self.assertEqual(self.client.delete(detail).status_code, 405)

		endpoint.refresh_from_db()
		self.assertEqual(endpoint.http_url, 'https://files0.example.test/a')
