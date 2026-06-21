import uuid as _uuid
from urllib.parse import urlparse
from django.apps import apps
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import Q
from django.utils import timezone
from reNgine.definitions import (TASK_STATUSES,
								 NUCLEI_REVERSE_SEVERITY_MAP)
from reNgine.utilities import *
from scanEngine.models import EngineType, HardwareProfile
from targetApp.models import Domain


class hybrid_property:
	def __init__(self, func):
		self.func = func
		self.name = func.__name__
		self.exp = None

	def __get__(self, instance, owner):
		if instance is None:
			return self
		return self.func(instance)

	def __set__(self, instance, value):
		pass

	def expression(self, exp):
		self.exp = exp
		return self


class ScanHistory(models.Model):
	id = models.AutoField(primary_key=True)
	start_scan_date = models.DateTimeField()
	scan_status = models.IntegerField(choices=TASK_STATUSES, default=-1)
	results_dir = models.CharField(max_length=100, blank=True)
	domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	scan_type = models.ForeignKey(EngineType, on_delete=models.CASCADE)
	hardware_profile = models.ForeignKey(HardwareProfile, on_delete=models.SET_NULL, null=True, blank=True)

	workflow_ids = ArrayField(models.CharField(max_length=100), blank=True, default=list)
	tasks = ArrayField(models.CharField(max_length=200), null=True)
	stop_scan_date = models.DateTimeField(null=True, blank=True)
	used_gf_patterns = models.CharField(max_length=500, null=True, blank=True)
	error_message = models.CharField(max_length=300, blank=True, null=True)
	recovery_count = models.IntegerField(default=0)
	emails = models.ManyToManyField('Email', related_name='emails', blank=True)
	employees = models.ManyToManyField('Employee', related_name='employees', blank=True)
	buckets = models.ManyToManyField('S3Bucket', related_name='buckets', blank=True)
	dorks = models.ManyToManyField('Dork', related_name='dorks', blank=True)
	initiated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='initiated_scans', blank=True, null=True)
	aborted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='aborted_scans')
	# scan related configs, prefix config fields with cfg_
	cfg_out_of_scope_subdomains = ArrayField(
		models.CharField(max_length=200),
		blank=True,
		null=True,
		default=list
	)
	cfg_starting_point_path = models.CharField(max_length=200, blank=True, null=True)
	cfg_excluded_paths = ArrayField(
		models.CharField(max_length=200),
		blank=True,
		null=True,
		default=list
	)
	cfg_imported_subdomains = ArrayField(
		models.CharField(max_length=200),
		blank=True,
		null=True,
		default=list
	)
	cfg_custom_dorks = models.TextField(blank=True, null=True)


	def __str__(self):
		return self.domain.name

	def get_subdomain_count(self):
		return Subdomain.objects.filter(scan_history__id=self.id).count()

	def get_subdomain_change_count(self):
		last_scan = (
			ScanHistory.objects
			.filter(id=self.id)
			.filter(tasks__overlap=['subdomain_discovery'])
			.order_by('-start_scan_date')
		)
		scanned_host_q1 = (
			Subdomain.objects
			.filter(target_domain__id=self.domain.id)
			.exclude(scan_history__id=last_scan[0].id)
			.values('name')
		)
		scanned_host_q2 = (
			Subdomain.objects
			.filter(scan_history__id=last_scan[0].id)
			.values('name')
		)
		new_subdomains = scanned_host_q2.difference(scanned_host_q1).count()
		removed_subdomains = scanned_host_q1.difference(scanned_host_q2).count()
		return [new_subdomains, removed_subdomains]


	def get_endpoint_count(self):
		return (
			EndPoint.objects
			.filter(scan_history__id=self.id)
			.count()
		)

	def get_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.count()
		)

	def get_unknown_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=-1)
			.count()
		)

	def get_info_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=0)
			.count()
		)

	def get_low_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=1)
			.count()
		)

	def get_medium_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=2)
			.count()
		)

	def get_high_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=3)
			.count()
		)

	def get_critical_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=4)
			.count()
		)

	def get_firewall_count(self):
		return Subdomain.objects.filter(scan_history__id=self.id).filter(
			Q(waf__name__icontains='Sophos') |
			Q(ip_addresses__ports__number__in=[4444, 500, 4500, 8443, 1194])
		).distinct().count()

	def get_progress(self):
		"""Calculate scan progress based on successful/failed vs total task counts.
		"""
		from api.scan_task_counts import get_task_counts
		successful, failed, total = get_task_counts(self)
		if total:
			return round(((successful + failed) / total) * 100, 2)
		return 0.0


	def get_completed_ago(self):
		if self.stop_scan_date:
			return self.get_time_ago(self.stop_scan_date)

	def get_total_scan_time_in_sec(self):
		if self.stop_scan_date:
			return (self.stop_scan_date - self.start_scan_date).seconds

	def get_elapsed_time(self):
		return self.get_time_ago(self.start_scan_date)

	def get_time_ago(self, time):
		duration = timezone.now() - time
		days, seconds = duration.days, duration.seconds
		hours = days * 24 + seconds // 3600
		minutes = (seconds % 3600) // 60
		seconds = seconds % 60
		if not hours and not minutes:
			return f'{seconds} seconds'
		elif not hours:
			return f'{minutes} minutes'
		elif not minutes:
			return f'{hours} hours'
		return f'{hours} hours {minutes} minutes'


class Subdomain(models.Model):
	# TODO: Add endpoint property instead of replicating endpoint fields here
	# Aquatone tasks are crashing due to endpoint property not being found
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
	name = models.CharField(max_length=1000)
	is_imported_subdomain = models.BooleanField(default=False)
	is_important = models.BooleanField(default=False, null=True, blank=True)
	http_url = models.CharField(max_length=10000, null=True, blank=True)
	screenshot_path = models.CharField(max_length=1000, null=True, blank=True)
	http_header_path = models.CharField(max_length=1000, null=True, blank=True)
	discovered_date = models.DateTimeField(blank=True, null=True)
	cname = models.CharField(max_length=5000, blank=True, null=True)
	is_cdn = models.BooleanField(default=False, blank=True, null=True)
	cdn_name = models.CharField(max_length=200, blank=True, null=True)
	http_status = models.IntegerField(default=0)
	content_type = models.CharField(max_length=100, null=True, blank=True)
	response_time = models.FloatField(null=True, blank=True)
	webserver = models.CharField(max_length=1000, blank=True, null=True)
	content_length = models.IntegerField(default=0, blank=True, null=True)
	page_title = models.CharField(max_length=1000, blank=True, null=True)
	technologies = models.ManyToManyField('Technology', related_name='technologies', blank=True)
	ip_addresses = models.ManyToManyField('IpAddress', related_name='ip_addresses', blank=True)
	directories = models.ManyToManyField('DirectoryScan', related_name='directories', blank=True)
	waf = models.ManyToManyField('Waf', related_name='waf', blank=True)
	origin_ip = models.CharField(max_length=45, null=True, blank=True)
	attack_surface = models.TextField(null=True, blank=True)
	criticality_level = models.IntegerField(default=1, null=True, blank=True)
	criticality_reason = models.TextField(null=True, blank=True)

	class Meta:
		constraints = [
			models.UniqueConstraint(
				fields=['scan_history', 'name'],
				name='unique_subdomain_per_scan',
			),
		]

	def __str__(self):
		return str(self.name)

	@property
	def get_endpoint_count(self):
		endpoints = EndPoint.objects.filter(subdomain__name=self.name)
		if self.scan_history:
			endpoints = endpoints.filter(scan_history=self.scan_history)
		return endpoints.count()

	@property
	def get_info_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=0)
			.count()
		)

	@property
	def get_low_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=1)
			.count()
		)

	@property
	def get_medium_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=2)
			.count()
		)

	@property
	def get_high_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=3)
			.count()
		)

	@property
	def get_critical_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=4)
			.count()
		)

	@property
	def get_total_vulnerability_count(self):
		return self.get_vulnerabilities.count()

	@property
	def get_vulnerabilities(self):
		vulns = Vulnerability.objects.filter(subdomain__name=self.name)
		if self.scan_history:
			vulns = vulns.filter(scan_history=self.scan_history)
		return vulns

	@property
	def get_vulnerabilities_without_info(self):
		vulns = Vulnerability.objects.filter(subdomain__name=self.name).exclude(severity=0)
		if self.scan_history:
			vulns = vulns.filter(scan_history=self.scan_history)
		return vulns

	@property
	def get_directories_count(self):
		subdomains = (
			Subdomain.objects
			.filter(id=self.id)
		)
		dirscan = (
			DirectoryScan.objects
			.filter(directories__in=subdomains)
		)
		return (
			DirectoryFile.objects
			.filter(directory_files__in=dirscan)
			.distinct()
			.count()
		)

	@property
	def get_todos(self):
		TodoNote = apps.get_model('recon_note', 'TodoNote')
		notes = TodoNote.objects
		if self.scan_history:
			notes = notes.filter(scan_history=self.scan_history)
		notes = notes.filter(subdomain__id=self.id)
		return notes.values()

	@property
	def get_subscan_count(self):
		return (
			SubScan.objects
			.filter(subdomain__id=self.id)
			.distinct()
			.count()
		)



class Screenshot(models.Model):
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name='screenshots')
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, related_name='screenshots')
	url = models.URLField(max_length=2000)
	title = models.CharField(max_length=1000, null=True, blank=True)
	status_code = models.IntegerField(null=True, blank=True)
	screenshot_path = models.CharField(max_length=1000)
	html_path = models.CharField(max_length=1000, null=True, blank=True)
	favicon_hash = models.CharField(max_length=100, null=True, blank=True)
	technologies = models.JSONField(default=dict, blank=True)
	tags = models.JSONField(default=list, blank=True)
	response_headers = models.JSONField(default=dict, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return str(self.url)


class SubScan(models.Model):
	id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=100, blank=True, null=True)
	start_scan_date = models.DateTimeField()
	status = models.IntegerField()
	workflow_ids = ArrayField(models.CharField(max_length=100), blank=True, default=list)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE)
	stop_scan_date = models.DateTimeField(null=True, blank=True)
	error_message = models.CharField(max_length=300, blank=True, null=True)
	engine = models.ForeignKey(EngineType, on_delete=models.CASCADE, blank=True, null=True)
	subdomain_subscan_ids = models.ManyToManyField('Subdomain', related_name='subdomain_subscan_ids', blank=True)

	def get_completed_ago(self):
		if self.stop_scan_date:
			return get_time_taken(timezone.now(), self.stop_scan_date)

	def get_total_time_taken(self):
		if self.stop_scan_date:
			return get_time_taken(self.stop_scan_date, self.start_scan_date)

	def get_elapsed_time(self):
		return get_time_taken(timezone.now(), self.start_scan_date)

	def get_task_name_str(self):
		taskmap = {
			'subdomain_discovery': 'Subdomain discovery',
			'dir_file_fuzz': 'Directory and File fuzzing',
			'port_scan': 'Port Scan',
			'fetch_url': 'Fetch URLs',
			'vulnerability_scan': 'Vulnerability Scan',
			'screenshot': 'Screenshot',
			'waf_detection': 'Waf Detection',
			'osint': 'Open-Source Intelligence'
		}
		return taskmap.get(self.type, 'Unknown')

class EndPoint(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	source = models.CharField(max_length=200, null=True, blank=True)
	http_url = models.CharField(max_length=30000)
	content_length = models.IntegerField(default=0, null=True, blank=True)
	page_title = models.CharField(max_length=30000, null=True, blank=True)
	http_status = models.IntegerField(default=0, null=True, blank=True)
	content_type = models.CharField(max_length=100, null=True, blank=True)
	discovered_date = models.DateTimeField(blank=True, null=True)
	response_time = models.FloatField(null=True, blank=True)
	webserver = models.CharField(max_length=1000, blank=True, null=True)
	is_default = models.BooleanField(null=True, blank=True, default=False)
	is_redirect = models.BooleanField(default=False)
	matched_gf_patterns = models.CharField(max_length=10000, null=True, blank=True)
	techs = models.ManyToManyField('Technology', related_name='techs', blank=True)
	# used for subscans
	endpoint_subscan_ids = models.ManyToManyField('SubScan', related_name='endpoint_subscan_ids', blank=True)

	def __str__(self):
		return self.http_url

	@hybrid_property
	def is_alive(self):
		return self.http_status and (0 < self.http_status < 500) and self.http_status != 404


class Parameter(models.Model):
	"""Represents a discovered HTTP/GraphQL/JSON parameter for an endpoint.

	Populated by existing tools (Arjun, ParamSpider, LinkFinder, Kiterunner)
	and enriched by the Custom Parameter Discovery Engine (CPDE) with
	confidence scoring, multi-source correlation, and location metadata.
	"""

	id = models.AutoField(primary_key=True)
	endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, related_name='parameters')
	name = models.CharField(max_length=1000)
	value = models.CharField(max_length=1000, null=True, blank=True)
	# type stores the tool source label (e.g. 'Arjun', 'LinkFinder', 'js_ast', 'openapi')
	type = models.CharField(max_length=100, null=True, blank=True)
	impact = models.CharField(max_length=100, null=True, blank=True)
	discovered_date = models.DateTimeField(auto_now_add=True)

	# ── CPDE Intelligence Fields ──────────────────────────────────────────────
	# Confidence score (0–100) aggregated across all evidence sources.
	# 0 = legacy/unknown (set by pre-CPDE tools), ≥50 = corroborated by CPDE.
	confidence = models.IntegerField(
		default=0,
		help_text="0-100 confidence score aggregated from all evidence sources"
	)
	# JSON list of source labels that contributed to this parameter record,
	# e.g. ["arjun", "js_ast", "openapi"]. Empty for legacy records.
	sources = models.JSONField(
		default=list,
		help_text="Evidence source labels e.g. ['arjun','js_ast','openapi']"
	)
	# Where the parameter appears in the request:
	# json_body | query_string | header | graphql_var | form_data | path
	param_location = models.CharField(
		max_length=50,
		null=True,
		blank=True,
		help_text="json_body|query_string|header|graphql_var|form_data|path"
	)
	# JS-inferred data type (string, number, boolean, object, array).
	# Null for parameters discovered by non-AST tools.
	data_type = models.CharField(
		max_length=100,
		null=True,
		blank=True,
		help_text="Inferred JS type: string, number, boolean, object, array"
	)
	# True when the parameter name matches known auth patterns
	# (e.g. token, Authorization, X-API-Key, session_id).
	is_auth_related = models.BooleanField(
		default=False,
		help_text="True when name matches auth header/token patterns"
	)
	# Source-type flags — set by CPDE to enable fast graph/API filtering.
	observed_in_js = models.BooleanField(default=False)
	observed_in_openapi = models.BooleanField(default=False)
	observed_in_graphql = models.BooleanField(default=False)
	# Direct denormalized FK to ScanHistory for efficient scan-scoped queries.
	# Avoids the endpoint→scan_history join on every parameter listing.
	# Null for legacy records created before this field existed.
	scan_history = models.ForeignKey(
		'ScanHistory',
		on_delete=models.CASCADE,
		null=True,
		blank=True,
		related_name='parameters',
		help_text="Direct scan FK — denormalized for efficient scan-scoped queries"
	)

	def __str__(self):
		return f"{self.name} ({self.type})"


class VulnerabilityTags(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name


class VulnerabilityReference(models.Model):
	id = models.AutoField(primary_key=True)
	url = models.CharField(max_length=5000)

	def __str__(self):
		return self.url


class CveId(models.Model):
	"""
	Represents a CVE record containing vulnerability metadata such as CVSS severity, exploitability, and relationships.
	"""
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100, unique=True, db_index=True)
	is_cisa_kev = models.BooleanField(default=False)
	
	cvss_v31_base_score = models.FloatField(null=True, blank=True)  # 0-10
	attack_vector = models.CharField(max_length=20, null=True, blank=True)  # NETWORK, ADJACENT, LOCAL, PHYSICAL
	attack_complexity = models.CharField(max_length=20, null=True, blank=True)  # LOW, HIGH
	privileges_required = models.CharField(max_length=20, null=True, blank=True)  # NONE, LOW, HIGH
	user_interaction = models.CharField(max_length=20, null=True, blank=True)  # NONE, REQUIRED
	confidentiality_impact = models.CharField(max_length=20, null=True, blank=True)  # NONE, LOW, HIGH
	integrity_impact = models.CharField(max_length=20, null=True, blank=True)  # NONE, LOW, HIGH
	availability_impact = models.CharField(max_length=20, null=True, blank=True)  # NONE, LOW, HIGH
	
	epss_score = models.FloatField(null=True, blank=True)  # 0-1
	epss_percentile = models.FloatField(null=True, blank=True)  # 0-100
	published_date = models.DateTimeField(null=True, blank=True)
	last_modified_date = models.DateTimeField(null=True, blank=True)
	vulnerability_type = models.CharField(max_length=50, null=True, blank=True)  # SCA, DAST, SAST, Config
	is_poc = models.BooleanField(default=False)
	is_template = models.BooleanField(default=False)
	
	# SploitScan and LLM Caching fields
	ai_risk_assessment = models.TextField(null=True, blank=True)
	public_exploits = models.JSONField(default=list, blank=True)
	hackerone_data = models.JSONField(default=dict, blank=True)
	patching_priority = models.CharField(max_length=10, null=True, blank=True)
	mitigation_ideas = models.TextField(null=True, blank=True)

	
	related_cves = models.ManyToManyField(
		'self', 
		symmetrical=False, 
		blank=True,
		related_name='related_from'
	)

	def __str__(self):
		return f"{self.name} (CVSS: {self.cvss_v31_base_score})"


class EpssFeedData(models.Model):
	"""
	Stores the daily bulk EPSS data feed locally to prevent hitting API rate limits.
	"""
	cve_id = models.CharField(max_length=50, primary_key=True)
	epss_score = models.FloatField()
	epss_percentile = models.FloatField()
	date_fetched = models.DateTimeField(auto_now=True)

	def __str__(self):
		return f"{self.cve_id} (EPSS: {self.epss_score})"


class CweId(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name


class GPTVulnerabilityReport(models.Model):
	url_path = models.CharField(max_length=2000)
	title = models.CharField(max_length=2500)
	description = models.TextField(null=True, blank=True)
	impact = models.TextField(null=True, blank=True)
	remediation = models.TextField(null=True, blank=True)
	references = models.ManyToManyField('VulnerabilityReference', related_name='report_reference', blank=True)

	def __str__(self):
		return self.title


class Exposure(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
	endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, null=True, blank=True)
	type = ArrayField(models.CharField(max_length=200), default=list, blank=True) # e.g. ["VPN Gateway", "Database"]
	
	EXPOSURE_STATUS_CHOICES = (
		('open', 'Open'),
		('verified', 'Verified'),
		('false_positive', 'False Positive'),
		('remediated', 'Remediated'),
	)
	status = models.CharField(max_length=20, choices=EXPOSURE_STATUS_CHOICES, default='open')
	first_seen = models.DateTimeField(auto_now_add=True)
	last_seen = models.DateTimeField(auto_now=True)
	risk_score = models.FloatField(default=0.0)
	
	def __str__(self):
		target = self.subdomain.name if self.subdomain else (self.target_domain.name if self.target_domain else "Unknown")
		return f"{self.type} on {target}"


class ExposureEvidence(models.Model):
	id = models.AutoField(primary_key=True)
	exposure = models.ForeignKey(Exposure, on_delete=models.CASCADE, related_name='evidence')
	source_tool = models.CharField(max_length=100) # e.g. "httpx", "Katana", "Screenshot"
	evidence_data = models.JSONField(default=dict, blank=True)
	timestamp = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return f"{self.source_tool} evidence for {self.exposure}"


class Vulnerability(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	source = models.CharField(max_length=200, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	endpoint = models.ForeignKey(
		EndPoint,
		on_delete=models.CASCADE,
		blank=True,
		null=True)
	exposure = models.ForeignKey(
		Exposure,
		on_delete=models.SET_NULL,
		blank=True,
		null=True,
		related_name='vulnerabilities'
	)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	template = models.CharField(max_length=100, null=True, blank=True)
	template_url = models.CharField(max_length=2500, null=True, blank=True)
	template_id = models.CharField(max_length=200, null=True, blank=True)
	matcher_name = models.CharField(max_length=500, null=True, blank=True)
	name = models.CharField(max_length=2500)
	severity = models.IntegerField()
	description = models.TextField(null=True, blank=True)
	impact = models.TextField(null=True, blank=True)
	remediation = models.TextField(null=True, blank=True)

	extracted_results = ArrayField(
		models.CharField(max_length=5000), blank=True, null=True
	)

	tags = models.ManyToManyField('VulnerabilityTags', related_name='vuln_tags', blank=True)
	references = models.ManyToManyField('VulnerabilityReference', related_name='vuln_reference', blank=True)
	cve_ids = models.ManyToManyField('CveId', related_name='cve_ids', blank=True)
	cwe_ids = models.ManyToManyField('CweId', related_name='cwe_ids', blank=True)

	cvss_metrics = models.CharField(max_length=500, null=True, blank=True)
	cvss_score = models.FloatField(null=True, blank=True, default=None)
	curl_command = models.CharField(max_length=15000, null=True, blank=True)
	type = models.CharField(max_length=100, null=True, blank=True)
	http_url = models.CharField(max_length=10000, null=True)
	discovered_date = models.DateTimeField(null=True)
	open_status = models.BooleanField(null=True, blank=True, default=True)
	hackerone_report_id = models.CharField(max_length=50, null=True, blank=True)
	request = models.TextField(blank=True, null=True)
	response = models.TextField(blank=True, null=True)
	is_gpt_used = models.BooleanField(null=True, blank=True, default=False)
	# used for subscans
	vuln_subscan_ids = models.ManyToManyField('SubScan', related_name='vuln_subscan_ids', blank=True)

	exploit_url = models.CharField(max_length=2500, null=True, blank=True)
	VULNERABILITY_STATUS_CHOICES = (
		('unverified', 'Unverified'),
		('verified', 'Verified'),
		('not_working', 'Not Working'),
		('patched', 'Patched'),
		('closed', 'Closed'),
	)
	validation_status = models.CharField(max_length=20, choices=VULNERABILITY_STATUS_CHOICES, default='unverified')
	validation_confidence = models.FloatField(null=True, blank=True, default=0.0)
	correlation_score = models.FloatField(null=True, blank=True, default=0.0)
	is_suppressed = models.BooleanField(default=False)
	group_key = models.CharField(max_length=500, null=True, blank=True, db_index=True)

	def get_path(self):
		if self.http_url:
			return urlparse(self.http_url).path
		return "/"

	def __str__(self):
		cve_str = ', '.join(f'`{cve.name}`' for cve in self.cve_ids.all())
		severity = NUCLEI_REVERSE_SEVERITY_MAP[self.severity]
		return f'{self.http_url} | `{severity.upper()}` | `{self.name}` | `{cve_str}`'


class ValidationResult(models.Model):
	id = models.AutoField(primary_key=True)
	vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='validation_results')
	tool = models.CharField(max_length=100)
	validated = models.BooleanField(default=False)
	confidence = models.FloatField(default=0.0)
	payload = models.TextField(null=True, blank=True)
	request_evidence = models.TextField(null=True, blank=True)
	response_evidence = models.TextField(null=True, blank=True)
	timestamp = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return f"Validation for {self.vulnerability.name} by {self.tool}"

	def get_severity(self):
		"""Retrieve severity from the linked vulnerability.

		Returns:
			int: The severity level (0-4 or -1) of the vulnerability.
		"""
		return self.vulnerability.severity

	def get_cve_str(self):
		"""Format the associated CVE names as a comma-separated list of code blocks.

		Returns:
			str: A string of comma-separated CVE names wrapped in markdown backticks.
		"""
		return ', '.join(f'`{cve.name}`' for cve in self.vulnerability.cve_ids.all())

	def get_cwe_str(self):
		"""Format the associated CWE names as a comma-separated list of code blocks.

		Returns:
			str: A string of comma-separated CWE names wrapped in markdown backticks.
		"""
		return ', '.join(f'`{cwe.name}`' for cwe in self.vulnerability.cwe_ids.all())

	def get_tags_str(self):
		"""Format the associated tags as a comma-separated list of code blocks.

		Returns:
			str: A string of comma-separated vulnerability tag names wrapped in markdown backticks.
		"""
		return ', '.join(f'`{tag.name}`' for tag in self.vulnerability.tags.all())

	def get_refs_str(self):
		"""Format references as a bulleted list of code blocks.

		Returns:
			str: A formatted list of references separated by bullet points and wrapped in backticks.
		"""
		return '•' + '\n• '.join(f'`{ref.url}`' for ref in self.vulnerability.references.all())

	def get_path(self):
		"""Extract path from the linked vulnerability URL.

		Returns:
			str: The path string of the vulnerability's HTTP URL, or '/' if empty.
		"""
		from urllib.parse import urlparse
		return urlparse(self.vulnerability.http_url).path if self.vulnerability.http_url else "/"


class ImpactAssessment(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
	vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, null=True, blank=True)

	simulated_path = models.JSONField(null=True, blank=True)
	potential_attack_chain = models.JSONField(null=True, blank=True)
	potential_impact = models.TextField(null=True, blank=True)
	remediation_priority = models.IntegerField(default=1)
	is_ai_generated = models.BooleanField(default=False)

	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		# Enforce one ImpactAssessment per Vulnerability to prevent
		# MultipleObjectsReturned errors in correlation.py's _generate_attack_chain.
		# APME and the correlation engine could previously both create rows for the
		# same vulnerability, breaking the update_or_create lookup.
		constraints = [
			models.UniqueConstraint(
				fields=['vulnerability'],
				condition=models.Q(vulnerability__isnull=False),
				name='unique_impact_assessment_per_vulnerability'
			)
		]

	def __str__(self):
		return f"Impact Assessment for {self.vulnerability.name if self.vulnerability else 'General'}"


class FalsePositiveRule(models.Model):
	id = models.AutoField(primary_key=True)
	target_domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	template_id = models.CharField(max_length=200) # Nuclei template ID or vuln name
	regex_pattern = models.CharField(max_length=500, null=True, blank=True) # Optional regex for URL
	is_active = models.BooleanField(default=True)
	reason = models.TextField(null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)

	def matches(self, vuln_name, url):
		if self.template_id and self.template_id.lower() not in vuln_name.lower():
			return False
		if self.regex_pattern:
			import re
			try:
				if not re.search(self.regex_pattern, url):
					return False
			except:
				return False
		return True

	def __str__(self):
		return f"FP Rule: {self.template_id} on {self.target_domain.name}"


class ScanActivity(models.Model):
	id = models.AutoField(primary_key=True)
	scan_of = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
	task_uid = models.UUIDField(default=_uuid.uuid4, unique=True, db_index=True)
	time_started = models.DateTimeField(null=True, blank=True)
	time_ended = models.DateTimeField(null=True, blank=True)
	tier = models.PositiveSmallIntegerField(null=True, blank=True)
	subscan = models.ForeignKey(
		'SubScan', null=True, blank=True,
		on_delete=models.SET_NULL,
		related_name='activities',
	)
	title = models.CharField(max_length=1000)
	name = models.CharField(max_length=1000)
	time = models.DateTimeField()
	status = models.IntegerField()
	error_message = models.CharField(max_length=300, blank=True, null=True)
	traceback = models.TextField(blank=True, null=True)
	execution_id = models.CharField(max_length=100, blank=True, null=True)

	def __str__(self):
		return str(self.title)


class Command(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
	activity = models.ForeignKey(ScanActivity, on_delete=models.CASCADE, blank=True, null=True)
	command = models.TextField(blank=True, null=True)
	return_code = models.IntegerField(blank=True, null=True)
	output = models.TextField(blank=True, null=True)
	time = models.DateTimeField()

	def __str__(self):
		return str(self.command)


class Waf(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	manufacturer = models.CharField(max_length=500, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class WafBypassFinding(models.Model):
	id = models.AutoField(primary_key=True)
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name='waf_bypass_findings')
	technique = models.CharField(max_length=200)
	is_successful = models.BooleanField(default=False)
	payload_evidence = models.TextField(null=True, blank=True)
	discovered_date = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		status = "SUCCESS" if self.is_successful else "FAILED"
		return f"{self.subdomain.name} | {self.technique} | {status}"


class Technology(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class CountryISO(models.Model):
	id = models.AutoField(primary_key=True)
	iso = models.CharField(max_length=10, blank=True)
	name = models.CharField(max_length=100, blank=True)

	def __str__(self):
		return str(self.name)


class IpAddress(models.Model):
	id = models.AutoField(primary_key=True)
	address = models.CharField(max_length=100, blank=True, null=True)
	is_cdn = models.BooleanField(default=False)
	ports = models.ManyToManyField('Port', related_name='ports')
	geo_iso = models.ForeignKey(
		CountryISO, on_delete=models.CASCADE, null=True, blank=True)
	version = models.IntegerField(blank=True, null=True)
	is_private = models.BooleanField(default=False)
	reverse_pointer = models.CharField(max_length=100, blank=True, null=True)
	asn = models.CharField(max_length=20, blank=True, null=True)
	asn_cidr = models.CharField(max_length=50, blank=True, null=True)
	asn_org = models.CharField(max_length=200, blank=True, null=True)
	# this is used for querying which ip was discovered during subcan
	ip_subscan_ids = models.ManyToManyField('SubScan', related_name='ip_subscan_ids')

	def __str__(self):
		return str(self.address)


class Port(models.Model):
	id = models.AutoField(primary_key=True)
	number = models.IntegerField(default=0)
	service_name = models.CharField(max_length=100, blank=True, null=True)
	description = models.CharField(max_length=1000, blank=True, null=True)
	is_uncommon = models.BooleanField(default=False)

	def __str__(self):
		return str(self.service_name)


class DirectoryFile(models.Model):
	id = models.AutoField(primary_key=True)
	length = models.IntegerField(default=0)
	lines = models.IntegerField(default=0)
	http_status = models.IntegerField(default=0)
	words = models.IntegerField(default=0)
	name = models.CharField(max_length=500, blank=True, null=True)
	url = models.CharField(max_length=5000, blank=True, null=True)
	content_type = models.CharField(max_length=100, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class DirectoryScan(models.Model):
	id = models.AutoField(primary_key=True)
	command_line = models.CharField(max_length=5000, blank=True, null=True)
	directory_files = models.ManyToManyField('DirectoryFile', related_name='directory_files', blank=True)
	scanned_date = models.DateTimeField(null=True)
	# this is used for querying which ip was discovered during subcan
	dir_subscan_ids = models.ManyToManyField('SubScan', related_name='dir_subscan_ids', blank=True)


class MetaFinderDocument(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	doc_name = models.CharField(max_length=1000, null=True, blank=True)
	url = models.CharField(max_length=10000, null=True, blank=True)
	title = models.CharField(max_length=1000, null=True, blank=True)
	author = models.CharField(max_length=1000, null=True, blank=True)
	producer = models.CharField(max_length=1000, null=True, blank=True)
	creator = models.CharField(max_length=1000, null=True, blank=True)
	os = models.CharField(max_length=1000, null=True, blank=True)
	http_status = models.IntegerField(default=0, null=True, blank=True)
	creation_date = models.CharField(max_length=1000, blank=True, null=True)
	modified_date = models.CharField(max_length=1000, blank=True, null=True)


class Email(models.Model):
	id = models.AutoField(primary_key=True)
	address = models.CharField(max_length=200, blank=True, null=True)
	password = models.CharField(max_length=200, blank=True, null=True)
	metadata = models.JSONField(default=dict, blank=True)

class Employee(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=1000, null=True, blank=True)
	designation = models.CharField(max_length=1000, null=True, blank=True)
	metadata = models.JSONField(default=dict, blank=True)


class Dork(models.Model):
	id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=500, null=True, blank=True)
	url = models.CharField(max_length=10000, null=True, blank=True)


class S3Bucket(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, null=True, blank=True)
	region = models.CharField(max_length=500, null=True, blank=True)
	provider = models.CharField(max_length=100, null=True, blank=True)
	owner_id = models.CharField(max_length=250, null=True, blank=True)
	owner_display_name = models.CharField(max_length=250, null=True, blank=True)
	perm_auth_users_read = models.IntegerField(default=0)
	perm_auth_users_write = models.IntegerField(default=0)
	perm_auth_users_read_acl = models.IntegerField(default=0)
	perm_auth_users_write_acl = models.IntegerField(default=0)
	perm_auth_users_full_control = models.IntegerField(default=0)
	perm_all_users_read = models.IntegerField(default=0)
	perm_all_users_write = models.IntegerField(default=0)
	perm_all_users_read_acl = models.IntegerField(default=0)
	perm_all_users_write_acl = models.IntegerField(default=0)
	perm_all_users_full_control = models.IntegerField(default=0)
	num_objects = models.IntegerField(default=0)
	size = models.IntegerField(default=0)

class SecretLeak(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)

	tool_name = models.CharField(max_length=100) # TruffleHog, GitLeaks, LeakLookup
	secret_type = models.CharField(max_length=200) # AWS Key, Stripe API, Password
	source_url = models.CharField(max_length=5000) # URL of JS file or Repo
	match_content = models.TextField() # The actual masked secret found

	LEAK_STATUS_CHOICES = (
		('unverified', 'Unverified'),
		('verified', 'Verified'),
		('false_positive', 'False Positive'),
	)
	status = models.CharField(max_length=20, choices=LEAK_STATUS_CHOICES, default='unverified')
	discovered_date = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return f"{self.secret_type} found by {self.tool_name}"


class MonitoringDiscovery(models.Model):
	id = models.AutoField(primary_key=True)
	domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	discovery_type = models.CharField(max_length=50, choices=(
		('subdomain', 'New Subdomain'),
		('ip', 'IP Change'),
		('vhost', 'New Virtual Host'),
		('directory', 'New Directory'),
		('login', 'New Login Page'),
		('status_change', 'Status Code Change'),
	))
	content = models.JSONField()
	discovered_at = models.DateTimeField(auto_now_add=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.SET_NULL, null=True, blank=True)

	def __str__(self):
		return f"{self.discovery_type} - {self.domain.name}"


class StressTestResult(models.Model):
    TEST_STATUS_CHOICES = [
        ('success', 'Success'),
        ('aborted', 'Aborted'),
        ('failed', 'Failed'),
        ('running', 'Running'),
    ]

    scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, related_name='stress_results')
    target_domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='stress_results', null=True, blank=True)
    tool_used = models.CharField(max_length=50, default="k6")
    concurrency_used = models.IntegerField(default=0)
    duration = models.CharField(max_length=50, blank=True, null=True)

    total_requests = models.IntegerField(default=0)
    successful_requests = models.IntegerField(default=0)
    failed_requests = models.IntegerField(default=0)

    avg_latency_ms = models.FloatField(default=0.0)
    p95_latency_ms = models.FloatField(default=0.0)
    p99_latency_ms = models.FloatField(default=0.0)
    max_requests_per_second = models.FloatField(default=0.0)

    # NEW: Extended metrics
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    endpoints_tested = models.JSONField(default=list, blank=True)
    response_code_distribution = models.JSONField(default=dict, blank=True)
    error_breakdown = models.JSONField(default=dict, blank=True)

    # NEW: Additional percentiles
    p50_latency_ms = models.FloatField(default=0.0)
    p75_latency_ms = models.FloatField(default=0.0)
    p90_latency_ms = models.FloatField(default=0.0)
    p999_latency_ms = models.FloatField(default=0.0)
    percentile_latencies = models.JSONField(default=dict, blank=True)

    # NEW: Performance insights
    max_concurrent_connections = models.IntegerField(default=0)
    peak_throughput_rps = models.FloatField(default=0.0)
    test_status = models.CharField(
        max_length=20,
        choices=TEST_STATUS_CHOICES,
        default='success'
    )

    # NEW: Findings & analysis
    findings = models.TextField(blank=True, default='')
    anomalies_detected = models.JSONField(default=list, blank=True)
    recommendations = models.TextField(blank=True, default='')

    is_kill_switch_triggered = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Stress Test Result'
        verbose_name_plural = 'Stress Test Results'
        indexes = [
            models.Index(fields=['scan_history', '-start_time']),
            models.Index(fields=['test_status']),
        ]

    def __str__(self):
        return f"Stress Test Result for Scan {self.scan_history.id} - {self.tool_used}"


class StressTelemetryPoint(models.Model):
    """Individual metric snapshot during a stress test (time-series data)."""
    TOOL_CHOICES = [
        ('k6', 'k6'),
        ('wrk', 'wrk'),
        ('hping3', 'hping3'),
        ('locust', 'locust'),
        ('stressor', 'stressor'),
    ]

    stress_result = models.ForeignKey(
        StressTestResult,
        on_delete=models.CASCADE,
        related_name='telemetry_points'
    )
    endpoint = models.ForeignKey(
        EndPoint,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    tool = models.CharField(max_length=20, choices=TOOL_CHOICES)
    timestamp = models.DateTimeField(db_index=True)

    # Common metrics (normalized across tools)
    latency_ms = models.FloatField(null=True, blank=True)
    throughput = models.FloatField(null=True, blank=True)
    error_rate = models.FloatField(null=True, blank=True)
    request_count = models.IntegerField(null=True, blank=True)
    error_count = models.IntegerField(null=True, blank=True)

    # Tool-specific metrics (JSON for flexibility)
    tool_specific_metrics = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Stress Telemetry Point'
        verbose_name_plural = 'Stress Telemetry Points'
        indexes = [
            models.Index(fields=['stress_result', 'timestamp']),
            models.Index(fields=['tool', 'timestamp']),
            models.Index(fields=['endpoint', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.tool} telemetry at {self.timestamp}"


class StressToolConfiguration(models.Model):
    """Stores exact tool parameters used in each test."""
    stress_result = models.OneToOneField(
        StressTestResult,
        on_delete=models.CASCADE,
        related_name='tool_config'
    )
    tool_configs = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Stress Tool Configuration'
        verbose_name_plural = 'Stress Tool Configurations'

    def __str__(self):
        return f"Tool config for stress result {self.stress_result.id}"


class AuthCandidate(models.Model):
	PROTOCOL_CHOICES = (
		('http', 'HTTP'),
		('smb', 'SMB'),
		('rdp', 'RDP'),
		('ssh', 'SSH'),
		('ftp', 'FTP'),
		('telnet', 'Telnet'),
	)
	STATUS_CHOICES = (
		('pending', 'Pending'),
		('processing', 'Processing'),
		('completed', 'Completed'),
		('failed', 'Failed'),
	)
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, null=True, blank=True)
	endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, null=True, blank=True)
	target = models.CharField(max_length=2000)
	protocol = models.CharField(max_length=20, choices=PROTOCOL_CHOICES)
	port = models.IntegerField()
	source_tool = models.CharField(max_length=200, null=True, blank=True)
	metadata = models.JSONField(default=dict, blank=True)
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
	discovered_date = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name_plural = "Authentication Candidates"
		constraints = [
			models.UniqueConstraint(
				fields=['scan_history', 'target', 'protocol', 'port'],
				name='unique_authcandidate_scan_target_proto_port',
			)
		]

	def __str__(self):
		return f"{self.protocol.upper()} | {self.target}:{self.port}"


class ScanReport(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, related_name='reports')
	report_type = models.CharField(max_length=50) # full, vulnerability
	report_template = models.CharField(max_length=50) # default, modern, enterprise
	status = models.IntegerField(choices=TASK_STATUSES, default=-1)
	report_file = models.FileField(upload_to='reports/', null=True, blank=True)
	error_message = models.TextField(null=True, blank=True)
	params = models.JSONField(default=dict, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	completed_at = models.DateTimeField(null=True, blank=True)

	class Meta:
		verbose_name_plural = "Scan Reports"

	def __str__(self):
		return f"Report for {self.scan_history.domain.name} ({self.report_type})"

class OsintStaging(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
	target_domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	osint_type = models.CharField(max_length=100) # Email, Employee, Phone, etc.
	content = models.TextField()
	source = models.CharField(max_length=200)
	confidence = models.IntegerField(default=0)
	metadata = models.JSONField(default=dict, blank=True)
	status = models.CharField(max_length=20, choices=(
		('pending', 'Pending'),
		('validated', 'Validated'),
		('ignored', 'Ignored'),
	), default='pending')
	discovered_date = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name_plural = "OSINT Staging"

	def __str__(self):
		return f"{self.osint_type}: {self.content[:50]}"


class TemporalWorkflowExecution(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, related_name='temporal_executions')
	workflow_id = models.CharField(max_length=255, unique=True)
	run_id = models.CharField(max_length=255)
	workflow_type = models.CharField(max_length=100)
	status = models.CharField(max_length=50, default="RUNNING") # RUNNING, COMPLETED, FAILED, TIMED_OUT, CANCELLED, TERMINATED
	started_at = models.DateTimeField(auto_now_add=True)
	ended_at = models.DateTimeField(null=True, blank=True)
	error_message = models.TextField(null=True, blank=True)

	def __str__(self):
		return f"{self.workflow_type} ({self.workflow_id})"


class WorkflowLineage(models.Model):
	id = models.AutoField(primary_key=True)
	parent_execution = models.ForeignKey(TemporalWorkflowExecution, on_delete=models.CASCADE, related_name='child_lineages', null=True, blank=True)
	child_execution = models.ForeignKey(TemporalWorkflowExecution, on_delete=models.CASCADE, related_name='parent_lineages')
	relation_type = models.CharField(max_length=50) # CHILD_WORKFLOW, RECURSIVE_EXPANSION, EVENT_TRIGGERED
	depth = models.IntegerField(default=0)


class TemporalActivityExecution(models.Model):
	id = models.AutoField(primary_key=True)
	workflow_execution = models.ForeignKey(TemporalWorkflowExecution, on_delete=models.CASCADE, related_name='activities')
	activity_id = models.CharField(max_length=255)
	activity_type = models.CharField(max_length=100)
	status = models.CharField(max_length=50, default="RUNNING")
	retry_count = models.IntegerField(default=0)
	started_at = models.DateTimeField(auto_now_add=True)
	ended_at = models.DateTimeField(null=True, blank=True)
	heartbeat_telemetry = models.JSONField(null=True, blank=True)
	error_message = models.TextField(null=True, blank=True)


class WorkflowCheckpoint(models.Model):
	id = models.AutoField(primary_key=True)
	workflow_execution = models.ForeignKey(TemporalWorkflowExecution, on_delete=models.CASCADE)
	checkpoint_name = models.CharField(max_length=100)
	state_payload = models.JSONField() # JSON state containing found subdomains, ports, etc.
	saved_at = models.DateTimeField(auto_now_add=True)


class RecursiveExpansionState(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
	target = models.CharField(max_length=1000)
	depth = models.IntegerField(default=0)
	budget_allocated = models.IntegerField(default=100)
	budget_consumed = models.IntegerField(default=0)
	ancestry_path = ArrayField(models.CharField(max_length=1000), default=list) # Trace roots
	expansion_score = models.FloatField(default=1.0)


class OASTCorrelationState(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
	token = models.CharField(max_length=255, unique=True) # Interactsh token
	workflow_id = models.CharField(max_length=255)
	registered_at = models.DateTimeField(auto_now_add=True)
	expires_at = models.DateTimeField()
	is_correlated = models.BooleanField(default=False)
	interaction_payload = models.JSONField(null=True, blank=True)


class WorkflowSuppressionState(models.Model):
	id = models.AutoField(primary_key=True)
	target_domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	identifier = models.CharField(max_length=500) # SHA-256 of template_id + host + port
	suppressed_until = models.DateTimeField()
	reason = models.CharField(max_length=500, blank=True, null=True)


class WorkflowSignal(models.Model):
	id = models.AutoField(primary_key=True)
	workflow_execution = models.ForeignKey(TemporalWorkflowExecution, on_delete=models.CASCADE, related_name='signals')
	signal_name = models.CharField(max_length=100)
	payload = models.JSONField(null=True, blank=True)
	received_at = models.DateTimeField(auto_now_add=True)


class WorkflowEvent(models.Model):
	id = models.AutoField(primary_key=True)
	workflow_execution = models.ForeignKey(TemporalWorkflowExecution, on_delete=models.CASCADE, related_name='events')
	event_type = models.CharField(max_length=100) # e.g. subdomain_discovered, endpoint_discovered, etc.
	payload = models.JSONField(null=True, blank=True)
	timestamp = models.DateTimeField(auto_now_add=True)


class ExecutionTelemetry(models.Model):
	id = models.AutoField(primary_key=True)
	workflow_execution = models.ForeignKey(TemporalWorkflowExecution, on_delete=models.CASCADE, related_name='telemetry')
	cpu_usage = models.FloatField(default=0.0)
	memory_usage = models.FloatField(default=0.0)
	active_threads = models.IntegerField(default=0)
	timestamp = models.DateTimeField(auto_now_add=True)


class TemporalSchedule(models.Model):
	schedule_id = models.CharField(max_length=200, unique=True)
	name = models.CharField(max_length=200)
	# workflow_type values: 'MasterScanWorkflow', 'StressTestWorkflow', 'APMESyncWorkflow'
	workflow_type = models.CharField(max_length=100)
	workflow_args = models.JSONField(default=dict)
	cron_expression = models.CharField(max_length=100, blank=True, default='')
	interval_seconds = models.IntegerField(null=True, blank=True)
	clocked_time = models.DateTimeField(null=True, blank=True)
	one_off = models.BooleanField(default=False)
	is_active = models.BooleanField(default=True)
	total_run_count = models.IntegerField(default=0)
	last_run_at = models.DateTimeField(null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	domain = models.ForeignKey(
		'targetApp.Domain',
		null=True,
		blank=True,
		on_delete=models.SET_NULL,
		related_name='temporal_schedules',
	)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return f'{self.name} ({self.schedule_id})'


class VulnerabilityHistory(models.Model):
    """
    Tracks the lifecycle, persistence, and remediation status of vulnerabilities 
    across scan runs. Enables trend analysis and remediation tracking.
    
    Attributes:
        group_key: SHA-256 hash uniquely identifying a vulnerability class
        first_seen: Timestamp of initial discovery
        last_seen: Timestamp of most recent discovery
        is_remediated: Boolean flag indicating if vulnerability has been fixed
        remediation_date: Timestamp when vulnerability was first remediated
        total_occurrences: Count of how many times this vulnerability has appeared
        affected_subdomains_count: Number of distinct subdomains affected
        scan_history: Reference to the scan that found this record
        vulnerability: Reference to the Vulnerability that triggered history creation
        cve: Optional reference to associated CVE record
    """
    id = models.AutoField(primary_key=True)
    
    # Linking to scans and vulnerabilities
    scan_history = models.ForeignKey(
        ScanHistory, 
        on_delete=models.CASCADE, 
        related_name='vulnerability_history',
        help_text='Scan that generated this history record'
    )
    vulnerability = models.ForeignKey(
        Vulnerability, 
        on_delete=models.CASCADE, 
        related_name='history_records',
        help_text='Vulnerability that triggered this record'
    )
    cve = models.ForeignKey(
        CveId, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        help_text='Associated CVE, if available'
    )
    
    # Deduplication & grouping
    group_key = models.CharField(
        max_length=500, 
        db_index=True,
        help_text='SHA-256 hash for grouping identical vulnerabilities'
    )
    
    # Timeline tracking
    first_seen = models.DateTimeField(
        auto_now_add=True,
        help_text='First discovery timestamp'
    )
    last_seen = models.DateTimeField(
        auto_now=True,
        help_text='Most recent discovery timestamp'
    )
    
    # Remediation status
    is_remediated = models.BooleanField(
        default=False,
        help_text='Whether vulnerability has been fixed'
    )
    remediation_date = models.DateTimeField(
        null=True, 
        blank=True,
        help_text='Date when vulnerability was remediated'
    )
    
    # Trending & impact metrics
    total_occurrences = models.IntegerField(
        default=1,
        help_text='Total times this vulnerability appeared'
    )
    affected_subdomains_count = models.IntegerField(
        default=0,
        help_text='Number of distinct subdomains affected'
    )
    
    class Meta:
        verbose_name = 'Vulnerability History'
        verbose_name_plural = 'Vulnerability Histories'
        ordering = ['-last_seen']
        
        # Enforce one history record per (group_key, scan_history) pair
        unique_together = ('group_key', 'scan_history')
        
        # Performance indexes
        indexes = [
            models.Index(
                fields=['group_key', '-last_seen'],
                name='vh_groupkey_lastseen_idx'
            ),
            models.Index(
                fields=['is_remediated', '-last_seen'],
                name='vh_remediated_lastseen_idx'
            ),
            models.Index(
                fields=['scan_history', '-last_seen'],
                name='vh_scan_lastseen_idx'
            ),
        ]
    
    def __str__(self):
        status = "✓ Remediated" if self.is_remediated else "✗ Active"
        return f"{self.vulnerability.name} [{self.group_key[:8]}...] - {status}"
    
    def days_since_discovery(self):
        """Calculate days between first discovery and now."""
        from django.utils import timezone
        return (timezone.now() - self.first_seen).days
    
    def days_to_remediation(self):
        """Calculate time from first discovery to remediation."""
        if not self.remediation_date:
            return None
        return (self.remediation_date - self.first_seen).days
    
    @classmethod
    def get_trending_vulns(cls, domain, days=30):
        """Get vulnerabilities discovered in last N days."""
        from django.utils import timezone
        from datetime import timedelta
        
        cutoff = timezone.now() - timedelta(days=days)
        return cls.objects.filter(
            scan_history__domain=domain,
            first_seen__gte=cutoff
        ).order_by('-total_occurrences')
    
    @classmethod
    def get_persistent_vulns(cls, domain, min_days=90):
        """Get vulnerabilities that have persisted for N+ days."""
        from django.utils import timezone
        
        return cls.objects.filter(
            scan_history__domain=domain,
            is_remediated=False,
            days_since_discovery__gte=min_days
        ).order_by('first_seen')