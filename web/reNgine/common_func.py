import whatportis
import socket
import json
import glob
import os
import pickle
import subprocess
from reNgine.validators import validate_external_url
import random
import shutil
import traceback
import ipaddress
import humanize
import redis
import requests
import tldextract
import shlex
import re
import xmltodict

from time import sleep
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import logging as _logging
get_task_logger = _logging.getLogger
from discord_webhook import DiscordEmbed, DiscordWebhook
from django.db.models import Q
from dotted_dict import DottedDict

from django.utils import timezone
from reNgine.common_serializers import *
from reNgine.definitions import *
from reNgine.settings import *
from scanEngine.models import *
from dashboard.models import *
from startScan.models import *
from targetApp.models import *
from reNgine.utilities import is_valid_url, replace_nulls


logger = get_task_logger(__name__)
DISCORD_WEBHOOKS_CACHE = redis.Redis.from_url(REDIS_URL)

#------------------#
# EngineType utils #
#------------------#
def dump_custom_scan_engines(results_dir):
	"""Dump custom scan engines to YAML files.

	Args:
		results_dir (str): Results directory (will be created if non-existent).
	"""
	custom_engines = EngineType.objects.filter(default_engine=False)
	if not os.path.exists(results_dir):
		os.makedirs(results_dir, exist_ok=True)
	for engine in custom_engines:
		with open(os.path.join(results_dir, f"{engine.engine_name}.yaml"), 'w') as f:
			f.write(engine.yaml_configuration)

def load_custom_scan_engines(results_dir):
	"""Load custom scan engines from YAML files. The filename without .yaml will
	be used as the engine name.

	Args:
		results_dir (str): Results directory containing engines configs.
	"""
	config_paths = [
		f for f in os.listdir(results_dir)
		if os.path.isfile(os.path.join(results_dir, f)) and f.endswith('.yaml')
	]
	for path in config_paths:
		engine_name = os.path.splitext(os.path.basename(path))[0]
		full_path = os.path.join(results_dir, path)
		with open(full_path, 'r') as f:
			yaml_configuration = f.read()

		engine, _ = EngineType.objects.get_or_create(engine_name=engine_name)
		engine.yaml_configuration = yaml_configuration
		engine.save()


#--------------------------------#
# InterestingLookupModel queries #
#--------------------------------#
def get_lookup_keywords():
	"""Get lookup keywords from InterestingLookupModel.

	Returns:
		list: Lookup keywords.
	"""
	lookup_model = InterestingLookupModel.objects.first()
	lookup_obj = InterestingLookupModel.objects.filter(custom_type=True).order_by('-id').first()
	custom_lookup_keywords = []
	default_lookup_keywords = []
	if lookup_model:
		default_lookup_keywords = [
			key.strip()
			for key in lookup_model.keywords.split(',')]
	if lookup_obj:
		custom_lookup_keywords = [
			key.strip()
			for key in lookup_obj.keywords.split(',')
		]
	lookup_keywords = default_lookup_keywords + custom_lookup_keywords
	lookup_keywords = list(filter(None, lookup_keywords)) # remove empty strings from list
	return lookup_keywords


#-------------------#
# SubDomain queries #
#-------------------#

def get_subdomains(write_filepath=None, exclude_subdomains=False, ctx={}):
	"""Get Subdomain objects from DB.

	Args:
		write_filepath (str): Write info back to a file.
		exclude_subdomains (bool): Exclude subdomains, only return subdomain matching domain.
		ctx (dict): ctx

	Returns:
		list: List of subdomains matching query.
	"""
	domain_id = ctx.get('domain_id')
	scan_id = ctx.get('scan_history_id')
	subdomain_id = ctx.get('subdomain_id')
	exclude_subdomains = ctx.get('exclude_subdomains', False)
	url_filter = ctx.get('url_filter', '')
	domain = Domain.objects.filter(pk=domain_id).first()
	scan = ScanHistory.objects.filter(pk=scan_id).first()

	query = Subdomain.objects
	if domain:
		query = query.filter(target_domain=domain)
	if scan:
		query = query.filter(scan_history=scan)
	if subdomain_id:
		query = query.filter(pk=subdomain_id)
	elif domain and exclude_subdomains:
		query = query.filter(name=domain.name)
	subdomain_query = query.distinct('name').order_by('name')
	subdomains = [
		subdomain.name
		for subdomain in subdomain_query.all()
		if subdomain.name
	]
	if not subdomains:
		logger.error('No subdomains were found in query')

	if url_filter:
		subdomains = [f'{subdomain}/{url_filter}' for subdomain in subdomains]

	if write_filepath:
		with open(write_filepath, 'w') as f:
			f.write('\n'.join(subdomains))

	return subdomains

def get_new_added_subdomain(scan_id, domain_id):
	"""Find domains added during the last scan.

	Args:
		scan_id (int): startScan.models.ScanHistory ID.
		domain_id (int): startScan.models.Domain ID.

	Returns:
		django.models.querysets.QuerySet: query of newly added subdomains.
	"""
	scan = (
		ScanHistory.objects
		.filter(domain=domain_id)
		.filter(tasks__overlap=['subdomain_discovery'])
		.filter(id__lte=scan_id)
	)
	if not scan.count() > 1:
		return
	last_scan = scan.order_by('-start_scan_date')[1]
	scanned_host_q1 = (
		Subdomain.objects
		.filter(scan_history__id=scan_id)
		.values('name')
	)
	scanned_host_q2 = (
		Subdomain.objects
		.filter(scan_history__id=last_scan.id)
		.values('name')
	)
	added_subdomain = scanned_host_q1.difference(scanned_host_q2)
	return (
		Subdomain.objects
		.filter(scan_history=scan_id)
		.filter(name__in=added_subdomain)
	)


def get_removed_subdomain(scan_id, domain_id):
	"""Find domains removed during the last scan.

	Args:
		scan_id (int): startScan.models.ScanHistory ID.
		domain_id (int): startScan.models.Domain ID.

	Returns:
		django.models.querysets.QuerySet: query of newly added subdomains.
	"""
	scan_history = (
		ScanHistory.objects
		.filter(domain=domain_id)
		.filter(tasks__overlap=['subdomain_discovery'])
		.filter(id__lte=scan_id)
	)
	if not scan_history.count() > 1:
		return
	last_scan = scan_history.order_by('-start_scan_date')[1]
	scanned_host_q1 = (
		Subdomain.objects
		.filter(scan_history__id=scan_id)
		.values('name')
	)
	scanned_host_q2 = (
		Subdomain.objects
		.filter(scan_history__id=last_scan.id)
		.values('name')
	)
	removed_subdomains = scanned_host_q2.difference(scanned_host_q1)
	return (
		Subdomain.objects
		.filter(scan_history=last_scan)
		.filter(name__in=removed_subdomains)
	)


def get_interesting_subdomains(scan_history=None, domain_id=None):
	"""Get Subdomain objects matching InterestingLookupModel conditions.

	Args:
		scan_history (startScan.models.ScanHistory, optional): Scan history.
		domain_id (int, optional): Domain id.

	Returns:
		django.db.Q: QuerySet object.
	"""
	lookup_keywords = get_lookup_keywords()
	lookup_obj = (
		InterestingLookupModel.objects
		.filter(custom_type=True)
		.order_by('-id').first())
	if not lookup_obj:
		return Subdomain.objects.none()

	url_lookup = lookup_obj.url_lookup
	title_lookup = lookup_obj.title_lookup
	condition_200_http_lookup = lookup_obj.condition_200_http_lookup

	# Filter on domain_id, scan_history_id
	query = Subdomain.objects
	if domain_id:
		query = query.filter(target_domain__id=domain_id)
	elif scan_history:
		query = query.filter(scan_history__id=scan_history)

	# Filter on HTTP status code 200
	if condition_200_http_lookup:
		query = query.filter(http_status__exact=200)

	# Build subdomain lookup / page title lookup queries
	url_lookup_query = Q()
	title_lookup_query = Q()
	for key in lookup_keywords:
		if url_lookup:
			url_lookup_query |= Q(name__icontains=key)
		if title_lookup:
			title_lookup_query |= Q(page_title__iregex=f"\\y{key}\\y")

	# Filter on url / title queries
	url_lookup_query = query.filter(url_lookup_query)
	title_lookup_query = query.filter(title_lookup_query)

	# Return OR query
	return url_lookup_query | title_lookup_query


#------------------#
# EndPoint queries #
#------------------#

def get_http_urls(
		is_alive=False,
		is_uncrawled=False,
		strict=False,
		ignore_files=False,
		write_filepath=None,
		exclude_subdomains=False,
		get_only_default_urls=False,
		ctx={}):
	"""Get HTTP urls from EndPoint objects in DB. Support filtering out on a
	specific path.

	Args:
		is_alive (bool): If True, select only alive urls.
		is_uncrawled (bool): If True, select only urls that have not been crawled.
		write_filepath (str): Write info back to a file.
		get_only_default_urls (bool):

	Returns:
		list: List of URLs matching query.
	"""
	domain_id = ctx.get('domain_id')
	scan_id = ctx.get('scan_history_id')
	subdomain_id = ctx.get('subdomain_id')
	url_filter = ctx.get('url_filter', '')
	domain = Domain.objects.filter(pk=domain_id).first()
	scan = ScanHistory.objects.filter(pk=scan_id).first()

	query = EndPoint.objects
	if domain:
		query = query.filter(target_domain=domain)
	if scan:
		query = query.filter(scan_history=scan)
	if subdomain_id:
		query = query.filter(subdomain__id=subdomain_id)
	elif exclude_subdomains and domain:
		query = query.filter(http_url=domain.http_url)
	if get_only_default_urls:
		query = query.filter(is_default=True)

	# If is_uncrawled is True, select only endpoints that have not been crawled
	# yet (no status). EndPoint.http_status defaults to 0, so we match both
	# 0 (newly seeded) and NULL (explicitly unset).
	if is_uncrawled:
		query = query.filter(Q(http_status__isnull=True) | Q(http_status=0))

	# If a path is passed, select only endpoints that contains it
	if url_filter and domain:
		url = f'{domain.name}{url_filter}'
		if strict:
			query = query.filter(http_url=url)
		else:
			query = query.filter(http_url__contains=url)

	# Filter alive endpoints in the database (matches EndPoint.is_alive hybrid_property).
	if is_alive:
		query = query.filter(
			http_status__gt=0,
			http_status__lt=500,
		).exclude(http_status=404)

	# Distinct URLs only — values_list avoids loading full ORM rows for large scans.
	endpoints = list(
		query.order_by('http_url').values_list('http_url', flat=True).distinct()
	)
	endpoints = [u for u in endpoints if is_valid_url(u)]
	if ignore_files: # ignore all files
		extensions_path = f'{RENGINE_HOME}/fixtures/extensions.txt'
		with open(extensions_path, 'r') as f:
			extensions = tuple(f.strip() for f in f.readlines())
		endpoints = [e for e in endpoints if not urlparse(e).path.endswith(extensions)]

	if not endpoints:
		logger.error('No endpoints were found in query')

	if write_filepath:
		with open(write_filepath, 'w') as f:
			f.write('\n'.join(endpoints))

	return endpoints

def collect_all_scan_urls(ctx, results_dir, ignore_files=True):
	"""Collect all discovered URLs for a scan from both DB and spidering result files.

	Combines:
	- All EndPoint records in DB for this scan (no alive-only filter)
	- {results_dir}/fetch_url.txt  (consolidated spidering output from all tools)
	- {results_dir}/urls_*.txt     (individual tool outputs as a safety net)

	Returns a sorted, deduplicated list of validated HTTP/HTTPS URLs.

	Args:
		ctx (dict): Scan context with at least 'scan_history_id' and 'domain_id'.
		results_dir (str): Path to the scan results directory.
		ignore_files (bool): When True, strip URLs whose path ends with a known
			static-file extension (uses fixtures/extensions.txt).

	Returns:
		list[str]: Sorted, deduplicated, validated URLs.
	"""
	all_urls = set()

	# --- Source 1: DB endpoints (all, not filtered by alive status) ---
	db_urls = get_http_urls(
		is_alive=False,
		ignore_files=ignore_files,
		ctx=ctx,
	)
	all_urls.update(db_urls)
	logger.info(
		'collect_all_scan_urls: %d URLs from DB (scan_id=%s)',
		len(db_urls),
		ctx.get('scan_history_id'),
	)

	# --- Source 2: Spidering result files ---
	file_urls_before = len(all_urls)
	if results_dir and os.path.isdir(results_dir):
		# fetch_url.txt is the primary consolidated file; urls_*.txt are per-tool outputs
		candidates = [os.path.join(results_dir, 'fetch_url.txt')]
		candidates += glob.glob(os.path.join(results_dir, 'urls_*.txt'))
		for filepath in candidates:
			if not os.path.isfile(filepath):
				continue
			try:
				with open(filepath, 'r', errors='replace') as fh:
					for raw_line in fh:
						url = raw_line.strip()
						if url and is_valid_url(url):
							all_urls.add(url)
			except OSError as exc:
				logger.warning(
					'collect_all_scan_urls: cannot read %s: %s', filepath, exc
				)
	logger.info(
		'collect_all_scan_urls: %d additional URLs from result files',
		len(all_urls) - file_urls_before,
	)

	# --- Extension filter for file-sourced URLs not yet filtered by get_http_urls ---
	if ignore_files:
		extensions_path = os.path.join(RENGINE_HOME, 'fixtures', 'extensions.txt')
		if os.path.isfile(extensions_path):
			with open(extensions_path, 'r') as fh:
				extensions = tuple(
					line.strip() for line in fh if line.strip()
				)
			all_urls = {
				u for u in all_urls
				if not urlparse(u).path.endswith(extensions)
			}

	result = sorted(all_urls)
	logger.info(
		'collect_all_scan_urls: %d total deduplicated URLs for scan_id=%s',
		len(result),
		ctx.get('scan_history_id'),
	)
	return result


def get_interesting_endpoints(scan_history=None, target=None):
	"""Get EndPoint objects matching InterestingLookupModel conditions.

	Args:
		scan_history (startScan.models.ScanHistory): Scan history.
		target (str): Domain id.

	Returns:
		django.db.Q: QuerySet object.
	"""

	lookup_keywords = get_lookup_keywords()
	lookup_obj = InterestingLookupModel.objects.filter(custom_type=True).order_by('-id').first()
	if not lookup_obj:
		return EndPoint.objects.none()
	url_lookup = lookup_obj.url_lookup
	title_lookup = lookup_obj.title_lookup
	condition_200_http_lookup = lookup_obj.condition_200_http_lookup

	# Filter on domain_id, scan_history_id
	query = EndPoint.objects
	if target:
		query = query.filter(target_domain__id=target)
	elif scan_history:
		query = query.filter(scan_history__id=scan_history)

	# Filter on HTTP status code 200
	if condition_200_http_lookup:
		query = query.filter(http_status__exact=200)

	# Build subdomain lookup / page title lookup queries
	url_lookup_query = Q()
	title_lookup_query = Q()
	for key in lookup_keywords:
		if url_lookup:
			url_lookup_query |= Q(http_url__icontains=key)
		if title_lookup:
			title_lookup_query |= Q(page_title__iregex=f"\\y{key}\\y")

	# Filter on url / title queries
	url_lookup_query = query.filter(url_lookup_query)
	title_lookup_query = query.filter(title_lookup_query)

	# Return OR query
	return url_lookup_query | title_lookup_query


#-----------#
# URL utils #
#-----------#

def get_subdomain_from_url(url):
	"""Get subdomain from HTTP URL.

	Args:
		url (str): HTTP URL.

	Returns:
		str: Subdomain name.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in url:
		url = "http://" + url

	url_obj = urlparse(url.strip())
	return url_obj.netloc.split(':')[0]


def get_domain_from_subdomain(subdomain):
	"""Get domain from subdomain.

	Args:
		subdomain (str): Subdomain name.

	Returns:
		str: Domain name.
	"""
	# ext = tldextract.extract(subdomain)
	# return '.'.join(ext[1:3])

	if not validators.domain(subdomain):
		return None
	
	# Use tldextract to parse the subdomain
	extracted = tldextract.extract(subdomain)

	# if tldextract recognized the tld then its the final result
	if extracted.suffix:
		domain = f"{extracted.domain}.{extracted.suffix}"
	else:
		# Fallback method for unknown TLDs, like .clouds or .local etc
		parts = subdomain.split('.')
		if len(parts) >= 2:
			domain = '.'.join(parts[-2:])
		else:
			return None
		
	# Validate the domain before returning
	return domain if validators.domain(domain) else None



def sanitize_url(http_url):
	"""Removes HTTP ports 80 and 443 from HTTP URL because it's ugly.

	Args:
		http_url (str): Input HTTP URL.

	Returns:
		str: Stripped HTTP URL.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in http_url:
		http_url = "http://" + http_url
	try:
		url = urlparse(http_url)
	except ValueError:
		# Python 3.10+ raises ValueError for malformed bracket hosts (e.g. http://[]/path).
		return http_url.rstrip('/')

	if url.netloc.endswith(':80'):
		url = url._replace(netloc=url.netloc.replace(':80', ''))
	elif url.netloc.endswith(':443'):
		url = url._replace(scheme=url.scheme.replace('http', 'https'))
		url = url._replace(netloc=url.netloc.replace(':443', ''))
	return url.geturl().rstrip('/')

def parse_fetched_url_line(raw_line, starting_point_path=''):
	"""Normalize a single line from fetch_url tool output into a usable URL.

	Handles gospider-style lines like ``https://host/path] - /extra`` and
	``https://host - /path``. Invalid or filtered lines return None.
	"""
	url = (raw_line or '').strip()
	if not url:
		return None

	urlpath = None
	base_url = None
	if '] ' in url:
		split = tuple(url.split('] ', 1))
		if len(split) != 2:
			return None
		base_url, urlpath = split
		urlpath = urlpath.lstrip('- ')
	elif ' - ' in url:
		parts = url.split(' - ', 1)
		if len(parts) == 2:
			base_url, urlpath = parts

	if base_url and urlpath:
		if '://' not in base_url:
			base_url = f'http://{base_url}'
		parsed_base = urlparse(base_url)
		path = urlpath if urlpath.startswith('/') else f'/{urlpath}'
		url = f'{parsed_base.scheme}://{parsed_base.netloc}{path}'

	if starting_point_path and starting_point_path not in url:
		return None
	if not is_valid_url(url):
		return None
	return url


def url_param_signature(url):
	"""Return a dedup key based on scheme, netloc, path, and sorted param names (ignoring values).

	Two URLs sharing the same signature differ only in parameter values (e.g. ?id=1 vs ?id=2)
	and can be treated as the same functional endpoint for load-reduction purposes.
	"""
	try:
		parsed = urlparse(url)
		param_keys = ','.join(sorted(parse_qs(parsed.query).keys()))
		return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_keys}"
	except Exception:
		return url


def extract_path_from_url(url):
	parsed_url = urlparse(url)

	# Reconstruct the URL without scheme and netloc
	reconstructed_url = parsed_url.path

	if reconstructed_url.startswith('/'):
		reconstructed_url = reconstructed_url[1:]  # Remove the first slash

	if parsed_url.params:
		reconstructed_url += ';' + parsed_url.params
	if parsed_url.query:
		reconstructed_url += '?' + parsed_url.query
	if parsed_url.fragment:
		reconstructed_url += '#' + parsed_url.fragment

	return reconstructed_url

#-------#
# Utils #
#-------#

def record_exists(model, data, exclude_keys=[]):
	"""
	Check if a record already exists in the database based on the given data.

	Args:
		model (django.db.models.Model): The Django model to check against.
		data (dict): Data dictionary containing fields and values.
		exclude_keys (list): List of keys to exclude from the lookup.

	Returns:
		bool: True if the record exists, False otherwise.
	"""

	# Extract the keys that will be used for the lookup
	lookup_fields = {key: data[key] for key in data if key not in exclude_keys}

	# Return True if a record exists based on the lookup fields, False otherwise
	return model.objects.filter(**lookup_fields).exists()

def save_vulnerability(vuln_data=None, scan_history=None, target_domain=None, dedup_fields=None, **kwargs):
	# Support both positional and keyword arguments for backward compatibility
	if vuln_data and isinstance(vuln_data, dict):
		vuln_data.update(kwargs)
		if scan_history:
			vuln_data['scan_history'] = scan_history
		if target_domain:
			vuln_data['target_domain'] = target_domain
	else:
		vuln_data = kwargs
		if scan_history:
			vuln_data['scan_history'] = scan_history
		if target_domain:
			vuln_data['target_domain'] = target_domain

	# Ensure severity is an integer if passed as a string
	severity = vuln_data.get('severity')
	if isinstance(severity, str):
		from reNgine.definitions import NUCLEI_SEVERITY_MAP
		vuln_data['severity'] = NUCLEI_SEVERITY_MAP.get(severity.lower(), 2)  # default to Medium

	references = vuln_data.pop('references', [])
	cve_ids = vuln_data.pop('cve_ids', [])
	cwe_ids = vuln_data.pop('cwe_ids', [])
	tags = vuln_data.pop('tags', [])
	subscan = vuln_data.pop('subscan', None)

	exploit_url = vuln_data.pop('exploit_url', None)
	validation_status = vuln_data.pop('validation_status', 'unverified')

	# If subdomain is not provided, try to find it from http_url
	subdomain = vuln_data.get('subdomain')
	http_url = vuln_data.get('http_url')
	scan_history = vuln_data.get('scan_history')
	target_domain = vuln_data.get('target_domain')

	if not subdomain and http_url and scan_history and target_domain:
		from reNgine.utils.task import save_subdomain
		subdomain_name = get_subdomain_from_url(http_url)
		subdomain, _ = save_subdomain(subdomain_name, ctx={
			'scan_history_id': scan_history.id,
			'domain_id': target_domain.id,
		})
		if subdomain:
			vuln_data['subdomain'] = subdomain

	# remove nulls
	vuln_data = replace_nulls(vuln_data)

	# Check for False Positive rules
	is_suppressed = False
	try:
		from startScan.models import FalsePositiveRule
		rules = FalsePositiveRule.objects.filter(target_domain=target_domain, is_active=True)
		for rule in rules:
			if rule.matches(vuln_data.get('name', ''), http_url):
				is_suppressed = True
				break
	except Exception as e:
		logger.error("Error checking FP rules: %s", e)

	if is_suppressed:
		vuln_data['is_suppressed'] = True

	# Create vulnerability — use narrower dedup key when caller specifies one,
	# so volatile fields like description don't cause duplicate rows on re-scan.
	if not dedup_fields:
		dedup_fields = ['name', 'scan_history']
		if 'subdomain' in vuln_data:
			dedup_fields.append('subdomain')
		if 'http_url' in vuln_data:
			dedup_fields.append('http_url')

	lookup = {k: vuln_data.pop(k) for k in dedup_fields if k in vuln_data}
	vuln, created = Vulnerability.objects.update_or_create(defaults=vuln_data, **lookup)
	vuln_data.update(lookup)  # restore for use below (tags, auth-candidate, etc.)
	if created:
		vuln.discovered_date = timezone.now()
		vuln.open_status = True
		if exploit_url:
			vuln.exploit_url = exploit_url
		vuln.validation_status = validation_status
		vuln.save()

		# Centralized Brute-Force Candidate Registration
		auth_keywords = ['login', 'admin', 'auth', 'portal', 'credentials', 'password']
		name = vuln_data.get('name', '').lower()
		description = vuln_data.get('description', '').lower()
		
		if any(k in name or k in description for k in auth_keywords):
			try:
				from reNgine.utilities import save_auth_candidate
				http_url = vuln_data.get('http_url', '')
				parsed = urlparse(http_url)
				port = parsed.port or (443 if parsed.scheme == 'https' else 80)
				target = parsed.hostname
				
				if target:
					save_auth_candidate(
						scan_history=scan_history,
						subdomain=subdomain,
						target=target,
						protocol='http',
						port=port,
						source_tool=vuln_data.get('type', 'vulnerability_engine'),
						tech_hint=name
					)
			except Exception as e:
				logger.error("Error registering AuthCandidate from vulnerability %s: %s", name, e)
	elif exploit_url and not vuln.exploit_url:
		vuln.exploit_url = exploit_url
		vuln.save()

	# Save vuln tags
	for tag_name in tags or []:
		tag, created = VulnerabilityTags.objects.get_or_create(name=tag_name)
		if tag:
			vuln.tags.add(tag)
			vuln.save()

	# Save CVEs
	for cve_id in cve_ids or []:
		# Ignore empty/null CVE IDs
		if not cve_id or not str(cve_id).strip():
			continue
		normalized = str(cve_id).strip().upper()
		# Accept bare YYYY-NNNNN values (missing the CVE- prefix)
		if re.match(r'^\d{4}-\d+$', normalized):
			normalized = 'CVE-' + normalized
		cve, created = CveId.objects.get_or_create(name=normalized)
		if cve:
			vuln.cve_ids.add(cve)
			vuln.save()

	# Save CWEs
	for cwe_id in cwe_ids or []:
		# Ignore empty/null CWE IDs
		if not cwe_id or not str(cwe_id).strip():
			continue
		cwe, created = CweId.objects.get_or_create(name=str(cwe_id).strip())
		if cwe:
			vuln.cwe_ids.add(cwe)
			vuln.save()

	# Save vuln reference
	for url in references or []:
		ref, created = VulnerabilityReference.objects.get_or_create(url=url)
		if ref:
			vuln.references.add(ref)
			vuln.save()

	# Save subscan id in vuln object
	if subscan:
		from startScan.models import SubScan
		subscan_pk = subscan.pk if hasattr(subscan, 'pk') else subscan
		if SubScan.objects.filter(pk=subscan_pk).exists():
			vuln.vuln_subscan_ids.add(subscan)
			vuln.save()

	return vuln, created


def get_spiderfoot_keys():
	"""Get Spiderfoot API keys from DB.

	Returns:
		dict: Dictionary of module_name: key_value.
	"""
	keys = SpiderfootAPIKey.objects.all()
	return {k.module_name: k.key_value for k in keys}


def get_leaklookup_key():
	"""Get LeakLookup API key from DB.

	Returns:
		str: LeakLookup API key or ''.
	"""
	key_obj = LeakLookupAPIKey.objects.first()
	return key_obj.key if key_obj else ''


def get_chaos_api_key():
	"""Get Chaos API key from DB (used for ProjectDiscovery).

	Returns:
		str: Chaos API key or ''.
	"""
	key_obj = ChaosAPIKey.objects.first()
	return key_obj.key if key_obj else ''


# ---------------------------------------------------------------------------
# Module-level cache of proxies known to be dead within this process lifetime.
# Cleared between scans automatically because Celery workers restart between
# tasks. Prevents wasting timeout budget re-checking proxies that already
# failed during the same scan session.
# ---------------------------------------------------------------------------
_failed_proxy_cache: set = set()


def _detect_server_ip(timeout: int = 5) -> str:
	"""Return the server's own outbound IP by hitting an IP-reflection API
	without a proxy. Returns '' on any failure.

	Used only when OpSec transparent-proxy detection is enabled.
	"""
	try:
		resp = requests.get(
			'https://api.ipify.org?format=json',
			timeout=timeout,
			headers={'User-Agent': 'Mozilla/5.0'},
		)
		if resp.status_code == 200:
			return resp.json().get('ip', '')
	except Exception:
		pass
	return ''


def _is_valid_ip(value: str) -> bool:
	"""Return True if *value* looks like a valid IPv4 or IPv6 address.

	This filters out captive-portal strings like 'Login Required' that could
	otherwise fool a simple 200-OK JSON check.
	"""
	import ipaddress
	try:
		ipaddress.ip_address(value)
		return True
	except ValueError:
		return False


def check_proxy_robust(proxy_url, timeout=10, server_ip=''):
	"""Test if a proxy is truly working and not a transparent/captive-portal proxy.

	Improvements over the old implementation:
	  - Both IP-reflection endpoints are checked in *parallel* (short-circuit on
	    first success) rather than sequentially, halving worst-case latency.
	  - The returned IP value is validated as a real IPv4 / IPv6 address so that
	    captive-portal HTML strings cannot produce a false positive.
	  - When ``server_ip`` is provided (and OpSec transparent-proxy detection is
	    enabled), the proxy is rejected if its reported IP matches the server's own
	    outbound IP (i.e. the proxy is transparent and exposes the real source).

	Args:
		proxy_url (str): The proxy connection string (e.g., http://1.2.3.4:8080).
		timeout (int): Per-request timeout in seconds. Defaults to 10.
		server_ip (str): The server's own outbound IP string (for transparent-proxy
			detection). Pass '' to disable the check.

	Returns:
		bool: True if the proxy forwards traffic correctly, False otherwise.
	"""
	import ipaddress as _ipaddr
	from concurrent.futures import ThreadPoolExecutor, as_completed

	try:
		proxy_url = proxy_url.strip()
		if not proxy_url:
			return False
		# Normalise – ensure a scheme is present so requests can route correctly
		test_proxy = proxy_url
		if not any(test_proxy.startswith(s) for s in ['http://', 'https://', 'socks4://', 'socks5://']):
			test_proxy = 'http://' + test_proxy

		proxies = {'http': test_proxy, 'https': test_proxy}
		headers = {
			'User-Agent': (
				'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
				'(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
			)
		}

		# Two independent IP-reflection endpoints checked in parallel.
		check_targets = [
			('https://api.ipify.org?format=json', 'ip'),
			('http://ip-api.com/json',            'query'),
		]

		def _try_endpoint(url, key):
			"""Return the reported IP string or raise on failure."""
			resp = requests.get(
				url,
				proxies=proxies,
				headers=headers,
				timeout=timeout,
				allow_redirects=True,
			)
			if resp.status_code != 200:
				raise ValueError(f'HTTP {resp.status_code}')
			data = resp.json()
			ip_str = data.get(key, '')
			if not ip_str:
				raise ValueError('empty IP field in response')
			if not _is_valid_ip(ip_str):
				raise ValueError(f'response IP is not a valid IP address: {ip_str!r}')
			return ip_str

		reported_ip = None
		with ThreadPoolExecutor(max_workers=2) as _pool:
			future_map = {_pool.submit(_try_endpoint, u, k): (u, k) for u, k in check_targets}
			for fut in as_completed(future_map):
				try:
					reported_ip = fut.result()
					# Cancel the sibling future – we have our answer
					for other in future_map:
						if other is not fut:
							other.cancel()
					break
				except Exception:
					continue  # try the other endpoint

		if not reported_ip:
			# Both endpoints failed – proxy is dead or blocking check requests
			return False

		# Optional transparent-proxy detection: reject if the proxy simply
		# forwards our real IP without changing it.
		if server_ip and reported_ip == server_ip:
			logger.warning(
				'Proxy %s is transparent – reported IP %s matches server IP. Rejecting.',
				proxy_url, reported_ip,
			)
			return False

		return True
	except Exception:
		return False


def validate_single_proxy(proxy_name):
	"""Helper to validate a single proxy string.
	Returns (proxy_name, True) if valid, otherwise (proxy_name, False).
	"""
	is_valid = check_proxy_robust(proxy_name, timeout=10)
	return proxy_name, is_valid


def validate_proxies(proxy_text):
	"""Concurrently validate newline-separated proxy strings using the same robust logic as the fetch task.
	Returns a newline-separated string of validated live proxies.
	"""
	from concurrent.futures import ThreadPoolExecutor, as_completed
	if not proxy_text:
		return ''
	raw_proxies = [line.strip() for line in proxy_text.splitlines() if line.strip()]
	if not raw_proxies:
		return ''
	valid_proxies = []
	max_workers = min(1000, max(1, len(raw_proxies)))
	with ThreadPoolExecutor(max_workers=max_workers) as executor:
		future_to_proxy = {executor.submit(check_proxy_robust, p, 10): p for p in raw_proxies}
		for future in as_completed(future_to_proxy):
			proxy_name = future_to_proxy[future]
			try:
				is_valid = future.result()
			except Exception:
				is_valid = False
			if is_valid:
				valid_proxies.append(proxy_name)
	return '\n'.join(valid_proxies)



# Curated pool of modern desktop browser user agents for realistic request spoofing.
# Rotated when OpSec random UA is enabled.
_USER_AGENT_POOL = [
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
	'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0',
	'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Vivaldi/6.7.3329.21',
]

# Fallback UA used when OpSec random UA is disabled.
_DEFAULT_USER_AGENT = _USER_AGENT_POOL[0]


def get_random_user_agent():
	"""Return a user agent string respecting the OpSec random UA setting.

	If OpSec is enabled and enable_random_ua is True, returns a randomly chosen
	modern browser user agent from the curated pool. Otherwise returns the default
	Chrome UA to avoid fingerprinting as a scanner.

	Returns:
		str: A User-Agent header value string.
	"""
	try:
		from scanEngine.models import OpSec
		opsec = OpSec.objects.first()
		if opsec and opsec.enable_random_ua:
			return random.choice(_USER_AGENT_POOL)
	except Exception as e:
		logger.warning('get_random_user_agent: could not read OpSec settings: %s', e)
	return _DEFAULT_USER_AGENT


def get_random_proxy():
	"""Get a random proxy from the list stored in the database.

	Enhancements over the old implementation:
	  - **Freshness short-circuit**: if the proxy list was batch-verified by
	    ``fetch_proxies_task`` within the configured TTL (default 120 min) it is
	    trusted directly and a random entry is returned without re-validation.
	    This prevents hundreds of milliseconds of blocking overhead on every tool
	    call during a scan.
	  - **Parallel re-validation**: when the list is stale, all candidate proxies
	    are checked concurrently (up to 50 workers) instead of sequentially.
	    The first live one wins; the rest are cancelled.
	  - **In-process failure cache**: proxies that fail during the current scan
	    session are recorded in ``_failed_proxy_cache`` and skipped on subsequent
	    calls, avoiding repeated timeouts against already-dead entries.
	  - **Transparent-proxy detection**: when the OpSec setting
	    ``enable_transparent_proxy_detection`` is True the server's own outbound IP
	    is detected once per call and passed to ``check_proxy_robust`` so that
	    transparent proxies are rejected.

	Returns:
		str: Proxy URL string, 'socks5://tor:9050' when TOR is enabled, or '' if
			 no valid proxy is available.
	"""
	from concurrent.futures import ThreadPoolExecutor, as_completed
	from datetime import timezone as _tz
	import datetime as _dt

	# ------------------------------------------------------------------
	# TOR mode: bypass all proxy logic and return the TOR SOCKS5 address
	# ------------------------------------------------------------------
	_proxy_obj = Proxy.objects.first()
	if _proxy_obj and _proxy_obj.use_tor:
		return 'socks5://tor:9050'

	if not _proxy_obj or not _proxy_obj.use_proxy:
		return ''

	# Parse and clean the newline-separated proxy lines
	raw_proxies = [p.strip() for p in (_proxy_obj.proxies or '').splitlines() if p.strip()]
	if not raw_proxies:
		return ''

	# Normalise – ensure every entry has a scheme
	proxies = []
	for p in raw_proxies:
		if not p.startswith('http') and not p.startswith('socks'):
			p = f'http://{p}'
		proxies.append(p)

	# Remove entries that have already failed this session
	candidates = [p for p in proxies if p not in _failed_proxy_cache]
	if not candidates:
		# All known proxies have failed – clear the cache and try again fresh
		logger.warning('All cached proxies failed this session. Clearing failure cache.')
		_failed_proxy_cache.clear()
		candidates = proxies

	# ------------------------------------------------------------------
	# Freshness short-circuit
	# If the batch verification is recent enough, trust it and return a
	# random candidate without any individual re-validation.
	# ------------------------------------------------------------------
	ttl_minutes = getattr(_proxy_obj, 'proxy_ttl_minutes', 120) or 120
	verified_at = getattr(_proxy_obj, 'proxies_verified_at', None)
	if verified_at is not None:
		now_utc = _dt.datetime.now(_tz.utc)
		age_minutes = (now_utc - verified_at).total_seconds() / 60
		if age_minutes <= ttl_minutes:
			chosen = random.choice(candidates)
			logger.info(
				'Proxy list is fresh (%.1f min old, TTL %d min). '
				'Returning %s without re-validation.',
				age_minutes, ttl_minutes, chosen,
			)
			return chosen
		logger.info(
			'Proxy list is stale (%.1f min old, TTL %d min). '
			'Falling back to parallel re-validation.',
			age_minutes, ttl_minutes,
		)
	else:
		logger.info('No proxies_verified_at timestamp found. Performing parallel re-validation.')

	# ------------------------------------------------------------------
	# Optional transparent-proxy detection (opt-in via OpSec setting)
	# ------------------------------------------------------------------
	server_ip = ''
	try:
		from scanEngine.models import OpSec as _OpSec
		_opsec = _OpSec.objects.first()
		if _opsec and getattr(_opsec, 'enable_transparent_proxy_detection', False):
			server_ip = _detect_server_ip(timeout=5)
			if server_ip:
				logger.info('Transparent proxy detection enabled. Server IP: %s', server_ip)
	except Exception as _e:
		logger.warning('Could not read OpSec settings for transparent proxy detection: %s', _e)

	# ------------------------------------------------------------------
	# Parallel re-validation – first live proxy wins
	# ------------------------------------------------------------------
	random.shuffle(candidates)
	# Cap workers to avoid spawning thousands of threads for a huge list
	max_workers = min(50, len(candidates))

	result_holder = [None]  # thread-safe single-slot via GIL

	def _check(proxy_url):
		"""Check a single proxy; mark it failed on the cache if dead."""
		if check_proxy_robust(proxy_url, timeout=10, server_ip=server_ip):
			return proxy_url
		_failed_proxy_cache.add(proxy_url)
		return None

	with ThreadPoolExecutor(max_workers=max_workers) as pool:
		future_map = {pool.submit(_check, p): p for p in candidates}
		for fut in as_completed(future_map):
			try:
				live = fut.result()
			except Exception:
				live = None
			if live:
				result_holder[0] = live
				# Cancel remaining futures to stop wasting resources
				for other in future_map:
					if other is not fut:
						other.cancel()
				break

	if result_holder[0]:
		logger.info('Using valid proxy (parallel validation): %s', result_holder[0])
		return result_holder[0]

	logger.error('No valid proxies found after parallel re-validation!')
	return ''


def get_proxy_list():
	"""Get a list of all proxies input by the user in the UI.
	Does not validate if they are alive.
	
	Returns:
		list: List of proxy names or [] if no proxy defined or use_proxy is False,
			  or if use_tor is True (since Tor uses proxychains).
	"""
	proxy = Proxy.objects.first()
	if not proxy or not proxy.use_proxy or proxy.use_tor:
		return []

	proxies = [p.strip() for p in proxy.proxies.splitlines() if p.strip()]
	cleaned_proxies = []
	for p in proxies:
		if not p.startswith('http') and not p.startswith('socks'):
			p = f"http://{p}"
		cleaned_proxies.append(p)

	return cleaned_proxies

def remove_ansi_escape_sequences(text):
	# Regular expression to match ANSI escape sequences
	ansi_escape_pattern = r'\x1b\[.*?m'

	# Use re.sub() to replace the ANSI escape sequences with an empty string
	plain_text = re.sub(ansi_escape_pattern, '', text)
	return plain_text

def get_cms_details(url):
	"""Get CMS details using cmseek.py.

	Args:
		url (str): HTTP URL.

	Returns:
		dict: Response.
	"""
	# this function will fetch cms details using cms_detector
	response = {}
	subprocess.run(
		['python3', '/usr/src/github/CMSeeK/cmseek.py',
		 '--random-agent', '--batch', '--follow-redirect', '-u', url],
		check=False
	)

	response['status'] = False
	response['message'] = 'Could not detect CMS!'

	parsed_url = urlparse(url)

	domain_name = parsed_url.hostname
	port = parsed_url.port

	find_dir = domain_name

	if port:
		find_dir += f'_{port}'

	# subdomain may also have port number, and is stored in dir as _port

	cms_dir_path =  f'/usr/src/github/CMSeeK/Result/{find_dir}'
	cms_json_path =  cms_dir_path + '/cms.json'

	if os.path.isfile(cms_json_path):
		cms_file_content = json.loads(open(cms_json_path, 'r').read())
		if not cms_file_content.get('cms_id'):
			return response
		response = {}
		response = cms_file_content
		response['status'] = True
		# remove cms dir path
		try:
			shutil.rmtree(cms_dir_path)
		except Exception as e:
			logger.error("Failed to remove CMS scan directory %s: %s", cms_dir_path, e)

	return response


#--------------------#
# NOTIFICATION UTILS #
#--------------------#

def send_telegram_message(message):
	"""Send Telegram message.

	Args:
		message (str): Message.
	"""
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_telegram and
		notif.telegram_bot_token and
		notif.telegram_bot_chat_id)
	if not do_send:
		return
	telegram_bot_token = notif.telegram_bot_token
	telegram_bot_chat_id = notif.telegram_bot_chat_id
	send_url = f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?chat_id={telegram_bot_chat_id}&parse_mode=Markdown&text={message}'
	requests.get(send_url)


def send_slack_message(message):
	"""Send Slack message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {'text': message}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_slack and
		notif.slack_hook_url)
	if not do_send:
		return
	hook_url = notif.slack_hook_url
	try:
		validate_external_url(hook_url)
	except ValueError:
		return
	requests.post(url=hook_url, data=json.dumps(message), headers=headers)

def send_lark_message(message):
	"""Send lark message.

	Args:
		message (str): Message.
	"""
	headers = {'content-type': 'application/json'}
	message = {"msg_type":"interactive","card":{"elements":[{"tag":"div","text":{"content":message,"tag":"lark_md"}}]}}
	notif = Notification.objects.first()
	do_send = (
		notif and
		notif.send_to_lark and
		notif.lark_hook_url)
	if not do_send:
		return
	hook_url = notif.lark_hook_url
	try:
		validate_external_url(hook_url)
	except ValueError:
		return
	requests.post(url=hook_url, data=json.dumps(message), headers=headers)

def send_discord_message(
		message,
		title='',
		severity=None,
		url=None,
		files=None,
		fields={},
		fields_append=[]):
	"""Send Discord message.

	If title and fields are specified, ignore the 'message' and create a Discord
	embed that can be updated later if specifying the same title (title is the
	cache key).

	Args:
		message (str): Message to send. If an embed is used, this is ignored.
		severity (str, optional): Severity. Colors are picked based on severity.
		files (list, optional): List of files to attach to message.
		title (str, optional): Discord embed title.
		url (str, optional): Discord embed URL.
		fields (dict, optional): Discord embed fields.
		fields_append (list, optional): Discord embed field names to update
			instead of overwrite.
	"""

	# Check if do send
	notif = Notification.objects.first()
	if not (notif and notif.send_to_discord and notif.discord_hook_url):
		return False
	try:
		validate_external_url(notif.discord_hook_url)
	except ValueError:
		return False

	# If fields and title, use an embed
	use_discord_embed = fields and title
	if use_discord_embed:
		message = '' # no need for message in embeds

	# Check for cached response in cache, using title as key (stored as JSON message ID)
	cached_msg_id = DISCORD_WEBHOOKS_CACHE.get(title) if title else None

	# Get existing webhook if found in cache (stored as JSON dict)
	cached_webhook_data = DISCORD_WEBHOOKS_CACHE.get(title + '_webhook') if title else None
	if cached_webhook_data:
		wh_dict = json.loads(cached_webhook_data)
		webhook = DiscordWebhook(
			url=wh_dict.get('url', notif.discord_hook_url),
			rate_limit_retry=False,
			content=wh_dict.get('content', message))
		webhook.remove_embeds()
	else:
		webhook = DiscordWebhook(
			url=notif.discord_hook_url,
			rate_limit_retry=False,
			content=message)

	# Get existing embed if found in cache (stored as JSON dict)
	embed = None
	cached_embed_data = DISCORD_WEBHOOKS_CACHE.get(title + '_embed') if title else None
	if cached_embed_data:
		embed_dict = json.loads(cached_embed_data)
		embed = DiscordEmbed(title=embed_dict.get('title', title))
		if embed_dict.get('color'):
			embed.set_color(embed_dict['color'])
		if embed_dict.get('description'):
			embed.set_description(embed_dict['description'])
		for field in embed_dict.get('fields', []):
			embed.add_embed_field(name=field['name'], value=field['value'], inline=field.get('inline', False))
	elif use_discord_embed:
		embed = DiscordEmbed(title=title)

	# Set embed fields
	if embed:
		if url:
			embed.set_url(url)
		if severity:
			embed.set_color(DISCORD_SEVERITY_COLORS[severity])
		embed.set_description(message)
		embed.set_timestamp()
		existing_fields_dict = {field['name']: field['value'] for field in embed.fields}
		logger.debug(''.join([f'\n\t{k}: {v}' for k, v in fields.items()]))
		for name, value in fields.items():
			if not value: # cannot send empty field values to Discord [error 400]
				continue
			value = str(value)
			new_field = {'name': name, 'value': value, 'inline': False}

			# If field already existed in previous embed, update it.
			if name in existing_fields_dict.keys():
				field = [f for f in embed.fields if f['name'] == name][0]

				# Append to existing field value
				if name in fields_append:
					existing_val = field['value']
					existing_val = str(existing_val)
					if value not in existing_val:
						value = f'{existing_val}\n{value}'

					if len(value) > 1024: # character limit for embed field
						value = value[0:1016] + '\n[...]'

				# Update existing embed
				ix = embed.fields.index(field)
				embed.fields[ix]['value'] = value

			else:
				embed.add_embed_field(**new_field)

		webhook.add_embed(embed)

		# Cache webhook and embed data as JSON (never pickle)
		DISCORD_WEBHOOKS_CACHE.set(title + '_webhook', json.dumps({
			'url': webhook.url,
			'content': webhook.content,
		}))
		DISCORD_WEBHOOKS_CACHE.set(title + '_embed', json.dumps({
			'title': embed.title if hasattr(embed, 'title') else title,
			'color': embed.color if hasattr(embed, 'color') else None,
			'description': embed.description if hasattr(embed, 'description') else None,
			'fields': embed.fields if hasattr(embed, 'fields') else [],
		}))

	# Add files to webhook
	if files:
		for (path, name) in files:
			with open(path, 'r') as f:
				content = f.read()
			webhook.add_file(content, name)

	# Edit webhook if it already existed (using cached message ID), otherwise send new
	if cached_msg_id:
		webhook.id = cached_msg_id
		response = webhook.edit(webhook)
	else:
		response = webhook.execute()
		if use_discord_embed and response.status_code == 200:
			try:
				msg_id = response.json().get('id', '')
				DISCORD_WEBHOOKS_CACHE.set(title, msg_id)
			except Exception:
				pass

	# Get status code
	if response.status_code == 429:
		errors = json.loads(
			response.content.decode('utf-8'))
		wh_sleep = (int(errors['retry_after']) / 1000) + 0.15
		sleep(wh_sleep)
		send_discord_message(
				message,
				title,
				severity,
				url,
				files,
				fields,
				fields_append)
	elif response.status_code != 200:
		logger.error(
			'Error while sending webhook data to Discord. HTTP code: %s. Details: %s',
			response.status_code,
			response.content)


def enrich_notification(message, scan_history_id, subscan_id):
	"""Add scan id / subscan id to notification message.

	Args:
		message (str): Original notification message.
		scan_history_id (int): Scan history id.
		subscan_id (int): Subscan id.

	Returns:
		str: Message.
	"""
	if scan_history_id is not None:
		if subscan_id:
			message = f'`#{scan_history_id}_{subscan_id}`: {message}'
		else:
			message = f'`#{scan_history_id}`: {message}'
	return message


def get_scan_title(scan_id, subscan_id=None, task_name=None):
	return f'Subscan #{subscan_id} summary' if subscan_id else f'Scan #{scan_id} summary'


def get_scan_url(scan_id=None, subscan_id=None):
	if scan_id:
		return f'https://{DOMAIN_NAME}/scan/detail/{scan_id}'
	return None


def get_scan_fields(engine, scan, subscan=None, status='RUNNING', tasks=[]):
	scan_obj = subscan if subscan else scan
	if subscan:
		tasks_h = f'`{subscan.type}`'
		host = subscan.subdomain.name
		scan_obj = subscan
	else:
		tasks_h = '• ' + '\n• '.join(f'`{task.name}`' for task in tasks) if tasks else ''
		host = scan.domain.name
		scan_obj = scan

	# Find scan elapsed time
	duration = None
	if scan_obj and status in ['ABORTED', 'FAILED', 'SUCCESS']:
		td = scan_obj.stop_scan_date - scan_obj.start_scan_date
		duration = humanize.naturaldelta(td)
	elif scan_obj:
		td = timezone.now() - scan_obj.start_scan_date
		duration = humanize.naturaldelta(td)

	# Build fields
	url = get_scan_url(scan.id)
	fields = {
		'Status': f'**{status}**',
		'Engine': engine.engine_name if engine else "Default",
		'Scan ID': f'[#{scan.id}]({url})'
	}

	if subscan:
		url = get_scan_url(scan.id, subscan.id)
		fields['Subscan ID'] = f'[#{subscan.id}]({url})'

	if duration:
		fields['Duration'] = duration

	fields['Host'] = host
	if tasks:
		fields['Tasks'] = tasks_h

	return fields


def get_task_title(task_name, scan_id=None, subscan_id=None):
	if scan_id:
		prefix = f'#{scan_id}'
		if subscan_id:
			prefix += f'-#{subscan_id}'
		return f'`{prefix}` - `{task_name}`'
	return f'`{task_name}` [unbound]'


def get_task_header_message(name, scan_history_id, subscan_id):
	msg = f'`{name}` [#{scan_history_id}'
	if subscan_id:
		msg += f'_#{subscan_id}]'
	msg += 'status'
	return msg


def get_task_cache_key(func_name, *args, **kwargs):
	args_str = '_'.join([str(arg) for arg in args])
	kwargs_str = '_'.join([f'{k}={v}' for k, v in kwargs.items() if k not in RENGINE_TASK_IGNORE_CACHE_KWARGS])
	return f'{func_name}__{args_str}__{kwargs_str}'


def get_output_file_name(scan_history_id, subscan_id, filename):
	title = f'#{scan_history_id}'
	if subscan_id:
		title += f'-{subscan_id}'
	title += f'_{filename}'
	return title


def get_traceback_path(task_name, results_dir, scan_history_id=None, subscan_id=None):
	path = results_dir
	if scan_history_id:
		path += f'/#{scan_history_id}'
		if subscan_id:
			path += f'-#{subscan_id}'
	path += f'-{task_name}.txt'
	return path


def fmt_traceback(exc):
	return '\n'.join(traceback.format_exception(None, exc, exc.__traceback__))


#--------------#
# CLI BUILDERS #
#--------------#

def _build_cmd(cmd, options, flags, sep=" "):
	for k,v in options.items():
		if not v:
			continue
		if v is True:
			cmd += f" {k}"
		else:
			cmd += f" {k}{sep}{v}"

	for flag in flags:
		if not flag:
			continue
		cmd += f" --{flag}"

	return cmd

def get_nmap_cmd(
		input_file,
		cmd=None,
		host=None,
		ports=None,
		output_file=None,
		script=None,
		script_args=None,
		max_rate=None,
		service_detection=True,
		flags=[]):
	if not cmd:
		cmd = 'nmap'

	if ports:
		if isinstance(ports, list):
			ports = ','.join(list(dict.fromkeys([str(p) for p in ports])))
		elif isinstance(ports, str):
			ports = ','.join(list(dict.fromkeys([p.strip() for p in ports.split(',')])))

	options = {
		"-sV": service_detection,
		"-p": ports,
		"--script": script,
		"--script-args": script_args,
		"--max-rate": max_rate,
		"-oX": output_file
	}
	cmd = _build_cmd(cmd, options, flags)

	is_nmap_valid = is_valid_nmap_command(cmd)
	if not is_nmap_valid:
		logger.error('Invalid nmap command or potentially dangerous: %s', cmd)
		return None

	if not input_file:
		cmd += f" {host}" if host else ""
	else:
		cmd += f" -iL {input_file}"

	return cmd


def xml2json(xml):
	with open(xml) as xml_file:
		xml_content = xml_file.read()
	return xmltodict.parse(xml_content)


def reverse_whois(lookup_keyword):
	domains = []
	'''
		This function will use viewdns to fetch reverse whois info
		Input: lookup keyword like email or registrar name
		Returns a list of domains as string.
	'''
	logger.info('Querying reverse whois for %s', lookup_keyword)
	url = f"https://viewdns.info:443/reversewhois/?q={lookup_keyword}"
	headers = {
		"Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
		"Sec-Ch-Ua-Mobile": "?0",
		"Sec-Ch-Ua-Platform": "\"Linux\"",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1",
		"Sec-Fetch-Dest": "document",
		"Referer": "https://viewdns.info/",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
	}
	response = requests.get(url, headers=headers)
	soup = BeautifulSoup(response.content, 'lxml')
	table = soup.find("table", {"border" : "1"})
	try:
		for row in table or []:
			dom = row.findAll('td')[0].getText()
			# created_on = row.findAll('td')[1].getText() TODO: add this in 3.0
			if dom == 'Domain Name':
				continue
			domains.append(dom)
	except Exception as e:
		logger.error('Error while fetching reverse whois info: %s', e)
	return domains


def get_domain_historical_ip_address(domain):
	ips = []
	'''
		This function will use viewdns to fetch historical IP address
		for a domain
	'''
	logger.info('Fetching historical IP address for domain %s', domain)
	url = f"https://viewdns.info/iphistory/?domain={domain}"
	headers = {
		"Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
		"Sec-Ch-Ua-Mobile": "?0",
		"Sec-Ch-Ua-Platform": "\"Linux\"",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1",
		"Sec-Fetch-Dest": "document",
		"Referer": "https://viewdns.info/",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
	}
	response = requests.get(url, headers=headers)
	soup = BeautifulSoup(response.content, 'lxml')
	table = soup.find("table", {"border" : "1"})					   
	for row in table or []:
		ip = row.findAll('td')[0].getText()
		location = row.findAll('td')[1].getText()
		owner = row.findAll('td')[2].getText()
		last_seen = row.findAll('td')[2].getText()
		if ip == 'IP Address':
			continue
		ips.append(
			{
				'ip': ip,
				'location': location,
				'owner': owner,
				'last_seen': last_seen,
			}
		)
	return ips


def get_open_ai_key():
	openai_key = OpenAiAPIKey.objects.all()
	return openai_key[0] if openai_key else None


def get_netlas_key():
	netlas_key = NetlasAPIKey.objects.all()
	return netlas_key[0] if netlas_key else None


def get_chaos_key():
	chaos_key = ChaosAPIKey.objects.all()
	return chaos_key[0] if chaos_key else None


def get_hackerone_key_username():
	"""
		Get the HackerOne API key username from the database.
		Returns: a tuple of the username and api key
	"""
	hackerone_key = HackerOneAPIKey.objects.all()
	return (hackerone_key[0].username, hackerone_key[0].key) if hackerone_key else None


def parse_llm_vulnerability_report(report):
	report = report.replace('**', '')
	data = {}
	sections = re.split(r'\n(?=(?:Description|Impact|Remediation|References):)', report.strip())

	for section in sections:
		if not section.strip():
			continue

		# Accept "Header:\ncontent", "Header:\n\ncontent", or "Header: content on same line"
		match = re.match(
			r'^(Description|Impact|Remediation|References):\s*(.*)',
			section.strip(),
			re.DOTALL,
		)
		if not match:
			continue

		section_title = match.group(1)
		content = match.group(2).strip()

		if section_title == 'Description':
			data['description'] = content
		elif section_title == 'Impact':
			data['impact'] = content
		elif section_title == 'Remediation':
			data['remediation'] = content
		elif section_title == 'References':
			data['references'] = [ref.strip() for ref in content.split('\n') if ref.strip()]

	return data


def create_scan_object(host_id, engine_id, initiated_by_id=None, hardware_profile_id=None):
	'''
	create task with pending status so that celery task will execute when
	threads are free
	Args:
		host_id: int: id of Domain model
		engine_id: int: id of EngineType model
		initiated_by_id: int : id of User model (Optional)
		hardware_profile_id: int: id of HardwareProfile model (Optional)
	'''
	# get current time
	current_scan_time = timezone.now()
	# fetch engine and domain object
	engine = EngineType.objects.get(pk=engine_id)
	domain = Domain.objects.get(pk=host_id)
	scan = ScanHistory()
	scan.scan_status = INITIATED_TASK
	scan.domain = domain
	scan.scan_type = engine
	scan.start_scan_date = current_scan_time
	if initiated_by_id:
		user = User.objects.get(pk=initiated_by_id)
		scan.initiated_by = user
	if hardware_profile_id:
		try:
			profile = HardwareProfile.objects.get(pk=hardware_profile_id)
			scan.hardware_profile = profile
		except HardwareProfile.DoesNotExist:
			pass
	scan.save()
	# save last scan date for domain model
	domain.start_scan_date = current_scan_time
	domain.save()
	return scan.id


def get_port_service_description(port):
	"""
		Retrieves the standard service name and description for a given port 
		number using whatportis and the builtin socket library as fallback.

		Args:
			port (int or str): The port number to look up. 
				Can be an integer or a string representation of an integer.

		Returns:
			dict: A dictionary containing the service name and description for the port number.
	"""
	logger.info('Fetching port service name and description for port %s', port)
	try:
		port = int(port)
		whatportis_result = whatportis.get_ports(str(port))
		
		if whatportis_result and whatportis_result[0].name:
			return {
				"service_name": whatportis_result[0].name,
				"description": whatportis_result[0].description
			}
		else:
			try:
				service = socket.getservbyport(port)
				return {
					"service_name": service,
					"description": "" # Keep description blank when using socket
				}
			except OSError:
				# If both whatportis and socket fail
				return {
					"service_name": "",
					"description": ""
				}
	except:
		# port is not a valid int or any other exception
		return {
			"service_name": "",
			"description": ""
		}


def update_or_create_port(port_number, service_name=None, description=None):
	"""
		Updates or creates a new Port object with the provided information to 
		avoid storing duplicate entries when service or description information is updated.

		Args:
			port_number (int): The port number to update or create.
			service_name (str, optional): The name of the service associated with the port.
			description (str, optional): A description of the service associated with the port.

		Returns:
			Tuple: A tuple containing the Port object and a boolean indicating whether the object was created.
	"""
	created = False
	try:
		port = Port.objects.get(number=port_number)
		
		# avoid updating None values in service and description if they already exist
		if service_name is not None and port.service_name != service_name:
			port.service_name = service_name
		if description is not None and port.description != description:
			port.description = description
		port.save()	
	except Port.DoesNotExist:
		# for cases if the port doesn't exist, create a new one
		port = Port.objects.create(
			number=port_number,
			service_name=service_name,
			description=description
		)
		created = True
	finally:
		return port, created
	

def exclude_urls_by_patterns(exclude_paths, urls):
	"""
		Filter out URLs based on a list of exclusion patterns provided from user
		
		Args:
			exclude_patterns (list of str): A list of patterns to exclude. 
			These can be plain path or regex.
			urls (list of str): A list of URLs to filter from.
			
		Returns:
			list of str: A new list containing URLs that don't match any exclusion pattern.
	"""
	logger.info('Filtering %d URLs by %d exclusion patterns', len(urls), len(exclude_paths))
	if not exclude_paths:
		# if no exclude paths are passed and is empty list return all urls as it is
		return urls
	
	compiled_patterns = []
	for path in exclude_paths:
		# treat each path as either regex or plain path
		try:
			raw_pattern = r"{}".format(path)
			compiled_patterns.append(re.compile(raw_pattern))
		except re.error:
			compiled_patterns.append(path)

	filtered_urls = []
	for url in urls:
		exclude = False
		for pattern in compiled_patterns:
			if isinstance(pattern, re.Pattern):
				if pattern.search(url):
					exclude = True
					break
			else:
				if pattern in url: #if the word matches anywhere in url exclude
					exclude = True
					break
		
		# if none conditions matches then add the url to filtered urls
		if not exclude:
			filtered_urls.append(url)

	return filtered_urls
	

def get_domain_info_from_db(target):
	"""
		Retrieves the Domain object from the database using the target domain name.

		Args:
			target (str): The domain name to search for.

		Returns:
			Domain: The Domain object if found, otherwise None.
	"""
	try:
		domain = Domain.objects.get(name=target)
		if not domain.insert_date:
			domain.insert_date = timezone.now()
			domain.save()
		return extract_domain_info(domain)
	except Domain.DoesNotExist:
		return None
	
def extract_domain_info(domain):
	"""
		Extract domain info from the domain_info_db.
		Args:
			domain: Domain object

		Returns:
			DottedDict: The domain info object.
	"""
	if not domain:
		return DottedDict()
	
	domain_name = domain.name
	domain_info_db = domain.domain_info
	
	try:
		domain_info = DottedDict({
			'dnssec': domain_info_db.dnssec,
			'created': domain_info_db.created,
			'updated': domain_info_db.updated,
			'expires': domain_info_db.expires,
			'geolocation_iso': domain_info_db.geolocation_iso,
			'status': [status.name for status in domain_info_db.status.all()],
			'whois_server': domain_info_db.whois_server,
			'ns_records': [ns.name for ns in domain_info_db.name_servers.all()],
		})

		# Extract registrar info
		registrar = domain_info_db.registrar
		if registrar:
			domain_info.update({
				'registrar_name': registrar.name,
				'registrar_phone': registrar.phone,
				'registrar_email': registrar.email,
				'registrar_url': registrar.url,
			})

		# Extract registration info (registrant, admin, tech)
		for role in ['registrant', 'admin', 'tech']:
			registration = getattr(domain_info_db, role)
			if registration:
				domain_info.update({
					f'{role}_{key}': getattr(registration, key)
					for key in ['name', 'id_str', 'organization', 'city', 'state', 'zip_code', 
								'country', 'phone', 'fax', 'email', 'address']
				})

		# Extract DNS records
		dns_records = domain_info_db.dns_records.all()
		for record_type in ['a', 'txt', 'mx']:
			domain_info[f'{record_type}_records'] = [
				record.name for record in dns_records if record.type == record_type
			]

		# Extract related domains and TLDs
		domain_info.update({
			'related_tlds': [domain.name for domain in domain_info_db.related_tlds.all()],
			'related_domains': [domain.name for domain in domain_info_db.related_domains.all()],
		})

		# Extract historical IPs
		domain_info['historical_ips'] = [
			{
				'ip': ip.ip,
				'owner': ip.owner,
				'location': ip.location,
				'last_seen': ip.last_seen
			}
			for ip in domain_info_db.historical_ips.all()
		]

		domain_info['target'] = domain_name
	except Exception as e:
		logger.error('Error while extracting domain info: %s', e)
		domain_info = DottedDict()

	return domain_info


def format_whois_response(domain_info):
	"""
		Format the domain info for the whois response.
		Args:
			domain_info (DottedDict): The domain info object.
		Returns:
			dict: The formatted whois response.	
	"""
	return {
		'status': True,
		'target': domain_info.get('target'),
		'dnssec': domain_info.get('dnssec'),
		'created': domain_info.get('created'),
		'updated': domain_info.get('updated'),
		'expires': domain_info.get('expires'),
		'geolocation_iso': domain_info.get('registrant_country'),
		'domain_statuses': domain_info.get('status'),
		'whois_server': domain_info.get('whois_server'),
		'dns': {
			'a': domain_info.get('a_records'),
			'mx': domain_info.get('mx_records'),
			'txt': domain_info.get('txt_records'),
		},
		'registrar': {
			'name': domain_info.get('registrar_name'),
			'phone': domain_info.get('registrar_phone'),
			'email': domain_info.get('registrar_email'),
			'url': domain_info.get('registrar_url'),
		},
		'registrant': {
			'name': domain_info.get('registrant_name'),
			'id': domain_info.get('registrant_id'),
			'organization': domain_info.get('registrant_organization'),
			'address': domain_info.get('registrant_address'),
			'city': domain_info.get('registrant_city'),
			'state': domain_info.get('registrant_state'),
			'zipcode': domain_info.get('registrant_zip_code'),
			'country': domain_info.get('registrant_country'),
			'phone': domain_info.get('registrant_phone'),
			'fax': domain_info.get('registrant_fax'),
			'email': domain_info.get('registrant_email'),
		},
		'admin': {
			'name': domain_info.get('admin_name'),
			'id': domain_info.get('admin_id'),
			'organization': domain_info.get('admin_organization'),
			'address':domain_info.get('admin_address'),
			'city': domain_info.get('admin_city'),
			'state': domain_info.get('admin_state'),
			'zipcode': domain_info.get('admin_zip_code'),
			'country': domain_info.get('admin_country'),
			'phone': domain_info.get('admin_phone'),
			'fax': domain_info.get('admin_fax'),
			'email': domain_info.get('admin_email'),
		},
		'technical_contact': {
			'name': domain_info.get('tech_name'),
			'id': domain_info.get('tech_id'),
			'organization': domain_info.get('tech_organization'),
			'address': domain_info.get('tech_address'),
			'city': domain_info.get('tech_city'),
			'state': domain_info.get('tech_state'),
			'zipcode': domain_info.get('tech_zip_code'),
			'country': domain_info.get('tech_country'),
			'phone': domain_info.get('tech_phone'),
			'fax': domain_info.get('tech_fax'),
			'email': domain_info.get('tech_email'),
		},
		'nameservers': domain_info.get('ns_records'),
		'related_domains': domain_info.get('related_domains'),
		'related_tlds': domain_info.get('related_tlds'),
		'historical_ips': domain_info.get('historical_ips'),
	}


def parse_whois_data(domain_info, whois_data):
	"""Parse WHOIS data and update domain_info."""
	whois = whois_data.get('whois', {})
	dns = whois_data.get('dns', {})

	# Parse basic domain information
	domain_info.update({
		'created': whois.get('created_date', None),
		'expires': whois.get('expiration_date', None),
		'updated': whois.get('updated_date', None),
		'whois_server': whois.get('whois_server', None),
		'dnssec': bool(whois.get('dnssec', False)),
		'status': whois.get('status', []),
	})

	# Parse registrar information
	parse_registrar_info(domain_info, whois.get('registrar', {}))

	# Parse registration information
	for role in ['registrant', 'administrative', 'technical']:
		parse_registration_info(domain_info, whois.get(role, {}), role)

	# Parse DNS records
	parse_dns_records(domain_info, dns)

	# Parse name servers
	domain_info.ns_records = dns.get('ns', [])


def parse_registrar_info(domain_info, registrar):
	"""Parse registrar information."""
	domain_info.update({
		'registrar_name': registrar.get('name', None),
		'registrar_email': registrar.get('email', None),
		'registrar_phone': registrar.get('phone', None),
		'registrar_url': registrar.get('url', None),
	})

def parse_registration_info(domain_info, registration, role):
	"""Parse registration information for registrant, admin, and tech contacts."""
	role_prefix = role if role != 'administrative' else 'admin'
	domain_info.update({
		f'{role_prefix}_{key}': value
		for key, value in registration.items()
		if key in ['name', 'id', 'organization', 'street', 'city', 'province', 'postal_code', 'country', 'phone', 'fax']
	})

	# Handle email separately to apply regex
	email = registration.get('email')
	if email:
		email_match = EMAIL_REGEX.search(str(email))
		domain_info[f'{role_prefix}_email'] = email_match.group(0) if email_match else None

def parse_dns_records(domain_info, dns):
	"""Parse DNS records."""
	domain_info.update({
		'mx_records': dns.get('mx', []),
		'txt_records': dns.get('txt', []),
		'a_records': dns.get('a', []),
		'ns_records': dns.get('ns', []),
	})


def save_domain_info_to_db(target, domain_info):
	"""Save domain info to the database."""
	if Domain.objects.filter(name=target).exists():
		domain, _ = Domain.objects.get_or_create(name=target)
		
		# Create or update DomainInfo
		domain_info_obj, created = DomainInfo.objects.get_or_create(domain=domain)
		
		# Update basic domain information
		domain_info_obj.dnssec = domain_info.get('dnssec', False)
		domain_info_obj.created = domain_info.get('created')
		domain_info_obj.updated = domain_info.get('updated')
		domain_info_obj.expires = domain_info.get('expires')
		domain_info_obj.whois_server = domain_info.get('whois_server')
		domain_info_obj.geolocation_iso = domain_info.get('registrant_country')

		# Save or update Registrar
		registrar, _ = Registrar.objects.get_or_create(
			name=domain_info.get('registrar_name', ''),
			defaults={
				'email': domain_info.get('registrar_email'),
				'phone': domain_info.get('registrar_phone'),
				'url': domain_info.get('registrar_url'),
			}
		)
		domain_info_obj.registrar = registrar

		# Save or update Registrations (registrant, admin, tech)
		for role in ['registrant', 'admin', 'tech']:
			registration, _ = DomainRegistration.objects.get_or_create(
				name=domain_info.get(f'{role}_name', ''),
				defaults={
					'organization': domain_info.get(f'{role}_organization'),
					'address': domain_info.get(f'{role}_address'),
					'city': domain_info.get(f'{role}_city'),
					'state': domain_info.get(f'{role}_state'),
					'zip_code': domain_info.get(f'{role}_zip_code'),
					'country': domain_info.get(f'{role}_country'),
					'email': domain_info.get(f'{role}_email'),
					'phone': domain_info.get(f'{role}_phone'),
					'fax': domain_info.get(f'{role}_fax'),
					'id_str': domain_info.get(f'{role}_id'),
				}
			)
			setattr(domain_info_obj, role, registration)

		# Save domain statuses
		domain_info_obj.status.clear()
		for status in domain_info.get('status', []):
			status_obj, _ = WhoisStatus.objects.get_or_create(name=status)
			domain_info_obj.status.add(status_obj)

		# Save name servers
		domain_info_obj.name_servers.clear()
		for ns in domain_info.get('ns_records', []):
			ns_obj, _ = NameServer.objects.get_or_create(name=ns)
			domain_info_obj.name_servers.add(ns_obj)

		# Save DNS records
		domain_info_obj.dns_records.clear()
		for record_type in ['a', 'mx', 'txt']:
			for record in domain_info.get(f'{record_type}_records', []):
				dns_record, _ = DNSRecord.objects.get_or_create(
					name=record,
					type=record_type
				)
				domain_info_obj.dns_records.add(dns_record)

		# Save related domains and TLDs
		domain_info_obj.related_domains.clear()
		for related_domain in domain_info.get('related_domains', []):
			related_domain_obj, _ = RelatedDomain.objects.get_or_create(name=related_domain)
			domain_info_obj.related_domains.add(related_domain_obj)

		domain_info_obj.related_tlds.clear()
		for related_tld in domain_info.get('related_tlds', []):
			related_tld_obj, _ = RelatedDomain.objects.get_or_create(name=related_tld)
			domain_info_obj.related_tlds.add(related_tld_obj)

		# Save historical IPs
		domain_info_obj.historical_ips.clear()
		for ip_info in domain_info.get('historical_ips', []):
			historical_ip, _ = HistoricalIP.objects.get_or_create(
				ip=ip_info['ip'],
				defaults={
					'owner': ip_info.get('owner'),
					'location': ip_info.get('location'),
					'last_seen': ip_info.get('last_seen'),
				}
			)
			domain_info_obj.historical_ips.add(historical_ip)

		# Save the DomainInfo object
		domain_info_obj.save()

		# Update the Domain object with the new DomainInfo
		domain.domain_info = domain_info_obj
		domain.save()

		return domain_info_obj


def create_inappnotification(
		title,
		description,
		notification_type=SYSTEM_LEVEL_NOTIFICATION,
		project_slug=None,
		icon="mdi-bell",
		is_read=False,
		status='info',
		redirect_link=None,
		open_in_new_tab=False
):
	"""
		This function will create an inapp notification
		Inapp Notification not to be confused with Notification model 
		that is used for sending alerts on telegram, slack etc.
		Inapp notification is used to show notification on the web app

		Args: 
			title: str: Title of the notification
			description: str: Description of the notification
			notification_type: str: Type of the notification, it can be either
				SYSTEM_LEVEL_NOTIFICATION or PROJECT_LEVEL_NOTIFICATION
			project_slug: str: Slug of the project, if notification is PROJECT_LEVEL_NOTIFICATION
			icon: str: Icon of the notification, only use mdi icons
			is_read: bool: Whether the notification is read or not, default is False
			status: str: Status of the notification (success, info, warning, error), default is info
			redirect_link: str: Link to redirect when notification is clicked
			open_in_new_tab: bool: Whether to open the redirect link in a new tab, default is False

		Returns:
			ValueError: if error
			InAppNotification: InAppNotification object if successful
	"""
	logger.info('Creating InApp Notification with title: %s', title)
	if notification_type not in [SYSTEM_LEVEL_NOTIFICATION, PROJECT_LEVEL_NOTIFICATION]:
		raise ValueError("Invalid notification type")
	
	if status not in [choice[0] for choice in NOTIFICATION_STATUS_TYPES]:
		raise ValueError("Invalid notification status")
	
	project = None
	if notification_type == PROJECT_LEVEL_NOTIFICATION:
		if not project_slug:
			raise ValueError("Project slug is required for project level notification")
		try:
			project = Project.objects.get(slug=project_slug)
		except Project.DoesNotExist as e:
			raise ValueError(f"No project exists: {e}")
		
	notification = InAppNotification(
		title=title,
		description=description,
		notification_type=notification_type,
		project=project,
		icon=icon,
		is_read=is_read,
		status=status,
		redirect_link=redirect_link,
		open_in_new_tab=open_in_new_tab
	)
	notification.save()

	# Dispatch a push notification to all registered mobile devices
	send_mobile_push_notification(
		title=title,
		body=description,
		data={'notification_id': notification.id, 'status': status}
	)

	return notification


def send_mobile_push_notification(title, body, data=None):
	"""
		Send a push notification to all active registered mobile devices
		via the Expo Push Notification Service.

		This function is intentionally fire-and-forget: errors are logged
		but never re-raised so that a push failure never breaks normal
		application flow.

		Args:
			title (str): The notification title shown on the device.
			body (str): The notification body/description text.
			data (dict, optional): Extra JSON payload passed to the app
				when the user taps the notification.
	"""
	try:
		# Import here to avoid circular imports; MobilePushToken lives in dashboard.models
		from dashboard.models import MobilePushToken

		# Collect all active Expo push tokens
		tokens = list(
			MobilePushToken.objects
			.filter(is_active=True)
			.values_list('token', flat=True)
		)

		if not tokens:
			# No registered devices — nothing to do
			return

		# Build one message per token (Expo supports batching up to 100)
		messages = [
			{
				'to': token,
				'title': title,
				'body': body,
				'data': data or {},
				'sound': 'default',
				'priority': 'high',
			}
			for token in tokens
		]

		# Expo Push API endpoint — no auth required for Expo push tokens
		expo_push_url = 'https://exp.host/--/api/v2/push/send'

		response = requests.post(
			expo_push_url,
			json=messages,
			headers={
				'Accept': 'application/json',
				'Accept-Encoding': 'gzip, deflate',
				'Content-Type': 'application/json',
			},
			timeout=10,
		)

		result = response.json()
		# Log any per-token errors returned by Expo
		for ticket in result.get('data', []):
			if ticket.get('status') == 'error':
				logger.warning(
					'[PushNotification] Expo push error: %s — %s',
					ticket.get('message'),
					ticket.get('details'),
				)

	except Exception as e:
		# Never let a push failure crash the calling code
		logger.error('[PushNotification] Failed to dispatch push notifications: %s', e)

def get_ip_info(ip_address):
	is_ipv4 = bool(validators.ipv4(ip_address))
	is_ipv6 = bool(validators.ipv6(ip_address))
	ip_data = None
	if is_ipv4:
		ip_data = ipaddress.IPv4Address(ip_address)
	elif is_ipv6:
		ip_data = ipaddress.IPv6Address(ip_address)
	else:
		return None
	return ip_data

def get_ips_from_cidr_range(target):
	try:
		return [str(ip) for ip in ipaddress.IPv4Network(target, False)]
	except Exception as e:
		logger.error('%s is not a valid CIDR range. Skipping.', target)


def is_valid_nmap_command(cmd):
	"""
		Check if the nmap command is valid or not
		This is to check the nmap command before executing it so as to avoid
		command injection attacks
		Args:
			cmd: str: nmap command
		Returns:
			bool: True if valid, False otherwise
	"""
	try:
		parts = shlex.split(cmd)
	except ValueError as e:
		logger.error('Nmap command shlex split failed: %s', e)
		return False

	if not parts:
		logger.error('Nmap command is empty after split')
		return False

	if not (parts[0] == 'nmap' or parts[0].endswith('/nmap') or parts[0].endswith('\\nmap') or parts[0].endswith('\\nmap.exe')):
		logger.error('Nmap command does not start with nmap: %s', parts[0])
		return False

	# Block dangerous shell characters (potentially used with shell=True)
	dangerous_chars = {';', '&', '|', '>', '<', '`', '$', '(', ')'}
	if any(char in cmd for char in dangerous_chars):
		logger.error('Nmap command contains dangerous characters: %s', cmd)
		return False

	for part in parts[1:]: # ignoring nmap the first part of command
		if part.startswith('-') or part.startswith('--'):
			continue

		# check for valid characters, . - etc are allowed in valid nmap command
		# adding : and = to support script args, port specifications and Windows paths
		# adding [] for IPv6, @ for script-args, +!*# for general nmap flexibility
		# adding space to support quoted arguments from shlex.split
		if all(c.isalnum() or c in '.,/-_:=\\ []@+!*#' for c in part):
			continue
		logger.error('Nmap command part rejected by whitelist: %s', part)
		return False
		
	return True


#------------------------------#
# Vulnerability Parsing Utils  #
#------------------------------#

def clean_semgrep_check_id(check_id):
	"""Cleans and normalizes Semgrep check IDs by removing rule path prefixes
	and deduplicating repeating suffixes.

	Args:
		check_id (str): The raw check ID from Semgrep results.

	Returns:
		str: The cleaned check ID.
	"""
	if not check_id:
		return ""
	
	# Split by dots to inspect path components
	parts = check_id.split('.')
	
	# Common prefixes or folders to discard from check IDs
	prefixes_to_strip = {
		'usr', 'src', 'github', 'semgrep_rules', 'rules', 'app', 'p',
		'semgrep_vulnerability_temp', 'semgrep_secret_temp', 'temp'
	}
	
	# Filter out initial path elements that match our strip list
	start_idx = 0
	while start_idx < len(parts) and parts[start_idx].lower() in prefixes_to_strip:
		start_idx += 1
		
	clean_parts = parts[start_idx:]
	
	if not clean_parts:
		return check_id
		
	# Deduplicate repeating suffix (e.g. ['react-dangerouslysetinnerhtml', 'react-dangerouslysetinnerhtml'])
	if len(clean_parts) >= 2 and clean_parts[-1].lower() == clean_parts[-2].lower():
		clean_parts.pop()
		
	return '.'.join(clean_parts)


def parse_semgrep_result(result):
	"""Parses a single Semgrep match into reNgine vulnerability format.

	Args:
		result (dict): Semgrep finding match dictionary.

	Returns:
		dict: Vulnerability data dictionary ready for saving.
	"""
	check_id = result.get('check_id', '')
	cleaned_check_id = clean_semgrep_check_id(check_id)
	return {
		'name': f"Semgrep: {cleaned_check_id}",
		'description': result.get('extra', {}).get('message', ''),
		'severity': SEMGREP_SEVERITY_MAP.get(result.get('extra', {}).get('severity', 'INFO'), 0),
		'http_url': result.get('path', ''),
		'type': 'SAST',
		'source': 'Semgrep',
	}


def parse_retire_result(result):
	"""Parses a single Retire.js vulnerability into reNgine vulnerability format.

	Args:
		result (dict): Retire.js finding dictionary.

	Returns:
		dict: Vulnerability data dictionary ready for saving.
	"""
	return {
		'name': f"Retire.js: {result.get('component')} ({result.get('version')})",
		'description': result.get('info', ''),
		'severity': 2, # Default medium for library vulnerabilities
		'http_url': result.get('file', ''),
		'type': 'SCA',
		'source': 'Retire.js',
	}


def parse_inql_results(directory_path):
	"""
	Parses InQL output directory for discovered GraphQL endpoints.
	InQL creates a directory structure like:
	target_domain/
		queries/
		schema.json
		...
	"""
	endpoints = []
	if not os.path.exists(directory_path):
		return endpoints

	# InQL often identifies the GraphQL endpoint by its structure
	# We look for files or directories that indicate a successful discovery
	for root, dirs, files in os.walk(directory_path):
		for file in files:
			if file == 'schema.json' or file.endswith('.graphql'):
				# The parent directory or the root might be the endpoint path
				# This is a heuristic. In reNgine, we often know the base URL.
				# We return the "fact" that GraphQL was found.
				endpoints.append({
					'type': 'GraphQL',
					'discovered_file': os.path.join(root, file)
				})
	return endpoints


def extract_params_from_url(url):
	"""
	Extracts query parameters from a URL and returns a list of dicts.
	"""
	params = []
	try:
		parsed = urlparse(url)
		query_dict = parse_qs(parsed.query)
		for key, values in query_dict.items():
			for value in values:
				params.append({
					'name': key,
					'value': value,
					'type': 'URL Query'
				})
	except Exception as e:
		logger.error("Error extracting parameters from URL %s: %s", url, e)
	return params


_JWT_PARAM_RE = re.compile(
	r'\b(jwt|bearer|authorization|access_token|refresh_token|id_token|auth_token)\b',
	re.IGNORECASE,
)
_JWT_SECRET_TYPE_RE = re.compile(
	r'jwt|json[\s_-]?web[\s_-]?token|bearer[\s_-]?token',
	re.IGNORECASE,
)

# Paths probed to detect a GraphQL endpoint before running InQL / graphql-cop.
_GRAPHQL_PROBE_PATHS = [
	'/graphql',
	'/api/graphql',
	'/__graphql',
	'/graphiql',
	'/api/graphiql',
	'/v1/graphql',
]

# Paths probed to detect an OpenAPI spec — mirrors openapi_discoverer._SPEC_PROBE_PATHS
# so has_openapi_spec() and discover() cover the same set of paths.
_OPENAPI_PROBE_PATHS = [
	'/openapi.json',
	'/openapi.yaml',
	'/swagger.json',
	'/swagger.yaml',
	'/api-docs',
	'/api-docs.json',
	'/api/docs',
	'/api/openapi.json',
	'/api/swagger.json',
	'/v1/api-docs',
	'/v2/api-docs',
	'/v3/api-docs',
	'/docs/openapi.json',
	'/.well-known/openapi.json',
]

_PROBE_HEADERS = {'User-Agent': 'r3ngine-probe/1.0'}
_PROBE_TIMEOUT = 5  # seconds per HEAD request


def has_graphql_endpoint(scan_id, url, proxy=None):
	"""Return True if a GraphQL endpoint has been detected for this scan.

	Checks existing EndPoint records first (zero network cost). Falls back to
	HEAD-probing common GraphQL paths if the DB has no evidence.
	"""
	logger.info('[GATE] has_graphql_endpoint: DB query — scan_id=%s url=%s', scan_id, url)
	db_match = EndPoint.objects.filter(
		scan_history_id=scan_id,
		http_url__iregex=r'/graphi?ql',
	).exists()
	if db_match:
		logger.info('[GATE] has_graphql_endpoint: DB hit — GraphQL endpoint already recorded for scan %s', scan_id)
		return True
	logger.info('[GATE] has_graphql_endpoint: DB miss — probing %d paths for %s (timeout=%ds each)', len(_GRAPHQL_PROBE_PATHS), url, _PROBE_TIMEOUT)

	from urllib.parse import urlparse as _urlparse
	parsed = _urlparse(url)
	base = '%s://%s' % (parsed.scheme, parsed.netloc)
	proxies = {'http': proxy, 'https': proxy} if proxy else None

	for path in _GRAPHQL_PROBE_PATHS:
		probe_url = base + path
		logger.info('[GATE] has_graphql_endpoint: probing %s', probe_url)
		try:
			resp = requests.head(
				probe_url,
				timeout=_PROBE_TIMEOUT,
				proxies=proxies,
				allow_redirects=True,
				headers=_PROBE_HEADERS,
			)
			logger.info('[GATE] has_graphql_endpoint: %s → HTTP %d', probe_url, resp.status_code)
			if resp.status_code not in (400, 404, 410):
				logger.info('[GATE] GraphQL endpoint candidate at %s (HTTP %d)', probe_url, resp.status_code)
				return True
		except requests.RequestException as e:
			logger.info('[GATE] has_graphql_endpoint: %s → error (%s)', probe_url, e)
			continue

	logger.info('[GATE] has_graphql_endpoint: no GraphQL endpoint found for %s', url)
	return False


def has_openapi_spec(url, proxy=None):
	"""Return True if an OpenAPI/Swagger spec is reachable at the given base URL.

	Uses HEAD requests only (fast existence check). For 200 responses the
	Content-Type header is inspected; if ambiguous a minimal GET confirms the
	body contains OpenAPI/Swagger keys. Using HEAD avoids downloading full spec
	bodies for probe paths that return 404 or connection-refused.
	"""
	from urllib.parse import urlparse as _urlparse
	parsed = _urlparse(url)
	base = '%s://%s' % (parsed.scheme, parsed.netloc)
	proxies = {'http': proxy, 'https': proxy} if proxy else None

	logger.info('[GATE] has_openapi_spec: probing %d paths for %s (timeout=%ds each)', len(_OPENAPI_PROBE_PATHS), url, _PROBE_TIMEOUT)
	for path in _OPENAPI_PROBE_PATHS:
		probe_url = base + path
		logger.info('[GATE] has_openapi_spec: probing %s', probe_url)
		try:
			resp = requests.head(
				probe_url,
				timeout=_PROBE_TIMEOUT,
				proxies=proxies,
				allow_redirects=True,
				headers=_PROBE_HEADERS,
			)
			logger.info('[GATE] has_openapi_spec: %s → HTTP %d', probe_url, resp.status_code)
			if resp.status_code != 200:
				continue
			# HEAD returned 200 — accept json/yaml content types directly
			ct = resp.headers.get('Content-Type', '')
			if 'json' in ct or 'yaml' in ct:
				logger.info('[GATE] OpenAPI spec found at %s (Content-Type: %s)', probe_url, ct)
				return True
			# For ambiguous content types confirm with a lightweight GET
			logger.info('[GATE] has_openapi_spec: ambiguous Content-Type %r — issuing GET %s', ct, probe_url)
			get_resp = requests.get(
				probe_url,
				timeout=_PROBE_TIMEOUT * 2,
				proxies=proxies,
				allow_redirects=True,
				headers=_PROBE_HEADERS,
			)
			if get_resp.status_code != 200:
				continue
			try:
				data = get_resp.json()
				if isinstance(data, dict) and ('paths' in data or 'openapi' in data or 'swagger' in data):
					logger.info('[GATE] OpenAPI spec confirmed at %s', probe_url)
					return True
			except Exception:
				continue
		except requests.RequestException as e:
			logger.info('[GATE] has_openapi_spec: %s → error (%s)', probe_url, e)
			continue

	logger.info('[GATE] has_openapi_spec: no OpenAPI spec found for %s', url)
	return False


def has_jwt_tokens(scan_id, subdomain=None):
	"""Return True if JWT tokens have been detected in the given scan.

	Checks Parameter records with is_auth_related=True whose name matches
	JWT patterns, and SecretLeak records whose secret_type indicates a JWT
	or Bearer token. When subdomain is provided the Parameter check is
	scoped to that subdomain; SecretLeak always covers the full scan so
	that scan-wide secret discoveries gate per-subdomain runs correctly.
	"""
	subdomain_label = subdomain.name if subdomain is not None else 'scan-wide'
	logger.info('[GATE] has_jwt_tokens: querying auth parameters — scan_id=%s scope=%s', scan_id, subdomain_label)
	param_qs = Parameter.objects.filter(
		endpoint__scan_history_id=scan_id,
		is_auth_related=True,
	)
	if subdomain is not None:
		param_qs = param_qs.filter(endpoint__subdomain=subdomain)
	for name in param_qs.values_list('name', flat=True):
		if _JWT_PARAM_RE.search(name):
			logger.info('[GATE] has_jwt_tokens: JWT param match on %r — scan_id=%s scope=%s', name, scan_id, subdomain_label)
			return True

	logger.info('[GATE] has_jwt_tokens: no JWT params found, querying SecretLeak — scan_id=%s', scan_id)
	for secret_type in SecretLeak.objects.filter(scan_history_id=scan_id).values_list('secret_type', flat=True):
		if _JWT_SECRET_TYPE_RE.search(secret_type):
			logger.info('[GATE] has_jwt_tokens: JWT secret match on %r — scan_id=%s', secret_type, scan_id)
			return True

	logger.info('[GATE] has_jwt_tokens: no JWT tokens found — scan_id=%s scope=%s', scan_id, subdomain_label)
	return False
