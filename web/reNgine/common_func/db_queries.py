"""Read/write helpers over Subdomain, EndPoint, InterestingLookupModel and Port rows.

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import glob
import os
import socket
import logging

import whatportis
from urllib.parse import urlparse
from django.db.models import Q

from reNgine.settings import RENGINE_HOME
from reNgine.utilities import is_valid_url
from scanEngine.models import InterestingLookupModel
from startScan.models import EndPoint, Port, ScanHistory, Subdomain
from targetApp.models import Domain, normalize_manual_subdomains

logger = logging.getLogger(__name__)


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
	# Skip unfiltered crawl dumps when scoped to a single subdomain — those files
	# contain hosts from the whole scan and would break singular / subscan scope.
	file_urls_before = len(all_urls)
	subdomain_id = ctx.get('subdomain_id')
	subdomain_name = (ctx.get('subdomain_name') or '').lower().rstrip('.')
	if results_dir and os.path.isdir(results_dir) and not subdomain_id:
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
	elif results_dir and os.path.isdir(results_dir) and subdomain_name:
		candidates = [os.path.join(results_dir, 'fetch_url.txt')]
		candidates += glob.glob(os.path.join(results_dir, 'urls_*.txt'))
		for filepath in candidates:
			if not os.path.isfile(filepath):
				continue
			try:
				with open(filepath, 'r', errors='replace') as fh:
					for raw_line in fh:
						url = raw_line.strip()
						if not url or not is_valid_url(url):
							continue
						host = (urlparse(url).hostname or '').lower().rstrip('.')
						if host == subdomain_name or host.endswith('.' + subdomain_name):
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


def merge_imported_subdomains(domain, imported_subdomains):
	"""Merge target-persisted manual subdomains with imported ones, deduplicating."""
	merged = []
	seen = set()
	for name in domain.get_manual_subdomains() + normalize_manual_subdomains(imported_subdomains):
		if name in seen:
			continue
		seen.add(name)
		merged.append(name)
	return merged


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
	# Not in a `finally`: that swallowed every error other than DoesNotExist,
	# and when the create() itself failed `port` was unbound, so the caller saw
	# an UnboundLocalError instead of the real database error.
	return port, created
