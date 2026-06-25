import logging
import os
from urllib.parse import urlparse

import validators
from django.db.models import Count
from django.utils import timezone
from metafinder.extractor import extract_metadata_from_google_search

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.utils.task import run_command, save_subdomain
from startScan.models import (
    EndPoint, IpAddress, ScanHistory, ScanActivity, Subdomain,
    MetaFinderDocument, SecretLeak,
)
from targetApp.models import Domain

logger = logging.getLogger(__name__)


def remove_duplicate_endpoints(
		scan_history_id,
		domain_id,
		subdomain_id=None,
		filter_ids=[],
		filter_status=[200, 301, 404],
		duplicate_removal_fields=ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS
	):
	"""Remove duplicate endpoints.

	Check for implicit redirections by comparing endpoints:
	- [x] `content_length` similarities indicating redirections
	- [x] `page_title` (check for same page title)
	- [ ] Sign-in / login page (check for endpoints with the same words)

	Args:
		scan_history_id: ScanHistory id.
		domain_id (int): Domain id.
		subdomain_id (int, optional): Subdomain id.
		filter_ids (list): List of endpoint ids to filter on.
		filter_status (list): List of HTTP status codes to filter on.
		duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates
	"""
	logger.info(f'Removing duplicate endpoints based on {duplicate_removal_fields}')
	endpoints = (
		EndPoint.objects
		.filter(scan_history__id=scan_history_id)
		.filter(target_domain__id=domain_id)
	)
	if filter_status:
		endpoints = endpoints.filter(http_status__in=filter_status)

	if subdomain_id:
		endpoints = endpoints.filter(subdomain__id=subdomain_id)

	if filter_ids:
		endpoints = endpoints.filter(id__in=filter_ids)

	for field_name in duplicate_removal_fields:
		cl_query = (
			endpoints
			.values_list(field_name)
			.annotate(mc=Count(field_name))
			.order_by('-mc')
		)
		for (field_value, count) in cl_query:
			if count > DELETE_DUPLICATES_THRESHOLD:
				eps_to_delete = (
					endpoints
					.filter(**{field_name: field_value})
					.order_by('discovered_date')
					.all()[1:]
				)
				msg = f'Deleting {len(eps_to_delete)} endpoints [reason: same {field_name} {field_value}]'
				for ep in eps_to_delete:
					url = urlparse(ep.http_url)
					if url.path in ['', '/', '/login']: # try do not delete the original page that other pages redirect to
						continue
					msg += f'\n\t {ep.http_url} [{ep.http_status}] [{field_name}={field_value}]'
					ep.delete()
				logger.warning(msg)


def process_httpx_response(line, ctx={}, is_ran_from_subdomain_scan=False):
	"""Process a single line of httpx output and save to database."""
	if not line or not isinstance(line, dict):
		return None, False

	# No response from endpoint
	if line.get('failed', False):
		return None, False

	# Parse httpx output
	http_status = line.get('status_code')
	http_url, is_redirect = extract_httpx_url(line)
	content_length = line.get('content_length', 0)
	page_title = line.get('title')
	webserver = line.get('webserver')
	rt = line.get('time')
	content_type = line.get('content_type', '')

	response_time = -1
	if rt:
		response_time = float(''.join(ch for ch in rt if not ch.isalpha()))
		if rt[-2:] == 'ms':
			response_time = response_time / 1000

	# Create Subdomain object in DB
	subdomain_name = get_subdomain_from_url(http_url)
	subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)

	if not subdomain:
		return None, False

	# Save default HTTP URL to endpoint object in DB
	endpoint, created = save_endpoint(
		http_url,
		crawl=False,
		ctx=ctx,
		subdomain=subdomain,
		is_default=is_ran_from_subdomain_scan
	)
	if not endpoint:
		return None, False

	endpoint.http_status = http_status
	endpoint.page_title = page_title
	endpoint.content_length = content_length
	endpoint.webserver = webserver
	endpoint.response_time = response_time
	endpoint.content_type = content_type
	endpoint.is_redirect = is_redirect
	endpoint.save()

	# Sync Subdomain status attributes if this is the default endpoint
	if endpoint.is_default and subdomain:
		subdomain.http_status = http_status
		subdomain.page_title = page_title
		subdomain.content_length = content_length
		subdomain.webserver = webserver
		subdomain.response_time = response_time
		subdomain.content_type = content_type
		subdomain.http_url = http_url
		subdomain.save()

	return endpoint, created


def extract_httpx_url(line):
	"""Extract final URL from httpx results. Always follow redirects to find
	the last URL.

	Args:
		line (dict): URL data output by httpx.

	Returns:
		tuple: (final_url, redirect_bool) tuple.
	"""
	status_code = line.get('status_code', 0)
	final_url = line.get('final_url')
	location = line.get('location')
	chain_status_codes = line.get('chain_status_codes', [])

	# Final URL is already looking nice, if it exists return it
	if final_url:
		return final_url, False
	http_url = line['url'] # fallback to url field

	# Handle redirects manually
	REDIRECT_STATUS_CODES = [301, 302]
	is_redirect = (
		status_code in REDIRECT_STATUS_CODES
		or
		any(x in REDIRECT_STATUS_CODES for x in chain_status_codes)
	)
	if is_redirect and location:
		if location.startswith(('http', 'https')):
			http_url = location
		else:
			http_url = f'{http_url}/{location.lstrip("/")}'

	# Sanitize URL
	http_url = sanitize_url(http_url)

	return http_url, is_redirect


def save_metadata_info(meta_dict):
	"""Extract metadata from Google Search.

	Args:
		meta_dict (dict): Info dict.

	Returns:
		list: List of startScan.MetaFinderDocument objects.
	"""
	logger.warning(f'Getting metadata for {meta_dict.osint_target}')

	scan_history = ScanHistory.objects.get(id=meta_dict.scan_id)

	# Proxy settings
	proxy = get_random_proxy()

	# Get metadata
	try:
		result = extract_metadata_from_google_search(meta_dict.osint_target, meta_dict.documents_limit)
	except Exception as e:
		logger.error(f'Error extracting metadata from Google Search for {meta_dict.osint_target}: {str(e)}')
		return []

	if not result:
		logger.error(f'No metadata result from Google Search for {meta_dict.osint_target}.')
		return []

	# Add metadata info to DB
	results = []
	for metadata_name, data in result.get_metadata().items():
		subdomain = Subdomain.objects.get(
			scan_history=meta_dict.scan_id,
			name=meta_dict.osint_target)
		metadata = DottedDict({k: v for k, v in data.items()})
		meta_finder_document = MetaFinderDocument(
			subdomain=subdomain,
			target_domain=meta_dict.domain,
			scan_history=scan_history,
			url=metadata.url,
			doc_name=metadata_name,
			http_status=metadata.status_code,
			producer=metadata.metadata.get('Producer'),
			creator=metadata.metadata.get('Creator'),
			creation_date=metadata.metadata.get('CreationDate'),
			modified_date=metadata.metadata.get('ModDate'),
			author=metadata.metadata.get('Author'),
			title=metadata.metadata.get('Title'),
			os=metadata.metadata.get('OSInfo'))
		meta_finder_document.save()
		results.append(data)
	return results


def create_scan_activity(scan_history_id, message, status):
	scan_activity = ScanActivity()
	scan_activity.scan_of = ScanHistory.objects.get(pk=scan_history_id)
	scan_activity.title = message
	scan_activity.time = timezone.now()
	scan_activity.status = status
	scan_activity.save()
	return scan_activity.id



def save_ip_address(ip_address, subdomain=None, subscan=None, scan_id=None, activity_id=None, **kwargs):
	if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
		logger.info(f'IP {ip_address} is not a valid IP. Skipping.')
		return None, False
	ip, created = IpAddress.objects.get_or_create(address=ip_address)
	if created:
		ip.discovered_date = timezone.now()

	# Trigger geo localization if newly created OR if geo_iso is null
	if created or ip.geo_iso is None:
		from reNgine.temporal_client import TemporalClientProvider, run_and_close
		import asyncio
		async def _start():
			client = await TemporalClientProvider.get_client()
			await client.start_workflow(
				"GeoLocalizeWorkflow",
				args=[ip_address, ip.id, scan_id, activity_id],
				id=f"geo-localize-{ip.id}-{int(timezone.now().timestamp())}",
				task_queue="python-orchestrator-queue"
			)
		loop = asyncio.new_event_loop()
		try:
			run_and_close(loop, _start())
		except Exception as e:
			logger.warning(f"Failed to start GeoLocalizeWorkflow for IP {ip_address} in scan {scan_id}: {e}")

	# Set extra attributes
	for key, value in kwargs.items():
		setattr(ip, key, value)
	ip.save()

	# Add IP to subdomain
	if subdomain:
		subdomain.ip_addresses.add(ip)
		subdomain.save()

	# Add subscan to IP
	if subscan:
		ip.ip_subscan_ids.add(subscan)

	return ip, created


def save_secret_leak(scan_history, tool_name, secret_type, source_url, match_content, subdomain=None, status='unverified'):
	leak, created = SecretLeak.objects.get_or_create(
		scan_history=scan_history,
		tool_name=tool_name,
		secret_type=secret_type,
		source_url=source_url,
		match_content=match_content,
		subdomain=subdomain,
	)
	if created:
		leak.status = status
		leak.save()
	return leak, created
