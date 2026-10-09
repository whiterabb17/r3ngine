"""HTTP crawl with httpx and the cURL output parser.

Split out of the former reNgine/tasks/crawl.py; re-exported by
reNgine.tasks.crawl for backward compatibility.
"""
import re

from reNgine.common_func import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403
from reNgine.utils.logger import get_module_logger
from reNgine.utils.opsec import get_opsec_manager
from reNgine.utils.task import run_command, stream_command
from reNgine.tasks.persistence import (
    process_httpx_response,
    remove_duplicate_endpoints,
    save_ip_address,
)

logger = get_module_logger(__name__)

def parse_curl_output(response):
	# TODO: Enrich from other cURL fields.
	CURL_REGEX_HTTP_STATUS = r'HTTP\/(?:(?:\d\.?)+)\s(\d+)\s(?:\w+)'
	http_status = 0
	if response:
		failed = False
		regex = re.compile(CURL_REGEX_HTTP_STATUS, re.MULTILINE)
		try:
			http_status = int(regex.findall(response)[0])
		except (KeyError, TypeError, IndexError):
			pass
	return {
		'http_status': http_status,
	}


def http_crawl(
		self,
		urls=[],
		method=None,
		recrawl=False,
		ctx={},
		track=True,
		description=None,
		is_ran_from_subdomain_scan=False,
		should_remove_duplicate_endpoints=True,
		duplicate_removal_fields=[]):
	"""Use httpx to query HTTP URLs for important info like page titles, http
	status, etc...

	Args:
		urls (list, optional): A set of URLs to check. Overrides default
			behavior which queries all endpoints related to this scan.
		method (str): HTTP method to use (GET, HEAD, POST, PUT, DELETE).
		recrawl (bool, optional): If False, filter out URLs that have already
			been crawled.
		should_remove_duplicate_endpoints (bool): Whether to remove duplicate endpoints
		duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates

	Returns:
		list: httpx results.
	"""
	logger.info('Initiating HTTP Crawl')
	if is_ran_from_subdomain_scan:
		logger.info('Running From Subdomain Scan...')
	cmd = '/usr/local/bin/httpx'
	cfg = self.yaml_configuration.get(HTTP_CRAWL) or {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	threads = cfg.get(THREADS, DEFAULT_THREADS)
	follow_redirect = cfg.get(FOLLOW_REDIRECT, True)
	self.output_path = None
	input_path = f'{self.results_dir}/httpx_input.txt'
	history_file = f'{self.results_dir}/commands.txt'
	if urls: # direct passing URLs to check
		if self.starting_point_path:
			urls = [u for u in urls if self.starting_point_path in u]

		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_uncrawled=not recrawl,
			write_filepath=input_path,
			ctx=ctx
		)
		# logger.debug(urls)

	# exclude urls by pattern
	if self.excluded_paths:
		urls = exclude_urls_by_patterns(self.excluded_paths, urls)

	# If no URLs found, skip it
	if not urls:
		return

	# Re-adjust thread number if few URLs to avoid spinning up a monster to
	# kill a fly.
	if len(urls) < threads:
		threads = len(urls)

	# projectdiscovery tools like naabu and httpx seem to fail when proxies are used
	# ensuring that proxies are never used for httpx
	proxy = ''

	# Run command
	cmd += f' -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe -random-agent'
	cmd += f' -t {threads}' if threads > 0 else ''
	cmd += f' --http-proxy {proxy}' if proxy else ''
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += f' {formatted_headers}'
	cmd += f' -json'
	cmd += f' -u {urls[0]}' if len(urls) == 1 else f' -l {input_path}'
	cmd += f' -x {method}' if method else ''
	if follow_redirect:
		cmd += ' --follow-redirects'
	
	# Apply OpSec stealth
	opsec = get_opsec_manager()
	cmd = opsec.apply_stealth('httpx', cmd, proxy=proxy)
	if ctx.get('singular_tool_run') and ctx.get('extra_cli_args'):
		from reNgine.tool_args import append_extra_cli_args
		cmd = append_extra_cli_args(cmd, ctx.get('extra_cli_args') or [])

	results = []
	endpoint_ids = []
	for line in stream_command(
			cmd,
			history_file=history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id):

		if not line or not isinstance(line, dict):
			continue

		logger.debug(line)

		# No response from endpoint
		if line.get('failed', False):
			continue

		httpx_result = process_httpx_response(line, ctx=ctx, is_ran_from_subdomain_scan=is_ran_from_subdomain_scan)
		if not httpx_result:
			continue

		endpoint, created = httpx_result

		if not endpoint:
			continue

		endpoint_str = f'{endpoint.http_url} [{endpoint.http_status}] `{endpoint.content_length}B` `{endpoint.webserver}` `{line.get("time")}`'
		logger.warning(endpoint_str)
		if endpoint.is_alive and endpoint.http_status != 403:
			self.notify(
				fields={'Alive endpoint': f'• {endpoint_str}'},
				add_meta_info=False)

		# Add endpoint to results for UI tabs
		line['_cmd'] = cmd
		line['final_url'] = endpoint.http_url
		line['endpoint_id'] = endpoint.id
		line['endpoint_created'] = created
		line['is_redirect'] = endpoint.is_redirect
		line['status_code'] = endpoint.http_status
		line['title'] = endpoint.page_title
		line['content_length'] = endpoint.content_length
		line['webserver'] = endpoint.webserver
		line['content_type'] = endpoint.content_type
		line['response_time'] = endpoint.response_time
		
		results.append(line)

		techs = line.get('tech', [])
		subdomain = endpoint.subdomain

		# Add technology objects to DB
		for technology in techs:
			from django.core.exceptions import MultipleObjectsReturned
			try:
				tech, _ = Technology.objects.get_or_create(name=technology)
			except MultipleObjectsReturned:
				tech = Technology.objects.filter(name=technology).first()
			endpoint.techs.add(tech)
			if subdomain:
				subdomain.technologies.add(tech)
				subdomain.save()
			endpoint.save()
		techs_str = ', '.join([f'`{tech}`' for tech in techs])
		self.notify(
			fields={'Technologies': techs_str},
			add_meta_info=False)

		# Add IP objects for 'a' records to DB
		a_records = line.get('a', [])
		cdn = line.get('cdn', False)
		for ip_address in a_records:
			ip, _ = save_ip_address(
				ip_address,
				subdomain,
				subscan=self.subscan,
				scan_id=self.scan_id,
				activity_id=self.activity_id,
				cdn=cdn)
		
		if a_records:
			ips_str = '• ' + '\n• '.join([f'`{ip}`' for ip in a_records])
			self.notify(
				fields={'IPs': ips_str},
				add_meta_info=False)

		# Update subdomain status: always update if subdomain has no real status yet,
		# or if this is the canonical/default endpoint.
		if subdomain and (endpoint.is_default or not subdomain.http_status):
			subdomain.http_url = endpoint.http_url
			subdomain.http_status = endpoint.http_status
			subdomain.page_title = endpoint.page_title
			subdomain.content_length = endpoint.content_length
			subdomain.webserver = endpoint.webserver
			subdomain.response_time = endpoint.response_time
			subdomain.content_type = endpoint.content_type

			cnames = line.get('cnames', [])
			if cnames:
				subdomain.cname = ','.join(cnames)

			subdomain.is_cdn = cdn
			if cdn:
				subdomain.cdn_name = line.get('cdn_name')
			subdomain.save()
		endpoint.save()
		endpoint_ids.append(endpoint.id)

	if should_remove_duplicate_endpoints:
		# Remove 'fake' alive endpoints that are just redirects to the same page
		remove_duplicate_endpoints(
			self.scan_id,
			self.domain_id,
			self.subdomain_id,
			filter_ids=endpoint_ids
		)

	# Remove input file
	run_command(
		f'rm {input_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	return results
