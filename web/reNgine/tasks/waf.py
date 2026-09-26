import logging
import os

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.utils.waf import OriginDiscoveryManager, WafBypassOrchestrator
from reNgine.utils.task import run_command, save_subdomain
from startScan.models import Subdomain, Waf

logger = logging.getLogger(__name__)

#: Waf.name and Waf.manufacturer are both CharField(max_length=500).
_WAF_FIELD_MAX_LENGTH = 500


def parse_wafw00f_entry(waf_info):
	"""Split wafw00f's "Name (Manufacturer)" into its two parts.

	Returns (None, None) for a line that is not in that shape. str.find returns
	-1 when the parenthesis is absent, so slicing on it unguarded turned such a
	line into "everything but the last character" — a value far longer than the
	500-character column, which failed the whole task with a DataError rather
	than skipping one unparseable line.
	"""
	open_idx = waf_info.find('(')
	close_idx = waf_info.find(')', open_idx + 1) if open_idx != -1 else -1
	if open_idx == -1 or close_idx == -1:
		return None, None

	name = waf_info[:open_idx].strip()
	if not name or name == 'None':
		return None, None

	manufacturer = waf_info[open_idx + 1:close_idx].strip().replace('.', '')
	return name[:_WAF_FIELD_MAX_LENGTH], manufacturer[:_WAF_FIELD_MAX_LENGTH]


def waf_detection(self, ctx={}, description=None):
	"""
	Uses wafw00f to check for the presence of a WAF.

	Args:
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of startScan.models.Waf objects.
	"""
	input_path = f'{self.results_dir}/input_endpoints_waf_detection.txt'
	config = self.yaml_configuration.get(WAF_DETECTION) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)

	# Get alive endpoints from DB
	get_http_urls(
		is_alive=enable_http_crawl,
		write_filepath=input_path,
		get_only_default_urls=True,
		ctx=ctx
	)

	cmd = f'wafw00f -i {input_path} -o {self.output_path}'
	if ctx.get('singular_tool_run') and ctx.get('extra_cli_args'):
		from reNgine.tool_args import append_extra_cli_args
		cmd = append_extra_cli_args(cmd, ctx.get('extra_cli_args') or [])
	logger.info(f'Running WAFW00F on {input_path}')
	run_command(
		cmd,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	if not os.path.isfile(self.output_path):
		logger.error(f'Could not find {self.output_path}')
		return

	with open(self.output_path) as file:
		wafs = file.readlines()

	for line in wafs:
		line = " ".join(line.split())
		splitted = line.split(' ', 1)
		if len(splitted) < 2:
			continue

		waf_name, waf_manufacturer = parse_wafw00f_entry(splitted[1].strip())
		if not waf_name:
			continue

		http_url = sanitize_url(splitted[0].strip())

		# Add waf to db
		waf, _ = Waf.objects.get_or_create(
			name=waf_name,
			manufacturer=waf_manufacturer
		)

		# Add waf info to Subdomain in DB
		subdomain = get_subdomain_from_url(http_url)
		logger.info(f'Wafw00f Subdomain : {subdomain}')
		subdomain_query, _ = save_subdomain(subdomain, ctx=ctx)
		if not subdomain_query:
			continue
		subdomain_query.waf.add(waf)
		subdomain_query.save()

		# Phase 2: Origin Discovery
		waf_config = config or {}
		use_shodan = waf_config.get('use_shodan', True)
		use_censys = waf_config.get('use_censys', True)

		logger.info(f"Starting Origin Discovery for {subdomain}")
		origin_manager = OriginDiscoveryManager(subdomain_query)
		origin_ips = origin_manager.find_origin(
			use_shodan=use_shodan,
			use_censys=use_censys
		)

		if origin_ips:
			# Store the first one as primary origin_ip
			primary_origin = origin_ips[0]
			subdomain_query.origin_ip = primary_origin
			subdomain_query.save()

			# Ensure this IP is stored and geolocated
			from reNgine.tasks.persistence import save_ip_address
			save_ip_address(
				primary_origin,
				subdomain=subdomain_query,
				subscan=self.subscan,
				scan_id=self.scan_id,
				activity_id=self.activity_id
			)
			logger.info(f"Origin IP found for {subdomain}: {primary_origin}")

	return wafs


def waf_bypass(self, ctx={}, description=None):
	"""
	Tests various WAF bypass techniques.
	"""
	if not ctx.get('singular_tool_run') and 'waf_bypass' not in (self.scan.tasks or []):
		return

	config = self.yaml_configuration.get('waf_bypass') or {}
	use_nuclei = config.get('use_nuclei', True)
	use_benchmarking = config.get('use_benchmarking', True)

	# Get subdomains with WAFs in this scan (scoped for singular / subscan runs).
	subdomains = Subdomain.objects.filter(scan_history=self.scan).exclude(waf=None)
	if ctx.get('subdomain_id'):
		subdomains = subdomains.filter(pk=ctx['subdomain_id'])
	elif ctx.get('singular_tool_run') and ctx.get('hosts'):
		subdomains = subdomains.filter(name__in=list(ctx.get('hosts') or []))

	for subdomain in subdomains:
		logger.info(f"Starting WAF Bypass tests for {subdomain.name}")
		orchestrator = WafBypassOrchestrator(subdomain)
		findings = orchestrator.run_all_tests(
			use_nuclei=use_nuclei,
			use_benchmarking=use_benchmarking
		)

		if findings:
			logger.info(f"Found {len(findings)} potential WAF bypasses for {subdomain.name}")

	return True
