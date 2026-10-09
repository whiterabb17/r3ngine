"""URL fetching with gau, hakrawler, waybackurls, gospider, katana and vigolium, plus GF pattern tagging.

Split out of the former reNgine/tasks/crawl.py; re-exported by
reNgine.tasks.crawl for backward compatibility.
"""
import os
import validators
from urllib.parse import urlparse

from reNgine.common_func import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403
from reNgine.utils.logger import get_module_logger
from reNgine.utils.task import (
    run_command,
    run_command_with_retry,
    activity_heartbeat_safe,
    bulk_persist_fetch_urls,
    bulk_apply_gf_pattern_from_file,
)

logger = get_module_logger(__name__)

def fetch_url(self, urls=[], ctx={}, description=None):
	"""Fetch URLs using different tools like gauplus, gau, gospider, waybackurls ...

	Args:
		urls (list): List of URLs to start from.
		description (str, optional): Task description shown in UI.
	"""
	input_path = f'{self.results_dir}/input_endpoints_fetch_url.txt'

	# Config
	config = self.yaml_configuration.get(FETCH_URL) or {}
	should_remove_duplicate_endpoints = config.get(REMOVE_DUPLICATE_ENDPOINTS, True)
	duplicate_removal_fields = config.get(DUPLICATE_REMOVAL_FIELDS, ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	gf_patterns = config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS)
	ignore_file_extension = config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS)
	tools = config.get(USES_TOOLS, ENDPOINT_SCAN_DEFAULT_TOOLS)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	# domain_request_headers = self.domain.request_headers if self.domain else None
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
	exclude_subdomains = config.get(EXCLUDED_SUBDOMAINS, False)

	# Get URLs to scan and save to input file
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_alive=enable_http_crawl,
			write_filepath=input_path,
			exclude_subdomains=exclude_subdomains,
			get_only_default_urls=True,
			ctx=ctx
		)
		# When http_crawl found no alive endpoints, fall back to all default
		# seed URLs so passive tools (gau, waybackurls) can still query
		# historical data even if the target is currently unreachable.
		if not urls and enable_http_crawl:
			urls = get_http_urls(
				is_alive=False,
				write_filepath=input_path,
				exclude_subdomains=exclude_subdomains,
				get_only_default_urls=True,
				ctx=ctx
			)

	# Domain regex
	host = self.domain.name if self.domain else urlparse(urls[0]).netloc
	host_regex = f"\'https?://([a-zA-Z0-9_-]+[.])*{host}[^][[:space:]\\\"\\`><]*\'"

	# Tools cmds
	base_cmd_map = {
		'gau': f'gau',
		'hakrawler': 'hakrawler -subs -u',
		'waybackurls': 'waybackurls',
		'gospider': f'gospider -S {input_path} --js -d 2 --sitemap --robots -w -r',
		'katana': f'katana -list {input_path} -silent -jc -kf all -d 3 -fs rdn',
	}

	recon_run = False
	for tool in tools:
		if tool in base_cmd_map:
			p = get_random_proxy()

			# Build base command without proxy so we can reuse it for fallback
			base_tool_cmd = base_cmd_map[tool]
			if threads > 0:
				if tool == 'gau': base_tool_cmd += f' --threads {threads}'
				elif tool == 'gospider': base_tool_cmd += f' -t {threads}'
				elif tool == 'katana': base_tool_cmd += f' -c {threads}'
			if custom_headers:
				formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
				if tool == 'gospider': base_tool_cmd += f' {formatted_headers}'
				elif tool == 'hakrawler': base_tool_cmd += ';;'.join(header for header in custom_headers)
				elif tool == 'katana': base_tool_cmd += f' {formatted_headers}'

			# Add proxy for the primary attempts
			tool_cmd = base_tool_cmd
			if p:
				if tool == 'katana': tool_cmd += f' -proxy "{p}"'
				elif tool == 'gospider': tool_cmd += f' -p {p}'
				#elif tool == 'hakrawler': tool_cmd += f' -proxy {p}'
				elif tool == 'gau': tool_cmd += f' --proxy {p}'

			url_results_file = f'{self.results_dir}/urls_{tool}.txt'
			if os.path.exists(url_results_file) and os.path.getsize(url_results_file) > 0:
				logger.info("%s: reusing cached results in %s", tool, url_results_file)
				recon_run = True
				continue

			full_cmd = f'cat {input_path} | {tool_cmd} | grep -Eo {host_regex} | tee {url_results_file}'
			logger.info("Running %s", tool)
			logger.warning("%s command: %s", tool, full_cmd)
			run_command_with_retry(
				full_cmd,
				results_file=url_results_file,
				shell=True,
				scan_id=self.scan_id,
				activity_id=self.activity_id
			)

			# If all 3 proxy attempts produced no results, retry once without proxy
			if p and (not os.path.exists(url_results_file) or os.path.getsize(url_results_file) == 0):
				logger.warning("%s: all proxy attempts failed, retrying once without proxy", tool)
				full_no_proxy_cmd = f'cat {input_path} | {base_tool_cmd} | grep -Eo {host_regex} | tee {url_results_file}'
				logger.warning(
					'%s no-proxy fallback: %s', tool,
					redact_proxy_credentials(full_no_proxy_cmd),
				)
				run_command(full_no_proxy_cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)

			recon_run = True

	# Vigolium spidering — runs ingestion+discovery phases to collect additional URLs.
	# Activated by adding 'vigolium' to fetch_url.uses_tools in the YAML config.
	if 'vigolium' in tools and os.path.isfile(input_path):
		from reNgine.tasks.vigolium import _ensure_duration as _ensure_vigolium_duration, _iter_jsonl

		vigolium_jsonl = f'{self.results_dir}/urls_vigolium.jsonl'
		vigolium_urls_file = f'{self.results_dir}/urls_vigolium.txt'

		vig_spider_config = config.get('vigolium_spider', {})
		vuln_vig_config = config.get('vulnerability_scan', {}).get('vigolium', {})
		vig_concurrency = vig_spider_config.get(VIGOLIUM_CONCURRENCY, 30)
		vig_rate_limit = vig_spider_config.get(VIGOLIUM_RATE_LIMIT, 80)
		vig_timeout = _ensure_vigolium_duration(vig_spider_config.get(VIGOLIUM_TIMEOUT, '20s'))
		vig_spider_max_time = _ensure_vigolium_duration(vig_spider_config.get(VIGOLIUM_SPIDER_MAX_TIME, '75m'))
		vig_strategy = vig_spider_config.get(VIGOLIUM_STRATEGY, 'balanced')
		vig_scope_origin = vig_spider_config.get(VIGOLIUM_SCOPE_ORIGIN, vuln_vig_config.get(VIGOLIUM_SCOPE_ORIGIN, 'balanced'))
		vig_skip_spidering = vig_spider_config.get(VIGOLIUM_SKIP_SPIDERING, vuln_vig_config.get(VIGOLIUM_SKIP_SPIDERING, False))

		phases = "ingestion,discovery" if vig_skip_spidering else "ingestion,spidering,discovery"
		vig_cmd = (
			f"vigolium scan"
			f" -T {input_path}"
			f" --only {phases}"
			f" --stateless"
			f" --format jsonl"
			f" -o {vigolium_jsonl}"
			f" -c {vig_concurrency}"
			f" -r {vig_rate_limit}"
			f" --timeout {vig_timeout}"
			f" --spider-max-time {vig_spider_max_time}"
			f" --strategy {vig_strategy}"
			f" --scope-origin {vig_scope_origin}"
			f" --skip-dependency-check"
		)
		proxy = get_random_proxy()
		if proxy:
			vig_cmd += f" --proxy {proxy}"

		if os.path.exists(vigolium_jsonl) and os.path.getsize(vigolium_jsonl) > 0:
			logger.info("fetch_url: reusing cached vigolium results in %s", vigolium_jsonl)
		else:
			logger.info("fetch_url: running vigolium spidering")
			logger.warning("vigolium spider command: %s", vig_cmd)
			run_command_with_retry(
				vig_cmd,
				results_file=vigolium_jsonl,
				scan_id=self.scan_id,
				activity_id=self.activity_id
			)

		spider_urls = [
			record['data']['url']
			for record in _iter_jsonl(vigolium_jsonl)
			if record.get('type') == 'http_record' and record.get('data', {}).get('url')
		]
		if spider_urls:
			with open(vigolium_urls_file, 'w') as _vf:
				_vf.write('\n'.join(spider_urls))
			logger.info("fetch_url: vigolium spidering found %s URLs", len(spider_urls))
			recon_run = True

	if not recon_run:
		logger.warning('No reconnaissance tools enabled for fetch_url. Skipping.')
		return

	# Cleanup task — only merge plain-text url lists (exclude .jsonl artifacts)
	sort_output = [
		f'cat {self.results_dir}/urls_*.txt > {self.output_path} 2>/dev/null || true',
		f'cat {input_path} >> {self.output_path}',
		f'sort -u {self.output_path} -o {self.output_path}',
	]
	if ignore_file_extension:
		ignore_exts = '|'.join(ignore_file_extension)
		grep_ext_filtered_output = [
			f'cat {self.output_path} | grep -Eiv "\\.({ignore_exts}).*" > {self.results_dir}/urls_filtered.txt',
			f'mv {self.results_dir}/urls_filtered.txt {self.output_path}'
		]
		sort_output.extend(grep_ext_filtered_output)

	for cmd in sort_output:
		run_command(
			cmd,
			shell=True,
			scan_id=self.scan_id,
			activity_id=self.activity_id
		)

	# Store all the endpoints and run httpx
	if not os.path.isfile(self.output_path):
		logger.warning('fetch_url: output file not found at %s, no URLs to process.', self.output_path)
		return

	all_urls_set = set()
	raw_line_count = 0
	with open(self.output_path, encoding='utf-8', errors='replace') as f:
		for raw_line in f:
			raw_line_count += 1
			parsed = parse_fetched_url_line(raw_line, self.starting_point_path)
			if not parsed:
				continue
			if not validators.url(parsed):
				logger.warning('Invalid URL "%s". Skipping.', parsed)
				continue
			all_urls_set.add(parsed)
			if raw_line_count % 25000 == 0:
				activity_heartbeat_safe(f'fetch_url parse {raw_line_count} lines')

	self.notify(fields={'Discovered URLs': len(all_urls_set)})

	all_urls = list(all_urls_set)

	# if exclude_paths is found, then remove urls matching those paths
	if self.excluded_paths:
		all_urls = exclude_urls_by_patterns(self.excluded_paths, all_urls)

	# Pass 1: URL signature dedup — collapse parametric variants (same path, different param values).
	if should_remove_duplicate_endpoints:
		pre_count = len(all_urls)
		seen_sigs = set()
		deduped = []
		for url in all_urls:
			sig = url_param_signature(url)
			if sig not in seen_sigs:
				seen_sigs.add(sig)
				deduped.append(url)
		all_urls = deduped
		logger.warning(
			"fetch_url dedup: %s → %s URLs (removed %s parametric variants)", pre_count, len(all_urls), pre_count - len(all_urls)
		)

	# Write result to output path
	with open(self.output_path, 'w') as f:
		f.write('\n'.join(all_urls))
	logger.warning("Found %s usable URLs", len(all_urls))

	# Save discovered URLs immediately to database as skeleton endpoints (batched).
	created_count = bulk_persist_fetch_urls(all_urls, ctx)
	logger.warning("fetch_url persisted %s new skeleton endpoints", created_count)

	# Pass 2: Content-based dedup — delete endpoints already enriched by http_crawl
	# whose (subdomain, content_length, page_title) signature matches a shorter sibling.
	# Skeleton endpoints added by fetch_url (no content_length/page_title yet) are skipped.
	if should_remove_duplicate_endpoints and duplicate_removal_fields:
		scan_obj = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()
		domain_obj = Domain.objects.filter(pk=ctx.get('domain_id')).first()
		if scan_obj and domain_obj:
			field_filter = {f'{f}__isnull': False for f in duplicate_removal_fields}
			field_filter.update(
				{f'{f}__gt': 0 for f in duplicate_removal_fields if f == 'content_length'}
			)
			crawled_eps = EndPoint.objects.filter(
				scan_history=scan_obj,
				target_domain=domain_obj,
				**field_filter
			).order_by('http_url')

			seen_content_sigs = {}
			to_delete = []
			for ep in crawled_eps.iterator(chunk_size=2000):
				sig = tuple(getattr(ep, f, None) for f in duplicate_removal_fields)
				subdomain_key = (ep.subdomain_id,) + sig
				if subdomain_key in seen_content_sigs:
					to_delete.append(ep.pk)
				else:
					seen_content_sigs[subdomain_key] = ep.pk

			if to_delete:
				deleted_count, _ = EndPoint.objects.filter(pk__in=to_delete).delete()
				logger.warning(
					"fetch_url content dedup: removed %s duplicate endpoints (same %s)", deleted_count, duplicate_removal_fields
				)



	#-------------------#
	# GF PATTERNS MATCH #
	#-------------------#

	# Combine old gf patterns with new ones
	if gf_patterns:
		self.scan.used_gf_patterns = ','.join(gf_patterns)
		self.scan.save()

	# Run gf patterns on saved endpoints
	# TODO: refactor to Celery task
	for gf_pattern in gf_patterns:
		# TODO: js var is causing issues, removing for now
		if gf_pattern == 'jsvar':
			logger.info('Ignoring jsvar as it is causing issues.')
			continue

		# Run gf on current pattern
		logger.warning('Running gf on pattern "%s"', gf_pattern)
		gf_output_file = f'{self.results_dir}/gf_patterns_{gf_pattern}.txt'
		cmd = f'cat {self.output_path} | gf {gf_pattern} | grep -Eo {host_regex} | tee -a {gf_output_file}'
		run_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)

		if not os.path.exists(gf_output_file):
			logger.error('Could not find GF output file %s. Skipping GF pattern "%s"', gf_output_file, gf_pattern)
			continue

		updated = bulk_apply_gf_pattern_from_file(gf_output_file, gf_pattern, ctx)
		logger.warning('GF pattern "%s" updated %s endpoints', gf_pattern, updated)

	return all_urls
