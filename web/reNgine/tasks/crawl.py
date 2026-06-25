import logging
import os
import json
import requests
from pathlib import Path
from urllib.parse import urlparse

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.utils.opsec import OpSecManager, ProxychainsWrapper, get_opsec_manager
from reNgine.utils.task import (
    run_command, run_command_with_retry, stream_command,
    bulk_persist_fetch_urls, bulk_apply_gf_pattern_from_file,
    save_endpoint, save_parameter,
)
from reNgine.tasks.persistence import process_httpx_response, extract_httpx_url, remove_duplicate_endpoints
from startScan.models import *

logger = logging.getLogger(__name__)

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
				logger.info(f'{tool}: reusing cached results in {url_results_file}')
				recon_run = True
				continue

			full_cmd = f'cat {input_path} | {tool_cmd} | grep -Eo {host_regex} | tee {url_results_file}'
			logger.info(f'Running {tool}')
			logger.warning(f'{tool} command: {full_cmd}')
			run_command_with_retry(
				full_cmd,
				results_file=url_results_file,
				shell=True,
				scan_id=self.scan_id,
				activity_id=self.activity_id
			)

			# If all 3 proxy attempts produced no results, retry once without proxy
			if p and (not os.path.exists(url_results_file) or os.path.getsize(url_results_file) == 0):
				logger.warning(f'{tool}: all proxy attempts failed, retrying once without proxy')
				full_no_proxy_cmd = f'cat {input_path} | {base_tool_cmd} | grep -Eo {host_regex} | tee {url_results_file}'
				logger.warning(f'{tool} no-proxy fallback: {full_no_proxy_cmd}')
				run_command(full_no_proxy_cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)

			recon_run = True

	# Vigolium spidering — runs ingestion+discovery phases to collect additional URLs.
	# Activated by adding 'vigolium' to fetch_url.uses_tools in the YAML config.
	if 'vigolium' in tools and os.path.isfile(input_path):
		from reNgine.vigolium_tasks import _ensure_duration as _ensure_vigolium_duration, _iter_jsonl

		vigolium_jsonl = f'{self.results_dir}/urls_vigolium.jsonl'
		vigolium_urls_file = f'{self.results_dir}/urls_vigolium.txt'

		vig_spider_config = config.get('vigolium_spider', {})
		vig_concurrency = vig_spider_config.get(VIGOLIUM_CONCURRENCY, 30)
		vig_rate_limit = vig_spider_config.get(VIGOLIUM_RATE_LIMIT, 80)
		vig_timeout = _ensure_vigolium_duration(vig_spider_config.get(VIGOLIUM_TIMEOUT, '20s'))
		vig_strategy = vig_spider_config.get(VIGOLIUM_STRATEGY, 'balanced')

		vig_cmd = (
			f"vigolium scan"
			f" -T {input_path}"
			f" --only ingestion,discovery"
			f" --stateless"
			f" --format jsonl"
			f" -o {vigolium_jsonl}"
			f" -c {vig_concurrency}"
			f" -r {vig_rate_limit}"
			f" --timeout {vig_timeout}"
			f" --strategy {vig_strategy}"
			f" --skip-dependency-check"
		)
		proxy = get_random_proxy()
		if proxy:
			vig_cmd += f" --proxy {proxy}"

		if os.path.exists(vigolium_jsonl) and os.path.getsize(vigolium_jsonl) > 0:
			logger.info(f'fetch_url: reusing cached vigolium results in {vigolium_jsonl}')
		else:
			logger.info("fetch_url: running vigolium spidering")
			logger.warning(f"vigolium spider command: {vig_cmd}")
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
			logger.info(f"fetch_url: vigolium spidering found {len(spider_urls)} URLs")
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
				logger.warning(f'Invalid URL "{parsed}". Skipping.')
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
			f'fetch_url dedup: {pre_count} → {len(all_urls)} URLs '
			f'(removed {pre_count - len(all_urls)} parametric variants)'
		)

	# Write result to output path
	with open(self.output_path, 'w') as f:
		f.write('\n'.join(all_urls))
	logger.warning(f'Found {len(all_urls)} usable URLs')

	# Save discovered URLs immediately to database as skeleton endpoints (batched).
	created_count = bulk_persist_fetch_urls(all_urls, ctx)
	logger.warning(f'fetch_url persisted {created_count} new skeleton endpoints')

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
					f'fetch_url content dedup: removed {deleted_count} duplicate endpoints '
					f'(same {duplicate_removal_fields})'
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
		logger.warning(f'Running gf on pattern "{gf_pattern}"')
		gf_output_file = f'{self.results_dir}/gf_patterns_{gf_pattern}.txt'
		cmd = f'cat {self.output_path} | gf {gf_pattern} | grep -Eo {host_regex} | tee -a {gf_output_file}'
		run_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)

		if not os.path.exists(gf_output_file):
			logger.error(f'Could not find GF output file {gf_output_file}. Skipping GF pattern "{gf_pattern}"')
			continue

		updated = bulk_apply_gf_pattern_from_file(gf_output_file, gf_pattern, ctx)
		logger.warning(f'GF pattern "{gf_pattern}" updated {updated} endpoints')

	return all_urls


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



def web_api_discovery(self, urls=[], ctx={}, description=None):
	"""Advanced Web App & API Discovery using Kiterunner, Arjun, LinkFinder, etc."""
	scan_id = ctx.get('scan_history_id')
	config = self.yaml_configuration.get(WEB_API_DISCOVERY) or {}
	uses_tools = ctx.get('api_discovery_tools') or config.get(USES_TOOLS, ['kiterunner', 'arjun', 'linkfinder', 'paramspider', 'semgrep'])
	kr_wordlist = ctx.get('kr_wordlist') or config.get(KITERUNNER_WORDLIST, 'routes-small.kite')
	scan_only_active = config.get(SCAN_ONLY_ACTIVE, True)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	arjun_methods = config.get(ARJUN_METHODS, ARJUN_DEFAULT_METHODS)
	proxy = None
	kr_proxy = 'socks5://tor:9050' if ctx.get('use_tor') else None

	logger.warning("[WEB_API] Starting Web API Discovery | scan_id=%s | tools=%s", scan_id, uses_tools)

	# Get targets
	if not urls:
		urls = get_http_urls(
			is_alive=scan_only_active,
			write_filepath=None,
			ctx=ctx
		)

	if not urls:
		logger.warning('[WEB_API] No targets found for Web API Discovery — aborting.')
		return

	logger.warning('[WEB_API] Target URL count: %d | scan_only_active=%s', len(urls), scan_only_active)

	results_dir = f"{self.results_dir}/web_api_discovery"
	os.makedirs(results_dir, exist_ok=True)

	# ── Phase 1: Map URLs to subdomains ─────────────────────────────────────
	# Build subdomain_targets {name: (Subdomain, base_url)} for Kiterunner and
	# an ordered url_subdomain_map for per-URL tools (Arjun, LinkFinder, InQL).
	# URL pattern deduplication removes param-value variants that add no value
	# (e.g. locale=ar vs locale=cs share the same path+key signature).
	subdomain_targets = {}
	url_subdomain_map = []
	processed_url_patterns = set()
	skipped_no_subdomain = 0

	for url in urls:
		parsed = urlparse(url)
		query_keys = sorted(parse_qs(parsed.query).keys())
		url_pattern = f"{parsed.netloc}{parsed.path}?{'&'.join(query_keys)}"
		if url_pattern in processed_url_patterns:
			continue
		processed_url_patterns.add(url_pattern)

		subdomain_name = get_subdomain_from_url(url)
		subdomain = Subdomain.objects.filter(name=subdomain_name, scan_history=self.scan).first()
		if not subdomain:
			skipped_no_subdomain += 1
			continue

		if subdomain_name not in subdomain_targets:
			base_url = f"{parsed.scheme}://{parsed.netloc}/"
			subdomain_targets[subdomain_name] = (subdomain, base_url)

		url_subdomain_map.append((url, subdomain_name, subdomain))

	logger.warning(
		'[WEB_API] URL mapping complete: %d unique subdomains, %d deduplicated URLs queued, %d skipped (no subdomain record)',
		len(subdomain_targets), len(url_subdomain_map), skipped_no_subdomain,
	)

	# ── Kiterunner: batched scan across subdomains ───────────────────────────
	# Subdomains are batched in groups of `threads` and written to a hosts file
	# so that -j (max-parallel-hosts) is actually utilised rather than wasted
	# on a single host per call.
	# Per-subdomain .json files act as the idempotency guard for Temporal retries:
	# any subdomain with a non-empty file is skipped; the rest form the next batch.
	if 'kiterunner' in uses_tools:
		# Task 6: Validate wordlist path to prevent traversal (Rule 1.1/1.2)
		_kr_base_dir = Path('/usr/src/wordlist/kr').resolve()
		_kr_wordlist_path = (_kr_base_dir / kr_wordlist).resolve()
		if not str(_kr_wordlist_path).startswith(str(_kr_base_dir)):
			logger.error('[WEB_API] Kiterunner: wordlist path %s escapes base dir — skipping', kr_wordlist)
		else:
			logger.warning('[WEB_API] Kiterunner: scanning %d subdomains | wordlist=%s | batch_size=%d', len(subdomain_targets), kr_wordlist, threads)

			# Separate cached subdomains from those that still need scanning
			to_scan = {
				name: (sub, base_url)
				for name, (sub, base_url) in subdomain_targets.items()
				if not (os.path.exists(f"{results_dir}/kr_{name}.json") and os.path.getsize(f"{results_dir}/kr_{name}.json") > 0)
			}
			cached_count = len(subdomain_targets) - len(to_scan)
			if cached_count:
				logger.warning('[WEB_API] Kiterunner: %d subdomains cached, scanning %d new', cached_count, len(to_scan))

			# Scan phase: batch uncached subdomains so -j is utilised
			scan_items = list(to_scan.items())
			for batch_start in range(0, len(scan_items), threads):
				batch = dict(scan_items[batch_start:batch_start + threads])
				batch_idx = batch_start // threads

				hosts_file = f"{results_dir}/kr_hosts_batch_{batch_idx}.txt"
				with open(hosts_file, 'w') as hf:
					for _name, (_sub, _base_url) in batch.items():
						hf.write(_base_url + '\n')

				combined_output = f"{results_dir}/kr_batch_{batch_idx}.json"
				cmd = (
					f"kr scan {hosts_file}"
					f" -w {_kr_wordlist_path}"
					f" -j {threads}"
					f" --timeout {timeout}s"
					f" --fail-status-codes 404"
					f" -o json -q"
					f" | tee {combined_output}"
				)
				logger.warning('[WEB_API] Kiterunner: batch %d — %d hosts | cmd: %s', batch_idx, len(batch), cmd)
				run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id, proxy=kr_proxy)
				logger.warning('[WEB_API] Kiterunner: batch %d finished', batch_idx)

				# Split combined JSON output into per-subdomain files for caching
				if os.path.exists(combined_output):
					subdomain_lines: dict = {name: [] for name in batch}
					with open(combined_output, 'r') as f:
						for line in f:
							line = line.strip()
							if not line:
								continue
							try:
								entry = json.loads(line)
								target_host = urlparse(entry.get('target', '')).hostname or ''
								if target_host in subdomain_lines:
									subdomain_lines[target_host].append(line)
							except (json.JSONDecodeError, Exception):
								continue
					for _name, lines in subdomain_lines.items():
						if lines:
							_kr_out = f"{results_dir}/kr_{_name}.json"
							with open(_kr_out, 'w') as f:
								f.write('\n'.join(lines) + '\n')
				else:
					logger.warning('[WEB_API] Kiterunner: combined output missing for batch %d', batch_idx)

			# Parse pass: read all per-subdomain files (cached + newly written)
			for subdomain_name, (subdomain, base_url) in subdomain_targets.items():
				kr_output = f"{results_dir}/kr_{subdomain_name}.json"
				if not os.path.exists(kr_output):
					logger.warning('[WEB_API] Kiterunner: output file missing for %s', subdomain_name)
					continue
				try:
					kr_parsed = urlparse(base_url)
					kr_endpoints = 0
					kr_params = 0
					with open(kr_output, 'r') as f:
						for line in f:
							if not line.strip():
								continue
							entry = json.loads(line)
							found_path = entry.get('path', '')
							if not found_path:
								continue
							# Use correct status field from responses array
							responses = entry.get('responses', [])
							http_status = responses[0].get('sc') if responses else None
							# Skip 404s as defence-in-depth (--fail-status-codes 404 handles most)
							if http_status == 404:
								continue
							full_url = f"{kr_parsed.scheme}://{kr_parsed.netloc}{found_path}"
							endpoint, _ = save_endpoint(full_url, ctx=ctx, subdomain=subdomain, http_status=http_status)
							kr_endpoints += 1
							if endpoint and '?' in full_url:
								params = extract_params_from_url(full_url)
								for p in params:
									save_parameter(endpoint, p['name'], param_type='Kiterunner', value=p['value'])
									kr_params += 1
					logger.warning('[WEB_API] Kiterunner: %s → %d endpoints, %d params saved', subdomain_name, kr_endpoints, kr_params)
				except Exception as e:
					logger.error('[WEB_API] Kiterunner: error parsing output for %s: %s', subdomain_name, e)
	else:
		logger.warning('[WEB_API] Kiterunner: skipped (not in uses_tools)')

	# ── Per-URL tools (Arjun, ParamSpider, LinkFinder, InQL) ─────────────────
	# Each tool uses a file-existence check so that Temporal retries skip work
	# that already completed in a previous attempt.
	processed_paramspider_subdomains = set()
	processed_arjun_subdomains = set()
	processed_linkfinder_subdomains = set()
	# Gate-check caches: has_graphql_endpoint probes up to 6 network paths with a
	# 5s timeout each, and has_jwt_tokens issues 2 DB queries — both return the
	# same result for every URL sharing a subdomain.  Evaluate each gate once per
	# subdomain and reuse the cached bool for subsequent URLs.
	_graphql_gate_cache: dict = {}  # subdomain_name -> bool
	_jwt_gate_cache: dict = {}      # subdomain_name -> bool
	logger.warning('[WEB_API] Starting per-URL tool phase for %d URLs', len(url_subdomain_map))

	for url, subdomain_name, subdomain in url_subdomain_map:

		# Arjun - Parameter discovery (once per subdomain; output is subdomain-scoped)
		if 'arjun' in uses_tools and subdomain_name not in processed_arjun_subdomains:
			processed_arjun_subdomains.add(subdomain_name)
			arjun_output = f"{results_dir}/arjun_{subdomain_name}.json"
			if os.path.exists(arjun_output) and os.path.getsize(arjun_output) > 0:
				logger.warning('[WEB_API] Arjun: cache hit for %s — loading existing results', subdomain_name)
			else:
				cmd = f"arjun -u {url} --passive -m {arjun_methods} -t {threads} -oJ {arjun_output}"
				logger.warning('[WEB_API] Arjun: running on %s | cmd: %s', subdomain_name, cmd)
				run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)
				logger.warning('[WEB_API] Arjun: finished on %s', subdomain_name)
			if os.path.exists(arjun_output):
				try:
					arjun_params = 0
					with open(arjun_output, 'r') as f:
						data = json.load(f)
						for target_url, details in data.items():
							endpoint, _ = save_endpoint(target_url, ctx=ctx, subdomain=subdomain)
							if endpoint:
								params = details.get('params', {})
								if isinstance(params, dict):
									for method, param_list in params.items():
										for p in param_list:
											save_parameter(endpoint, p, param_type=method)
											arjun_params += 1
								elif isinstance(params, list):
									method = details.get('method', 'unknown')
									for p in params:
										save_parameter(endpoint, p, param_type=method)
										arjun_params += 1
					logger.warning('[WEB_API] Arjun: %s → %d params saved', subdomain_name, arjun_params)
				except Exception as e:
					logger.error('[WEB_API] Arjun: error parsing output for %s: %s', subdomain_name, e)
			else:
				logger.warning('[WEB_API] Arjun: output file missing for %s', subdomain_name)

		# ParamSpider - once per subdomain
		if 'paramspider' in uses_tools and subdomain_name not in processed_paramspider_subdomains:
			processed_paramspider_subdomains.add(subdomain_name)
			ps_output = f"{results_dir}/ps_{subdomain_name}.txt"
			if os.path.exists(ps_output) and os.path.getsize(ps_output) > 0:
				logger.warning('[WEB_API] ParamSpider: cache hit for %s — loading existing results', subdomain_name)
			else:
				cmd = f"paramspider --domain {subdomain_name} | tee {ps_output}"
				proxy = get_random_proxy()
				if proxy:
					cmd = f"paramspider --domain {subdomain_name} --proxy {proxy} | tee {ps_output}"
				logger.warning('[WEB_API] ParamSpider: running on %s | cmd: %s', subdomain_name, cmd)
				run_command(cmd, shell=True, cwd=results_dir, scan_id=self.scan_id, activity_id=self.activity_id)
				logger.warning('[WEB_API] ParamSpider: finished on %s', subdomain_name)
			if os.path.exists(ps_output):
				try:
					ps_params = 0
					with open(ps_output, 'r') as f:
						for line in f:
							line = line.strip()
							if line and is_valid_url(line):
								endpoint, _ = save_endpoint(line, ctx=ctx, subdomain=subdomain)
								parsed = urlparse(line)
								if parsed.query:
									for q in parsed.query.split('&'):
										if '=' in q:
											p_name = q.split('=')[0]
											save_parameter(endpoint, p_name, param_type='URL Query')
											ps_params += 1
					logger.warning('[WEB_API] ParamSpider: %s → %d params saved', subdomain_name, ps_params)
				except Exception as e:
					logger.error('[WEB_API] ParamSpider: error parsing output for %s: %s', subdomain_name, e)
			else:
				logger.warning('[WEB_API] ParamSpider: output file missing for %s', subdomain_name)

		# LinkFinder - once per subdomain (JS endpoint and parameter extraction).
		# processed_linkfinder_subdomains is the primary dedup guard so the tool
		# runs at most once per subdomain regardless of whether its output file is
		# empty (empty output = no JS found, not an error requiring a retry).
		# os.path.exists is the Temporal retry guard: a file written by a prior
		# activity attempt is loaded directly without re-running the tool.
		if 'linkfinder' in uses_tools and subdomain_name not in processed_linkfinder_subdomains:
			processed_linkfinder_subdomains.add(subdomain_name)
			lf_output = f"{results_dir}/lf_{subdomain_name}.txt"
			if os.path.exists(lf_output):
				logger.warning('[WEB_API] LinkFinder: cache hit for %s — loading existing results', subdomain_name)
			else:
				cmd = f"python3 /usr/src/github/LinkFinder/linkfinder.py -d -i {url} -o cli | tee {lf_output}"
				logger.warning('[WEB_API] LinkFinder: running on %s | cmd: %s', subdomain_name, cmd)
				run_command(cmd, shell=True, cwd=results_dir, scan_id=self.scan_id, activity_id=self.activity_id)
				logger.warning('[WEB_API] LinkFinder: finished on %s', subdomain_name)
			if os.path.exists(lf_output):
				try:
					lf_endpoints = 0
					lf_params = 0
					with open(lf_output, 'r') as f:
						for line in f:
							line = line.strip()
							if line.startswith('/') or line.startswith('http'):
								if line.startswith('/'):
									parsed = urlparse(url)
									full_url = f"{parsed.scheme}://{parsed.netloc}{line}"
								else:
									full_url = line
								endpoint, _ = save_endpoint(full_url, ctx=ctx, subdomain=subdomain)
								lf_endpoints += 1
								if endpoint is not None and '?' in full_url:
									params = extract_params_from_url(full_url)
									for p in params:
										save_parameter(endpoint, p['name'], param_type='LinkFinder', value=p['value'])
										lf_params += 1
					logger.warning('[WEB_API] LinkFinder: %s → %d endpoints, %d params saved', subdomain_name, lf_endpoints, lf_params)
				except Exception as e:
					logger.error('[WEB_API] LinkFinder: error parsing output for %s: %s', subdomain_name, e)
			else:
				logger.warning('[WEB_API] LinkFinder: output file missing for %s', subdomain_name)

		# InQL - GraphQL Discovery (only when a GraphQL endpoint is detected).
		# _graphql_gate_cache[subdomain_name] is populated on first visit so that
		# has_graphql_endpoint (which issues a DB iregex query + up to 6 network
		# probes × 5 s each) is called at most once per subdomain, not per URL.
		if 'inql' in uses_tools:
			if subdomain_name not in _graphql_gate_cache:
				logger.warning('[WEB_API] InQL: checking GraphQL gate for %s (first visit)', subdomain_name)
				_graphql_gate_cache[subdomain_name] = has_graphql_endpoint(self.scan_id, url)
			if not _graphql_gate_cache[subdomain_name]:
				logger.warning('[WEB_API] InQL: no GraphQL endpoint detected, skipping %s', subdomain_name)
			else:
				inql_output = f"{results_dir}/inql_{subdomain_name}"
				cmd = f"inql -t {url} -o {inql_output}"
				proxy = get_random_proxy()
				if proxy:
					cmd += f" -p {proxy}"
				logger.warning('[WEB_API] InQL: running on %s | cmd: %s', subdomain_name, cmd)
				run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)
				if os.path.exists(inql_output):
					try:
						inql_findings = parse_inql_results(inql_output)
						for finding in inql_findings:
							save_endpoint(url, ctx=ctx, subdomain=subdomain, source='InQL (GraphQL Found)')
						from reNgine.cpde.graphql_enricher import enrich_graphql_params
						enrich_graphql_params(inql_output, url, subdomain, ctx)
						logger.warning('[WEB_API] InQL: %s → %d GraphQL findings saved', subdomain_name, len(inql_findings))
					except Exception as e:
						logger.error('[WEB_API] InQL: error parsing results for %s: %s', subdomain_name, e)
				else:
					logger.warning('[WEB_API] InQL: no output directory found for %s', subdomain_name)

		# jwt_tool - JWT security testing (only when JWT tokens have been found).
		# _jwt_gate_cache[subdomain_name] is populated on first visit so that
		# has_jwt_tokens (2 DB queries per call) runs at most once per subdomain.
		if JWT_TOOL in uses_tools:
			if subdomain_name not in _jwt_gate_cache:
				logger.warning('[WEB_API] jwt_tool: checking JWT gate for %s (first visit)', subdomain_name)
				_jwt_gate_cache[subdomain_name] = has_jwt_tokens(self.scan_id, subdomain=subdomain)
			if _jwt_gate_cache[subdomain_name]:
				logger.warning('[WEB_API] jwt_tool: JWT tokens found, running on %s', subdomain_name)
				from reNgine.api_tasks import run_jwt_scan
				run_jwt_scan(self, ctx, url, subdomain, results_dir)
				logger.warning('[WEB_API] jwt_tool: finished on %s', subdomain_name)
			else:
				logger.warning('[WEB_API] jwt_tool: no JWT tokens detected, skipping %s', subdomain_name)

		# graphql-cop - GraphQL security audit (only when a GraphQL endpoint is detected).
		# Shares _graphql_gate_cache with InQL — no second round of probes needed.
		if GRAPHQL_COP in uses_tools:
			if subdomain_name not in _graphql_gate_cache:
				logger.warning('[WEB_API] graphql-cop: checking GraphQL gate for %s (first visit)', subdomain_name)
				_graphql_gate_cache[subdomain_name] = has_graphql_endpoint(self.scan_id, url)
			if not _graphql_gate_cache[subdomain_name]:
				logger.warning('[WEB_API] graphql-cop: no GraphQL endpoint detected, skipping %s', subdomain_name)
			else:
				logger.warning('[WEB_API] graphql-cop: running on %s', subdomain_name)
				from reNgine.api_tasks import run_graphql_cop
				run_graphql_cop(self, ctx, url, subdomain)
				logger.warning('[WEB_API] graphql-cop: finished on %s', subdomain_name)

	# Semgrep - Post-discovery pattern matching
	if 'semgrep' in uses_tools:
		semgrep_output = f"{results_dir}/semgrep_results.json"
		cmd = f"semgrep scan --config auto --json --output {semgrep_output} {results_dir}"
		logger.warning('[WEB_API] Semgrep: running post-discovery scan | cmd: %s', cmd)
		run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)
		if os.path.exists(semgrep_output):
			try:
				with open(semgrep_output, 'r') as f:
					data = json.load(f)
					matches = data.get('results', [])
					for match in matches:
						vuln_data = parse_semgrep_result(match)
						save_vulnerability(vuln_data, self.scan, self.domain)
				logger.warning('[WEB_API] Semgrep: %d vulnerabilities saved', len(matches))
			except Exception as e:
				logger.error('[WEB_API] Semgrep: error parsing output: %s', e)
		else:
			logger.warning('[WEB_API] Semgrep: output file not found — may have failed silently')
	else:
		logger.warning('[WEB_API] Semgrep: skipped (not in uses_tools)')

	# Retire.js - JS Library vulnerability scan
	if 'retire' in uses_tools:
		retire_output = f"{results_dir}/retire_results.json"
		cmd = f"npx -y retire --path {results_dir} --outputformat json --outputpath {retire_output}"
		logger.warning('[WEB_API] Retire.js: running | cmd: %s', cmd)
		run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)
		if os.path.exists(retire_output):
			try:
				retire_vulns = 0
				with open(retire_output, 'r') as f:
					data = json.load(f)

					# Retire.js results can be either a list of file results or a dictionary wrapper
					results_list = []
					if isinstance(data, list):
						results_list = data
					elif isinstance(data, dict):
						# Check standard Retire.js dictionary output keys
						if 'data' in data and isinstance(data['data'], list):
							results_list = data['data']
						elif 'results' in data and isinstance(data['results'], list):
							results_list = data['results']
						else:
							results_list = [data]

				for result in results_list:
					if not isinstance(result, dict):
						continue
					for component in result.get('results', []):
						if not isinstance(component, dict):
							continue
						for vuln in component.get('vulnerabilities', []):
							if not isinstance(vuln, dict):
								continue
							vuln_data = parse_retire_result({
								'component': component.get('component'),
								'version': component.get('version'),
								'info': vuln.get('info'),
								'file': result.get('file')
							})
							save_vulnerability(vuln_data, self.scan, self.domain)
							retire_vulns += 1
				logger.warning('[WEB_API] Retire.js: %d vulnerabilities saved', retire_vulns)
			except Exception as e:
				logger.error('[WEB_API] Retire.js: error parsing output: %s', e)
		else:
			logger.warning('[WEB_API] Retire.js: output file not found — may have failed silently')
	else:
		logger.warning('[WEB_API] Retire.js: skipped (not in uses_tools)')

	# Aquatone - visual inspection of discovered URLs
	if 'aquatone' in uses_tools and urls:
		aquatone_out = f"{results_dir}/aquatone"
		os.makedirs(aquatone_out, exist_ok=True)
		targets_file = f"{aquatone_out}/targets.txt"
		with open(targets_file, 'w') as _f:
			_f.write('\n'.join(urls))
		cmd = f"cat {targets_file} | aquatone -out {aquatone_out} -threads {threads} -silent"
		logger.warning('[WEB_API] Aquatone: running on %d URLs | cmd: %s', len(urls), cmd)
		run_command(cmd, shell=True, cwd=aquatone_out, scan_id=self.scan_id, activity_id=self.activity_id)
		logger.warning('[WEB_API] Aquatone: finished')
	elif 'aquatone' in uses_tools:
		logger.warning('[WEB_API] Aquatone: skipped (no URLs)')

	# Sync to Graph
	if Neo4jManager:
		logger.warning('[WEB_API] Syncing results to Neo4j graph...')
		nm = Neo4jManager()
		nm.sync_scan_results(self.scan_id)
		nm.close()
		logger.warning('[WEB_API] Neo4j sync complete')

	# Trigger Intelligent Auth Candidate Extraction
	logger.warning('[WEB_API] Running auth candidate extraction...')
	from reNgine.auth_discovery_tasks import extract_auth_candidates
	extract_auth_candidates(self, ctx=ctx)
	logger.warning('[WEB_API] Web API Discovery complete | scan_id=%s', scan_id)


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

		# Update subdomain status attributes if this is the default endpoint
		if endpoint.is_default and subdomain:
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


#---------------------#
# Notifications tasks #
#---------------------#

#-------------#
# Utils tasks #
#-------------#

