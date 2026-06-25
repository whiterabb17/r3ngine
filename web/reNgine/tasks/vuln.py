import logging
import os
import json
import yaml
import concurrent.futures
from pathlib import Path

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.utils.opsec import OpSecManager, ProxychainsWrapper, get_opsec_manager
from reNgine.utils.task import run_command, run_command_with_retry, stream_command, activity_heartbeat_safe, save_endpoint
from reNgine.tech_mapping import get_nuclei_tags_from_techs
from reNgine.tasks.parsers import parse_nuclei_result, parse_dalfox_result, parse_crlfuzz_result
from reNgine.tasks.llm import get_vulnerability_gpt_report, add_gpt_description_db
from startScan.models import *
from scanEngine.models import Proxy

logger = logging.getLogger(__name__)

def vulnerability_scan(self, urls=[], ctx={}, description=None):
	"""This task serves as the entrypoint for vulnerability scans, spawning all enabled scanners.

	Args:
		urls (list): Target URLs to scan.
		ctx (dict): Scan context.
		description (str): Task description.
	"""
	logger.info('Running Vulnerability Scan Queue')
	config = self.yaml_configuration
	
	# Note: vulnerability_scan is bypassed by RunVulnerabilityScanActivity in Temporal.
	# This path handles any direct calls by dispatching each scanner sequentially.
	vuln_config = config.get(VULNERABILITY_SCAN) or {}
	from reNgine.definitions import RUN_NUCLEI, RUN_CRLFUZZ, RUN_DALFOX, RUN_S3SCANNER, RUN_ACUNETIX, RUN_WPSCAN, RUN_CPANEL2SHELL, RUN_REACT2SHELL
	from reNgine.vulnerability_tasks import cpanel_scan, react2shell_scan
	from reNgine.wpscan_tasks import wpscan_scan

	if vuln_config.get(RUN_NUCLEI, True):
		nuclei_scan(self, urls=urls, ctx=ctx, description='Nuclei Scan')
	if vuln_config.get(RUN_CRLFUZZ, False):
		crlfuzz_scan(self, urls=urls, ctx=ctx, description='CRLFuzz Scan')
	if vuln_config.get(RUN_DALFOX, False):
		dalfox_xss_scan(self, urls=urls, ctx=ctx, description='Dalfox XSS Scan')
	if vuln_config.get(RUN_S3SCANNER, True):
		s3scanner(self, ctx=ctx, description='S3 Bucket Scanner')
	if vuln_config.get(RUN_ACUNETIX, False):
		from dashboard.models import AcunetixAPIKey
		creds = AcunetixAPIKey.objects.first()
		if creds and creds.server_url and creds.api_key:
			acunetix_scan(self, domain_id=ctx.get('domain_id'), scan_history_id=ctx.get('scan_history_id'), ctx=ctx)
	cpanel_cfg = vuln_config.get('cpanel_scanner', {})
	if cpanel_cfg.get(RUN_CPANEL2SHELL, True):
		cpanel_scan(self, ctx=ctx, description='cPanel Vulnerability Scan')
	if vuln_config.get(RUN_WPSCAN, True):
		wpscan_scan(self, urls=urls, ctx=ctx, description='WPScan')
	react_cfg = vuln_config.get('react_scanner', {})
	if react_cfg.get(RUN_REACT2SHELL, True):
		react2shell_scan(self, ctx=ctx, description='React Vulnerability Scan')
	semgrep_scan(self, ctx=ctx, mode='vulnerability', description='Semgrep Vulnerability Scan')
	logger.info("Primary vulnerability scan tasks (Stage 1) completed.")
	logger.info("Additional vulnerability scan tasks (Stage 2) completed.")

	logger.info('Vulnerability scan completed...')
	return None






def nuclei_scan(self, urls=[], ctx={}, description=None, prepare_only=False, parse_only=None, severity=None, tags_override=None, proxies_file_path=None):
	"""HTTP vulnerability scan using Nuclei

	Args:
		urls (list, optional): List of HTTP URLs to scan.
		ctx (dict, optional): Task execution context dictionary containing settings.
		description (str, optional): Task description shown in the UI activity.
		prepare_only (bool, optional): If True, only write target files and skip tool run.
		parse_only (str, optional): Path to output file to parse results from.
		severity (str, optional): Nuclei severity to scan (e.g. info, low, medium, high, critical).

	Notes:
	Unfurl the urls to keep only domain and path, will be sent to vuln scan and
	ignore certain file extensions. Thanks: https://github.com/six2dez/reconftw
	"""
	# Config
	config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	severity_filter = severity or ctx.get('nuclei_severity_filter')
	severity_suffix = f"_{severity_filter}" if severity_filter else ""
	input_path = f'{self.results_dir}/input_endpoints_vulnerability_scan{severity_suffix}.txt'
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	concurrency = config.get(NUCLEI_CONCURRENCY) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
	rate_limit = config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
	# Cap concurrency and rate when routing through a proxy file.
	# nuclei v3.9.0 AdaptiveWaitGroup deadlocks at high concurrency under proxy
	# error rates of 60%+. See: scan 37 post-mortem / nuclei-stacktrace-*.dump.
	if proxies_file_path and os.path.exists(proxies_file_path):
		if concurrency > NUCLEI_PROXY_MAX_CONCURRENCY:
			logger.warning(
				'nuclei proxy mode: capping concurrency %s -> %s to prevent semaphore deadlock',
				concurrency, NUCLEI_PROXY_MAX_CONCURRENCY,
			)
			concurrency = NUCLEI_PROXY_MAX_CONCURRENCY
		if rate_limit > NUCLEI_PROXY_MAX_RATE_LIMIT:
			logger.warning(
				'nuclei proxy mode: capping rate_limit %s -> %s req/s',
				rate_limit, NUCLEI_PROXY_MAX_RATE_LIMIT,
			)
			rate_limit = NUCLEI_PROXY_MAX_RATE_LIMIT
	retries = config.get(RETRIES) or self.yaml_configuration.get(RETRIES, DEFAULT_RETRIES)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
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
	should_fetch_gpt_report = config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	nuclei_specific_config = config.get('nuclei', {})
	use_nuclei_conf = nuclei_specific_config.get(USE_NUCLEI_CONFIG, False)
	auto_update_templates = nuclei_specific_config.get('auto_update_templates', True)
	if severity_filter:
		severities = [severity_filter]
	else:
		severities = nuclei_specific_config.get(NUCLEI_SEVERITY, NUCLEI_DEFAULT_SEVERITIES)
	if tags_override is not None:
		# Tags were pre-computed and batched by NucleiPlannerWorkflow via
		# GatherNucleiTagsActivity.  Use them directly; skip the tech-detection
		# block so we don't re-query the DB on every batch call.
		tags = ','.join(tags_override) if tags_override else ''
		all_techs = set()
	else:
		tags = nuclei_specific_config.get(NUCLEI_TAGS, [])

		# Intelligence-Driven Scanning: Inject tags based on detected technologies
		tech_tags = []
		all_techs = set()
		if self.scan:
			# Get all technologies discovered for this scan
			subdomains = Subdomain.objects.filter(scan_history=self.scan)
			all_techs = set()
			for sub in subdomains:
				# assuming technologies is a many-to-many field with 'name' attribute
				all_techs.update(sub.technologies.values_list('name', flat=True))

			if all_techs:
				tech_tags = get_nuclei_tags_from_techs(list(all_techs))
				logger.info('Detected technologies: %s. Adding targeted Nuclei tags: %s', list(all_techs), tech_tags)

		if tech_tags:
			# Combine user tags with tech tags
			from reNgine.nuclei_batch_utils import build_tag_batches
			user_tags = set(tags if isinstance(tags, list) else tags.split(',') if tags else [])
			user_tags.update(tech_tags)
			all_combined = sorted(user_tags)
			batches = build_tag_batches(all_combined, {}, max_tags=3)
			if len(batches) > 1:
				logger.warning(
					'nuclei_scan: %d tags detected outside Temporal batching; '
					'running first batch of %d only. Use NucleiPlannerWorkflow for full coverage.',
					len(all_combined), len(batches[0]),
				)
			tags = ','.join(batches[0]) if batches else ''
		else:
			tags = ','.join(tags) if isinstance(tags, list) else tags

	nuclei_templates = nuclei_specific_config.get(NUCLEI_TEMPLATE)
	custom_nuclei_templates = nuclei_specific_config.get(NUCLEI_CUSTOM_TEMPLATE)
	severities_str = ','.join(severities)

	# Collect all URLs: DB endpoints (no alive-only filter) + spidering result files
	if urls:
		combined = list(set(urls))
	else:
		combined = collect_all_scan_urls(
			ctx=ctx,
			results_dir=self.results_dir,
			ignore_files=True,
		)
	with open(input_path, 'w') as f:
		f.write('\n'.join(combined))

	if intensity == 'normal': # reduce number of endpoints to scan
		unfurl_filter = f'{self.results_dir}/urls_unfurled{severity_suffix}.txt'
		run_command(
			f"cat {input_path} | unfurl -u format %s://%d%p |uro > {unfurl_filter}",
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		run_command(
			f'sort -u {unfurl_filter} -o  {unfurl_filter}',
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		if os.path.isfile(unfurl_filter) and os.path.getsize(unfurl_filter) > 0:
			input_path = unfurl_filter
		else:
			logger.warning('nuclei_scan: unfurl produced no output, using original endpoint list.')

	# Build templates
	logger.info('Updating Nuclei templates ...')
	# Wordfence Templates integration — 70k+ WordPress CVE templates, daily-updated
	# When tags_override is used, all_techs is empty; check the batch tags instead.
	if tags_override is not None:
		is_wordpress_detected = any(
			'wordpress' in t.lower() or 'wp-' in t.lower()
			for t in (tags_override or [])
		)
	else:
		is_wordpress_detected = any(
			'wordpress' in t.lower() or 'wp-' in t.lower()
			for t in all_techs
		) if all_techs else False
	wordfence_exists = False
	if is_wordpress_detected:
		wordfence_dir = '/root/nuclei-templates/wordfence'
		if os.path.isdir(wordfence_dir) and os.listdir(wordfence_dir):
			logger.info('WordPress detected; Wordfence templates present at %s', wordfence_dir)
			wordfence_exists = True
		else:
			logger.warning(
				'WordPress detected but Wordfence templates missing at %s; '
				'templates should be pre-loaded at container startup', wordfence_dir
			)

	if auto_update_templates:
		run_command(
			'nuclei -update-templates',
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
	templates = []
	if not (nuclei_templates or custom_nuclei_templates):
		templates.append(NUCLEI_DEFAULT_TEMPLATES_PATH)

	if nuclei_templates:
		if ALL in nuclei_templates:
			template = NUCLEI_DEFAULT_TEMPLATES_PATH
			templates.append(template)
		else:
			templates.extend(nuclei_templates)

	if custom_nuclei_templates:
		custom_nuclei_template_paths = []
		for elem in custom_nuclei_templates:
			if str(elem).endswith(('.yaml', '.yml')) or str(elem).endswith('/'):
				custom_nuclei_template_paths.append(str(elem))
			else:
				custom_nuclei_template_paths.append(f'{str(elem)}.yaml')
		templates.extend(custom_nuclei_template_paths)

	# Build CMD
	cmd = 'nuclei -j -hang-monitor -stats'
	cmd += ' -config /root/.config/nuclei/config.yaml' if use_nuclei_conf else ''
	cmd += f' -irr'

	# Apply OpSec stealth
	proxy = get_random_proxy()
	opsec = get_opsec_manager()
	cmd = opsec.apply_stealth('nuclei', cmd, proxy=proxy)
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += f' {formatted_headers}'
	cmd += f' '
	
	if proxies_file_path and os.path.exists(proxies_file_path):
		cmd += f' -proxy {proxies_file_path}'
	elif proxy:
		cmd += f' -proxy {proxy}' 
	cmd += f' -l {input_path}'
	cmd += f' -c {str(concurrency)}' if concurrency > 0 else ''

	cmd += f' -retries {retries}' if retries > 0 else ''
	cmd += f' -rl {rate_limit}' if rate_limit > 0 else ''
	if severities_str:
		cmd += f' -severity {severities_str}'
	#cmd += f' -timeout {str(timeout)}' if timeout and timeout > 0 else ''
	if tags:
		cmd += f" -tags '{tags}'"
	#cmd += f' -silent'
	for tpl in templates:
		cmd += f' -t {tpl}'
	
	if is_wordpress_detected and wordfence_exists:
		# Wordfence templates live at /root/nuclei-templates/wordfence — already included
		# in the default -t /root/nuclei-templates recursive scan; no extra -t needed.
		logger.info(f'[nuclei] WordPress detected; Wordfence templates active at /root/nuclei-templates/wordfence')
	logger.info("Running Nuclei vulnerabilities scan")
	if hasattr(self, 'activity') and self.activity:
		self.activity.title = "Nuclei Scan"
		self.activity.save()
	
	logger.warning(f'cmd: {cmd}')
	
	results = []
	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	import json
	line_source = stream_command(
		cmd,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	for line in line_source:
		if not isinstance(line, dict):
			continue

		results.append(line)

		# Gather nuclei results
		vuln_data = parse_nuclei_result(line)

		# Get corresponding subdomain
		http_url = sanitize_url(line.get('matched-at'))
		subdomain_name = get_subdomain_from_url(http_url)

		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		if not subdomain:
			continue

		severity_value = line['info'].get('severity', 'unknown')

		# Get or create EndPoint object
		response = line.get('response')
		httpx_crawl = False if response else enable_http_crawl # avoid yet another httpx crawl
		endpoint, _ = save_endpoint(
			http_url,
			crawl=httpx_crawl,
			subdomain=subdomain,
			ctx=ctx)
		if endpoint:
			http_url = endpoint.http_url
			if not httpx_crawl:
				output = parse_curl_output(response)
				endpoint.http_status = output['http_status']
				endpoint.save()

		# Register Auth Candidate if Nuclei flagged it as login or auth
		tags_list = line.get('info', {}).get('tags', []) or []
		if any(tag in tags_list for tag in ['login', 'auth', 'admin', 'default-login', 'bruteforce', 'panel']):
			from reNgine.utilities import save_auth_candidate
			save_auth_candidate(
				scan_history=self.scan,
				target=http_url,
				protocol='http',
				port=int(urlparse(http_url).port or (443 if 'https' in http_url else 80)),
				source_tool='Nuclei',
				metadata={'tags': tags_list, 'template_id': line.get('template-id')},
				subdomain=subdomain,
				endpoint=endpoint
			)

		# Get or create Vulnerability object
		vuln, created = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			subdomain=subdomain,
			**vuln_data)
		if not vuln or not created:
			continue

		# Print vuln
		logger.warning(str(vuln))

		# Send notification for all vulnerabilities except info
		url = vuln.http_url or vuln.subdomain
		send_vuln = (
			notif and
			notif.send_vuln_notif and
			vuln and
			severity_value in ['low', 'medium', 'high', 'critical'])
		if send_vuln:
			fields = {
				'Severity': f'**{severity_value.upper()}**',
				'URL': http_url,
				'Subdomain': subdomain_name,
				'Name': vuln.name,
				'Type': vuln.type,
				'Description': vuln.description,
				'Template': vuln.template_url,
				'Tags': vuln.get_tags_str() or "N/A",
				'CVEs': vuln.get_cve_str(),
				'CWEs': vuln.get_cwe_str(),
				'References': vuln.get_refs_str()
			}
			severity_map = {
				'low': 'info',
				'medium': 'warning',
				'high': 'error',
				'critical': 'error'
			}
			self.notify(
				f'vulnerability_scan_#{vuln.id}',
				severity_map[severity_value],
				fields,
				add_meta_info=False)

		# Send report to hackerone
		hackerone_query = Hackerone.objects.filter(send_report=True)
		api_key_check_query = HackerOneAPIKey.objects.filter(
			Q(username__isnull=False) & Q(key__isnull=False)
		)

		send_report = (
			hackerone_query.exists() and
			api_key_check_query.exists() and
			severity_value not in ('info', 'low') and
			vuln.target_domain.h1_team_handle
		)

		if send_report:
			hackerone = hackerone_query.first()
			try:
				if hackerone.send_critical and severity_value == 'critical':
					send_hackerone_report(vuln.id)
				elif hackerone.send_high and severity_value == 'high':
					send_hackerone_report(vuln.id)
				elif hackerone.send_medium and severity_value == 'medium':
					send_hackerone_report(vuln.id)
			except Exception as e:
				logger.warning(f"HackerOne report send failed for vuln {vuln.id}: {e}")

	# Write results to JSON file
	with open(self.output_path, 'w') as f:
		json.dump(results, f, indent=4)

	# Send finish notif
	if send_status:
		vulns = Vulnerability.objects.filter(scan_history__id=self.scan_id)
		info_count = vulns.filter(severity=0).count()
		low_count = vulns.filter(severity=1).count()
		medium_count = vulns.filter(severity=2).count()
		high_count = vulns.filter(severity=3).count()
		critical_count = vulns.filter(severity=4).count()
		unknown_count = vulns.filter(severity=-1).count()
		vulnerability_count = info_count + low_count + medium_count + high_count + critical_count + unknown_count
		fields = {
			'Total': vulnerability_count,
			'Critical': critical_count,
			'High': high_count,
			'Medium': medium_count,
			'Low': low_count,
			'Info': info_count,
			'Unknown': unknown_count
		}
		self.notify(fields=fields)

	if should_fetch_gpt_report and OpenAiAPIKey.objects.all().first():
		logger.info('Getting Vulnerability GPT Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=NUCLEI
		).exclude(
			severity=0
		)
		unique_vulns = set()
		for vuln in vulns:
			unique_vulns.add((vuln.name, vuln.get_path()))

		unique_vulns = list(unique_vulns)

		with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in unique_vulns}
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {gpt}: {e}")

	logger.info('Vulnerability scan completed...')
	return None

def dalfox_xss_scan(self, urls=[], ctx={}, description=None):
	"""XSS Scan using dalfox

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.
	"""
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_fetch_gpt_report = vuln_config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	dalfox_config = vuln_config.get(DALFOX) or {}
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
	is_waf_evasion = dalfox_config.get(WAF_EVASION, False)
	use_deep_scan = dalfox_config.get('DEEP_SCAN', False)
	use_remote_payloads = dalfox_config.get('REMOTE_PAYLOADS', False)
	use_remote_wordlists = dalfox_config.get('REMOTE_WORDLISTS', False)
	scan_timeout = dalfox_config.get('SCAN_TIMEOUT', 300)
	blind_xss_server = dalfox_config.get(BLIND_XSS_SERVER)
	user_agent = dalfox_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
	timeout = dalfox_config.get(TIMEOUT)
	delay = dalfox_config.get(DELAY)
	threads = dalfox_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	input_path = f'{self.results_dir}/input_endpoints_dalfox_xss.txt'

	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=False,
			ignore_files=False,
			write_filepath=input_path,
			ctx=ctx
		)

	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	# command builder
	proxy = get_random_proxy()
	opsec = get_opsec_manager()
	cmd = 'dalfox scan --no-color'
	cmd += f' --only-poc v,r'
	cmd += f' --ignore-return 302,404,403'
	
	cmd = opsec.apply_stealth('dalfox', cmd, proxy=proxy)
	cmd += f' file {input_path}'
	cmd += f' --proxy {proxy}' if proxy and '--proxy' not in cmd else ''
	cmd += f' --waf-evasion' if is_waf_evasion else ''
	cmd += f' --waf-bypass auto'
	cmd += f' --deep-scan' if use_deep_scan else ''
	cmd += f' --remote-payloads portswigger,payloadbox' if use_remote_payloads else ''
	cmd += f' --remote-wordlists burp,assetnote' if use_remote_wordlists else ''
	cmd += f' -b {blind_xss_server}' if blind_xss_server else ''
	cmd += f' --delay {delay}' if delay else ''
	cmd += f' --timeout {timeout}' if timeout else ''
	cmd += f' --scan-timeout {scan_timeout}' if scan_timeout else ''
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += f' {formatted_headers}'
	cmd += f' --user-agent {user_agent}' if user_agent else ''
	cmd += f' --workers {threads}' if threads else ''
	cmd += f' --format json'

	results = []
	for line in stream_command(
			cmd,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id,
			trunc_char=','
		):
		if not isinstance(line, dict):
			continue

		results.append(line)

		vuln_data = parse_dalfox_result(line)

		http_url = sanitize_url(line.get('data'))
		subdomain_name = get_subdomain_from_url(http_url)

		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		if not subdomain:
			continue
		endpoint, _ = save_endpoint(
			http_url,
			crawl=False,
			subdomain=subdomain,
			ctx=ctx
		)
		if endpoint:
			http_url = endpoint.http_url
			endpoint.save()

		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			**vuln_data
		)

		if not vuln:
			continue

	# after vulnerability scan is done, we need to run gpt if
	# should_fetch_gpt_report and openapi key exists

	if should_fetch_gpt_report and OpenAiAPIKey.objects.all().first():
		logger.info('Getting Dalfox Vulnerability GPT Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=DALFOX
		).exclude(
			severity=0
		)

		_vulns = []
		for vuln in vulns:
			_vulns.append((vuln.name, vuln.http_url))

		with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in _vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {gpt}: {e}")
	return results


def crlfuzz_scan(self, urls=[], ctx={}, description=None):
	"""CRLF Fuzzing with CRLFuzz

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.
	"""
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_fetch_gpt_report = vuln_config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
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
	user_agent = vuln_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
	threads = vuln_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	input_path = f'{self.results_dir}/input_endpoints_crlf.txt'
	output_path = f'{self.results_dir}/{self.filename}'

	urls = [u for u in urls if u and u.strip()]

	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=False,
			ignore_files=True,
			write_filepath=input_path,
			ctx=ctx
		)

	if not os.path.isfile(input_path) or os.path.getsize(input_path) == 0:
		logger.warning('crlfuzz: no endpoints to scan at %s, skipping.', input_path)
		return

	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	# command builder
	proxy = get_random_proxy()
	cmd = 'crlfuzz ' # -s
	cmd += f' -l {input_path}'
	cmd += f' -x {proxy}' if proxy else ''
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += f' {formatted_headers}'
	cmd += f' -o {output_path}'

	run_command(
		cmd,
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id
	)

	if not os.path.isfile(output_path):
		logger.info('No Results from CRLFuzz')
		return

	crlfs = []
	results = []
	with open(output_path, 'r') as file:
		crlfs = file.readlines()

	for crlf in crlfs:
		url = crlf.strip()
		if not url:
			continue

		vuln_data = parse_crlfuzz_result(url)

		http_url = sanitize_url(url)
		subdomain_name = get_subdomain_from_url(http_url)

		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		if not subdomain:
			continue

		endpoint, _ = save_endpoint(
			http_url,
			crawl=False,
			subdomain=subdomain,
			ctx=ctx
		)
		if endpoint:
			http_url = endpoint.http_url
			endpoint.save()

		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			**vuln_data
		)

		if not vuln:
			continue

	# after vulnerability scan is done, we need to run gpt if
	# should_fetch_gpt_report and openapi key exists

	if should_fetch_gpt_report and OpenAiAPIKey.objects.all().first():
		logger.info('Getting CRLFuzz Vulnerability GPT Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=CRLFUZZ
		).exclude(
			severity=0
		)

		_vulns = []
		for vuln in vulns:
			_vulns.append((vuln.name, vuln.http_url))

		with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in _vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {gpt}: {e}")

	return results


def s3scanner(self, ctx={}, description=None):
	"""Bucket Scanner

	Args:
		ctx (dict): Context
		description (str, optional): Task description shown in UI.
	"""
	input_path = f'{self.results_dir}/subdomain_discovery.txt'
	if not os.path.isfile(input_path):
		logger.warning(f's3scanner: subdomain list not found at {input_path}, skipping.')
		return
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	s3_config = vuln_config.get(S3SCANNER) or {}
	threads = s3_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	providers = s3_config.get(PROVIDERS, S3SCANNER_DEFAULT_PROVIDERS)
	scan_history = ScanHistory.objects.filter(pk=self.scan_id).first()
	for provider in providers:
		cmd = f's3scanner -bucket-file {input_path} -enumerate -provider {provider} -threads {threads} -json'
		for line in stream_command(
				cmd,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id):

			if not isinstance(line, dict):
				continue

			if line.get('bucket', {}).get('exists', 0) == 1:
				result = parse_s3scanner_result(line)
				s3bucket, created = S3Bucket.objects.get_or_create(**result)
				scan_history.buckets.add(s3bucket)
				logger.info(f"s3 bucket added {result['provider']}-{result['name']}-{result['region']}")


