import logging
import os
import json
import yaml
import concurrent.futures
from pathlib import Path

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.utils.opsec import OpSecManager, ProxychainsWrapper, get_opsec_manager
from reNgine.utils.task import run_command, run_command_with_retry, stream_command, activity_heartbeat_safe, save_endpoint, save_subdomain
from reNgine.tech_mapping import get_nuclei_tags_from_techs
from reNgine.tasks.parsers import parse_nuclei_result, parse_dalfox_result, parse_crlfuzz_result, parse_s3scanner_result
from reNgine.tasks.llm import get_vulnerability_gpt_report, add_gpt_description_db
from reNgine.tasks.crawl import parse_curl_output
from reNgine.tasks.notifications import send_hackerone_report
from reNgine.tasks.acunetix import acunetix_scan
from reNgine.tasks.vulnerability import cpanel_scan, react2shell_scan
from reNgine.tasks.wpscan import wpscan_scan
from reNgine.nuclei_batch_utils import build_tag_batches
from startScan.models import *
from scanEngine.models import Proxy

logger = logging.getLogger(__name__)

# Merged second-order config — covers takeover, CDN, JS, parameter, and title detection.
# Written to disk before each scan run so we never depend on a GitHub download.
_SECOND_ORDER_MERGED_CONFIG: dict = {
    # Non-200 external URLs — primary takeover/hijacking signal (HIGH severity)
    "LogNon200Queries": [
        "img[src]", "script[src]", "link[href]", "form[action]",
        "iframe[src]", "a[href]", "object[data]", "source[src]",
        "frame[src]", "embed[src]", "area[href]", "base[href]",
    ],
    # All external attribute references — recon / SSRF vector discovery (INFO)
    "LogQueries": [
        "img[src]", "script[src]", "link[href]", "form[action]",
        "input[name]", "input[value]", "meta[content]", "meta[name]",
        "iframe[src]", "a[href]", "object[data]", "source[src]",
        "frame[src]", "embed[src]", "area[href]", "base[href]",
    ],
    # Inline content — JS and title analysis (INFO)
    "LogInline": ["script", "title", "noscript", "style"],
    "Headers": {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    },
}

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
	
	if vuln_config.get('run_smugglex', True):
		smugglex_scan(self, urls=urls, ctx=ctx, description='Smugglex Scan')
	if vuln_config.get('run_second_order', True):
		second_order_scan(self, urls=urls, ctx=ctx, description='Second Order Scan')
	if vuln_config.get('run_nuclei_dast', True):
		nuclei_dast_scan(self, urls=urls, ctx=ctx, description='Nuclei DAST Scan')
		
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

		# Re-run the tag splitter because updating templates overwrites the split tags on disk
		# splitter_script = '/usr/src/app/scripts/nuclei_tag_splitter.py'
		# import sys
		# run_command(
		# 	f'{sys.executable} {splitter_script}',
		# 	shell=True,
		# 	history_file=self.history_file,
		# 	scan_id=self.scan_id,
		# 	activity_id=self.activity_id)
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
	proxy_obj = Proxy.objects.first()
	proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
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
	proxy_obj = Proxy.objects.first()
	proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
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
	proxy_obj = Proxy.objects.first()
	proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
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


def sync_cisa_kev_catalog():
	"""
	Syncs CISA KEV catalog and updates CVE records.
	"""
	import requests
	from startScan.models import CveId
	url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	try:
		response = requests.get(url, timeout=30)
		if response.status_code == 200:
			data = response.json()
			cve_list = [v.get("cveID") for v in data.get("vulnerabilities", [])]
			if cve_list:
				CveId.objects.filter(name__in=cve_list).update(is_cisa_kev=True)
				logger.info(f"Successfully synced CISA KEV catalog. Updated {len(cve_list)} records.")
	except Exception as e:
		logger.error(f"Error syncing CISA KEV catalog: {e}")


def sync_semgrep_rules():
	"""
	Synchronizes Semgrep rules from the public registry to the local filesystem.
	Runs at system startup and can be triggered manually.
	"""
	rules_dir = "/usr/src/github/semgrep_rules"
	if not os.path.exists(rules_dir):
		os.makedirs(rules_dir, exist_ok=True)
	
	# Rule sets to sync
	rule_sets = {
		"p/secrets": "secrets.yaml",
		"p/owasp-top-ten": "owasp-top-10.yaml",
		"p/ci": "ci.yaml",
		"p/javascript": "javascript.yaml",
		"p/python": "python.yaml"
	}
	
	for config, filename in rule_sets.items():
		target_path = os.path.join(rules_dir, filename)
		url = f"https://semgrep.dev/c/{config}"
		try:
			logger.info(f"Syncing Semgrep rule set: {config} -> {filename}")
			response = requests.get(url, timeout=60)
			if response.status_code == 200:
				with open(target_path, 'wb') as f:
					f.write(response.content)
				logger.info(f"Successfully synced Semgrep rule set: {config}")
			else:
				logger.error(f"Failed to download Semgrep rule set {config}: HTTP {response.status_code}")
		except Exception as e:
			logger.error(f"Failed to sync Semgrep rule set {config}: {e}")


def clean_and_validate_url(url, base_domain=None):
	"""Cleans and validates a URL by stripping metadata and enforcing domain matching.

	Args:
		url (str): The raw URL string to clean and validate.
		base_domain (str, optional): The target domain name to scope check against.

	Returns:
		str: The cleaned, fully qualified URL, or None if invalid/out-of-scope.
	"""
	from urllib.parse import urlparse
	
	url = url.strip()
	if not url:
		return None

	# Strip any trailing metadata often present in raw discovery tool outputs
	# (e.g. "url] - metadata", "url [javascript]", "url - text/html")
	if ' ' in url:
		parts = url.split()
		# Find the first part that looks like a URL or relative path
		for p in parts:
			if p.startswith('http://') or p.startswith('https://') or p.startswith('//') or '/' in p:
				url = p
				break
		else:
			url = parts[0]

	# Extract only the URL content before any trailing brackets or brackets metadata
	url = url.split(']')[0].split('[')[0].strip()

	if not url:
		return None

	# Normalize the scheme
	parsed = urlparse(url)
	if not parsed.scheme:
		if base_domain:
			if url.startswith('//'):
				url = f"https:{url}"
			else:
				url = f"https://{base_domain}/{url.lstrip('/')}"
		else:
			url = f"https://{url.lstrip('/')}"
		parsed = urlparse(url)

	hostname = parsed.hostname
	if not hostname:
		return None

	# Filter out external/third-party domains to maintain strict scan scoping
	if base_domain:
		base_domain_lower = base_domain.lower()
		hostname_lower = hostname.lower()
		if not (hostname_lower == base_domain_lower or hostname_lower.endswith('.' + base_domain_lower)):
			return None

	# Ensure it is a valid HTTP/HTTPS protocol URL
	if not (url.startswith('http://') or url.startswith('https://')):
		return None

	return url


def semgrep_scan(self, ctx={}, mode='vulnerability', description=None):
	"""
	Runs Semgrep static analysis on fetched files.
	mode: 'secret' or 'vulnerability'
	"""
	scan_id = ctx.get('scan_history_id')
	results_dir = ctx.get('results_dir')

	logger.warning("[SEMGREP] Starting %s scan | scan_id=%s", mode, scan_id)

	if not results_dir:
		logger.error("Results directory not provided. Semgrep scan aborted.")
		return

	# Create a directory for Semgrep to scan
	semgrep_dir = os.path.join(results_dir, f'semgrep_{mode}_temp')
	os.makedirs(semgrep_dir, exist_ok=True)

	# But to be robust, we'll download files ourselves if the directory is empty
	SENSITIVE_EXTENSIONS = ('.js', '.env', '.php', '.asp', '.aspx', '.jsp', '.jspx', '.txt', '.log', '.conf', '.config', '.bak', '.old', '.json', '.yaml', '.yml', '.html', '.htm')

	# Load URLs from fetch_url output files and tool-specific files
	urls_from_files = set()
	if os.path.exists(results_dir):
		for f in os.listdir(results_dir):
			if f.endswith('_fetch_url.txt') or (f.startswith('urls_') and f.endswith('.txt')):
				fpath = os.path.join(results_dir, f)
				try:
					with open(fpath, 'r', encoding='utf-8', errors='ignore') as f_in:
						for line in f_in:
							url_str = line.strip()
							if url_str:
								urls_from_files.add(url_str)
					logger.warning("[SEMGREP] Loaded %d URLs from file: %s", len(urls_from_files), fpath)
				except Exception as e:
					logger.error("[SEMGREP] Failed to read file %s: %s", fpath, e)

	endpoints = EndPoint.objects.filter(scan_history_id=scan_id)
	endpoint_urls = set(e.http_url for e in endpoints if e.http_url)
	logger.warning("[SEMGREP] Sources: %d endpoint URLs from DB, %d URLs from result files", len(endpoint_urls), len(urls_from_files))
	all_urls = endpoint_urls | urls_from_files
	logger.warning("[SEMGREP] Total combined URLs before extension filter: %d", len(all_urls))

	# Filter sensitive URLs robustly by parsing their path component
	target_urls = []
	for url in all_urls:
		try:
			path = urlparse(url).path.lower()
			if path.endswith(SENSITIVE_EXTENSIONS):
				target_urls.append(url)
		except Exception:
			if url.lower().endswith(SENSITIVE_EXTENSIONS):
				target_urls.append(url)

	logger.warning("[SEMGREP] URLs matching sensitive extensions: %d", len(target_urls))

	if not target_urls:
		logger.warning("[SEMGREP] No target files found for %s scan — aborting.", mode)
		return

	# Retrieve proxies configuration from database
	available_proxies = []
	use_proxy = False

	try:
		if Proxy.objects.all().exists():
			proxy_config = Proxy.objects.first()
			if proxy_config.use_proxy:
				use_proxy = True
				available_proxies = [p.strip() for p in proxy_config.proxies.splitlines() if p.strip()]
				# Shuffle the proxies to distribute traffic randomly
				random.shuffle(available_proxies)
				logger.warning("[SEMGREP] Proxy enabled with %d available proxies", len(available_proxies))
			else:
				logger.warning("[SEMGREP] Proxy configured but disabled — running direct")
	except Exception as e:
		logger.error("[SEMGREP] Failed to load proxies configuration: %s", e)

	# Convert custom headers list to dictionary
	headers_dict = {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	for h in custom_headers:
		if ':' in h:
			k, v = h.split(':', 1)
			headers_dict[k.strip()] = v.strip()
	if 'User-Agent' not in headers_dict:
		headers_dict['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

	base_domain = self.domain.name if self.domain else None

	# Clean, validate, and deduplicate all URLs
	unique_targets = set()
	invalid_count = 0
	for url in target_urls:
		clean_url = clean_and_validate_url(url, base_domain)
		if clean_url:
			unique_targets.add(clean_url)
		else:
			invalid_count += 1
	unique_targets = list(unique_targets)
	logger.warning("[SEMGREP] After clean/dedup: %d valid unique targets (%d dropped as invalid/out-of-scope)", len(unique_targets), invalid_count)

	# Cap the maximum files to scan to prevent infinite stalls on huge targets
	MAX_SEMGREP_FILES = 500
	if len(unique_targets) > MAX_SEMGREP_FILES:
		logger.warning("[SEMGREP] Capping target URLs from %d to %d to prevent stalling.", len(unique_targets), MAX_SEMGREP_FILES)
		unique_targets = unique_targets[:MAX_SEMGREP_FILES]
	else:
		logger.warning("[SEMGREP] Target URL count %d is within cap limit (%d) — no capping applied.", len(unique_targets), MAX_SEMGREP_FILES)

	downloaded_count = 0

	# Define download worker function
	def download_file(full_url):
		# Create a safe filename from URL
		safe_name = "".join([c if c.isalnum() else "_" for c in full_url])
		ext = os.path.splitext(urlparse(full_url).path)[1]
		if not ext:
			ext = ".js"
		filename = f"{safe_name}{ext}"
		filepath = os.path.join(semgrep_dir, filename)

		if os.path.exists(filepath):
			return True, filepath # Already downloaded

		logger.warning("[SEMGREP] Downloading file: %s", full_url)

		# Try downloading the URL, with proxy cycling on failure (capped at max 5 to prevent stalls)
		max_retries = min(5, len(available_proxies)) if use_proxy and available_proxies else 1
		if max_retries < 1:
			max_retries = 1
		attempt = 0
		current_proxy_index = random.randint(0, len(available_proxies) - 1) if available_proxies else 0

		while attempt < max_retries:
			proxies = None
			current_proxy_name = None
			if use_proxy and available_proxies:
				current_proxy_name = available_proxies[current_proxy_index % len(available_proxies)]
				proxies = {
					'http': current_proxy_name,
					'https': current_proxy_name
				}

			try:
				# Stream response to enforce maximum download file size of 5MB
				resp = requests.get(full_url, headers=headers_dict, proxies=proxies, timeout=10, verify=False, stream=True)
				if resp.status_code == 200:
					content = b""
					max_bytes = 5 * 1024 * 1024  # 5MB
					for chunk in resp.iter_content(chunk_size=8192):
						if len(content) + len(chunk) > max_bytes:
							content += chunk[:max_bytes - len(content)]
							break
						content += chunk
					
					with open(filepath, 'wb') as f:
						f.write(content)
					logger.warning("[SEMGREP] Download complete: %s", full_url)
					return True, filepath
				elif resp.status_code in [407, 502, 503, 504]:
					# Proxy connection/auth issues, cycle and retry
					raise requests.exceptions.ProxyError(f"Proxy returned status code {resp.status_code}")
				else:
					logger.debug(f"Semgrep downloader got status {resp.status_code} for {full_url}")
					break
			except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
				attempt += 1
				current_proxy_index += 1
			except Exception as e:
				logger.debug(f"Semgrep downloader got non-network error for {full_url}: {e}")
				break
		return False, None

	# Execute downloads in parallel using a ThreadPoolExecutor
	file_to_url_map = {}
	if unique_targets:
		from concurrent.futures import ThreadPoolExecutor, as_completed
		logger.warning("[SEMGREP] Downloading %d files in parallel (max_workers=10)...", len(unique_targets))
		with ThreadPoolExecutor(max_workers=10) as executor:
			futures = {executor.submit(download_file, url): url for url in unique_targets}
			for future in as_completed(futures):
				try:
					success, filepath = future.result()
					if success and filepath:
						downloaded_count += 1
						file_to_url_map[os.path.basename(filepath)] = futures[future]
				except Exception as e:
					logger.error("[SEMGREP] Error in download thread: %s", e)
		logger.warning("[SEMGREP] Download phase complete: %d / %d files downloaded successfully", downloaded_count, len(unique_targets))

	if downloaded_count == 0:
		logger.warning("[SEMGREP] No files could be downloaded — aborting %s scan.", mode)
		shutil.rmtree(semgrep_dir, ignore_errors=True)
		return

	rules_dir = "/usr/src/github/semgrep_rules"
	config_file = "owasp-top-10.yaml" if mode == 'vulnerability' else "secrets.yaml"
	rules_path = os.path.join(rules_dir, config_file)

	# Fallback if local sync failed
	if not os.path.exists(rules_path):
		logger.warning("[SEMGREP] Local rules not found at %s — falling back to remote registry.", rules_path)
		rules_path = "p/owasp-top-10" if mode == 'vulnerability' else "p/secrets"
	else:
		logger.warning("[SEMGREP] Using local rules: %s", rules_path)

	output_json = os.path.join(results_dir, f'semgrep_{mode}_{int(time.time())}.json')

	# Run Semgrep
	cmd = f"semgrep scan --config {rules_path} {semgrep_dir} --json --output {output_json} --timeout 600"
	logger.warning("[SEMGREP] Executing: %s", cmd)
	return_code, output = run_command(cmd, scan_id=scan_id)
	logger.warning("[SEMGREP] semgrep process exited with return code: %s", return_code)

	if os.path.exists(output_json):
		try:
			with open(output_json, 'r') as f:
				data = json.load(f)
				results = data.get('results', [])

				for result in results:
					if mode == 'secret':
						save_semgrep_secret_finding(result, ctx, semgrep_dir, file_to_url_map)
					else:
						save_semgrep_vulnerability_finding(result, ctx, semgrep_dir, file_to_url_map)

			logger.warning("[SEMGREP] %s scan complete — %d matches found.", mode, len(results))
		except Exception as e:
			logger.error("[SEMGREP] Error parsing output: %s", e)
	else:
		logger.warning("[SEMGREP] Output JSON not found at %s — semgrep may have failed silently.", output_json)

	# Cleanup
	shutil.rmtree(semgrep_dir, ignore_errors=True)

	return return_code


def save_semgrep_vulnerability_finding(result, ctx, base_dir, file_to_url_map=None):
	"""Saves a Semgrep finding as a Vulnerability.

	Args:
		result (dict): Semgrep finding match dictionary.
		ctx (dict): Scan context containing history and domain IDs.
		base_dir (str): Base directory path of the cloned repo.
		file_to_url_map (dict): Optional map from downloaded file basename to original URL.
	"""
	extra = result.get('extra', {})
	path = result.get('path', '')
	
	try:
		scan = ScanHistory.objects.get(id=ctx.get('scan_history_id'))
		domain = Domain.objects.get(id=ctx.get('domain_id'))
		
		check_id = result.get('check_id', '')
		# NOTE: clean_semgrep_check_id returns human-readable labels since v3.6.4; historical DB rows retain dotted-path format.
		cleaned_check_id = clean_semgrep_check_id(check_id)

		source_file = path.replace(base_dir, '').lstrip('/')
		mapped_url = file_to_url_map.get(os.path.basename(source_file)) if file_to_url_map else None
		final_url = mapped_url if mapped_url else source_file

		vuln_data = {
			'name': f"Semgrep: {cleaned_check_id}",
			'description': extra.get('message', ''),
			'severity': SEMGREP_SEVERITY_MAP.get(extra.get('severity', 'INFO'), 0),
			'http_url': final_url,
			'type': 'SAST',
			'request': f"File: {source_file}\nLine: {result.get('start', {}).get('line')}",
			'response': extra.get('lines', ''),
			'source': 'Semgrep',
		}
		save_vulnerability(vuln_data, scan_history=scan, target_domain=domain)
	except Exception as e:
		logger.error(f"Error saving Semgrep vulnerability: {e}")


def save_semgrep_secret_finding(result, ctx, base_dir, file_to_url_map=None):
	"""Saves a Semgrep finding as a SecretLeak.

	Args:
		result (dict): Semgrep finding match dictionary.
		ctx (dict): Scan context containing history and domain IDs.
		base_dir (str): Base directory path of the cloned repo.
		file_to_url_map (dict): Optional map from downloaded file basename to original URL.
	"""
	extra = result.get('extra', {})
	path = result.get('path', '')
	
	try:
		scan = ScanHistory.objects.get(id=ctx.get('scan_history_id'))
		
		check_id = result.get('check_id', '')
		# NOTE: clean_semgrep_check_id returns human-readable labels since v3.6.4; historical DB rows retain dotted-path format.
		cleaned_check_id = clean_semgrep_check_id(check_id)

		source_file = path.replace(base_dir, '').lstrip('/')
		mapped_url = file_to_url_map.get(os.path.basename(source_file)) if file_to_url_map else None
		final_url = mapped_url if mapped_url else source_file

		match_content = extra.get('lines', '').strip()

		# Filter out excessively broad generic.secrets.security.detected-facebook-oauth false positives 
		# where semgrep line extraction catches unrelated small strings (like "requires login")
		if 'detected-facebook-oauth' in cleaned_check_id and len(match_content) < 32:
			return None

		leak_data = {
			'scan_history': scan,
			'tool_name': 'Semgrep',
			'secret_type': cleaned_check_id or 'Secret',
			'source_url': final_url,
			'match_content': match_content,
			'status': 'unverified'
		}
		save_secret_leak(**leak_data)
	except Exception as e:
		logger.error(f"Error saving Semgrep secret: {e}")

def smugglex_scan(self, urls=[], ctx={}, description=None):
	"""Smugglex Scan"""
	from reNgine.common_func import save_vulnerability, get_http_urls, sanitize_url, get_subdomain_from_url
	from reNgine.utils.task import stream_command, run_command, save_subdomain, save_endpoint
	from reNgine.tasks.parsers import parse_smugglex_result
	import json
	import os

	logger.info('Smugglex scan started')
	input_path = f'{self.results_dir}/input_endpoints_smugglex.txt'
	if not urls:
		get_http_urls(is_alive=True, ignore_files=True, write_filepath=input_path, ctx=ctx)
	else:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
			
	if not os.path.isfile(input_path) or os.path.getsize(input_path) == 0:
		logger.warning('smugglex: no endpoints to scan, skipping.')
		return

	output_json = f"{self.results_dir}/smugglex_output.json"
	cmd = f"cat {input_path} | smugglex --json -o {output_json}"
	run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)
	
	if os.path.exists(output_json):
		try:
			with open(output_json, 'r') as f:
				for line in f:
					if not line.strip(): continue
					try:
						finding = json.loads(line)
						vuln_data = parse_smugglex_result(finding)
						save_vulnerability(
							target_domain=self.domain,
							scan_history=self.scan,
							subscan=self.subscan,
							**vuln_data)
					except json.JSONDecodeError:
						pass
		except Exception as e:
			logger.error(f"Smugglex parse error: {e}")

def second_order_scan(self, urls=[], ctx={}, description=None):
	"""Second Order Scan — runs the second-order Go tool against each target URL.

	Writes the embedded merged config (_SECOND_ORDER_MERGED_CONFIG) covering 5 detection
	modes: LogNon200Queries, LogQueries (img/script/link/form/input/meta),
	LogInline (script/title/noscript/style), and custom headers.

	Produces up to 3 output files per run:
	  attributes.json               -> LogQueries  (INFO severity)
	  inline.json                   -> LogInline   (INFO severity)
	  non-200-url-attributes.json   -> LogNon200Queries (HIGH severity)
	"""
	from reNgine.common_func import save_vulnerability
	from reNgine.tasks.parsers import parse_second_order_finding

	logger.info('Second Order scan started')

	config_path = "/usr/local/config/second_order_merged.json"
	os.makedirs("/usr/local/config", exist_ok=True)

	with open(config_path, 'w') as fh:
		json.dump(_SECOND_ORDER_MERGED_CONFIG, fh)

	targets = urls or ["https://%s" % self.domain.name]
	out_dir = "%s/second_order_out" % self.results_dir
	os.makedirs(out_dir, exist_ok=True)

	for target in targets:
		cmd = "second-order -target %s -config %s -output %s" % (target, config_path, out_dir)
		run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)

	for fname in os.listdir(out_dir):
		if not fname.endswith(".json"):
			continue
		fpath = os.path.join(out_dir, fname)
		try:
			with open(fpath, 'r') as fh:
				data = json.load(fh)
			for mode_key, pages in data.items():
				if not isinstance(pages, dict):
					continue
				for page_url, selectors in pages.items():
					if not isinstance(selectors, dict):
						continue
					for element_key, values in selectors.items():
						if not isinstance(values, list) or not values:
							continue
						vuln_data = parse_second_order_finding(mode_key, page_url, element_key, values)
						save_vulnerability(
							target_domain=self.domain,
							scan_history=self.scan,
							subscan=self.subscan,
							**vuln_data)
		except Exception as e:
			logger.error('second_order: parse error on %s: %s', fname, e)

def nuclei_dast_scan(self, urls=[], ctx={}, description=None):
	"""Nuclei DAST Scan"""
	from reNgine.common_func import save_vulnerability, get_http_urls, sanitize_url, get_subdomain_from_url
	from reNgine.utils.task import stream_command, save_subdomain, save_endpoint
	from reNgine.tasks.parsers import parse_nuclei_result
	import os

	logger.info('Nuclei DAST scan started')
	input_path = f'{self.results_dir}/input_endpoints_nuclei_dast.txt'
	if not urls:
		get_http_urls(is_alive=True, ignore_files=True, write_filepath=input_path, ctx=ctx)
	else:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
			
	if not os.path.isfile(input_path) or os.path.getsize(input_path) == 0:
		logger.warning('nuclei_dast: no endpoints to scan, skipping.')
		return

	config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	rate_limit = config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
	retries = config.get(RETRIES) or self.yaml_configuration.get(RETRIES, DEFAULT_RETRIES)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	proxy_obj = Proxy.objects.first()
	proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
	if proxy:
		from urllib.parse import urlparse as _urlparse
		_scheme = _urlparse(proxy).scheme
		if _scheme not in ('http', 'https', 'socks5'):
			logger.warning(
				'nuclei_dast: proxy scheme %s not supported by nuclei; running without proxy',
				_scheme,
			)
			proxy = None

	cmd = f"nuclei -dast -headless -l {input_path} -j"
	if rate_limit:
		cmd += f" -rl {rate_limit}"
	if retries:
		cmd += f" -retries {retries}"
	if proxy:
		cmd += f" -proxy {proxy}"

	for line in stream_command(
			cmd,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id):
		if not isinstance(line, dict): continue
		vuln_data = parse_nuclei_result(line)
		http_url = sanitize_url(line.get('matched-at'))
		subdomain_name = get_subdomain_from_url(http_url)
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		vuln_data['source'] = 'Nuclei DAST'
		save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			subdomain=subdomain,
			**vuln_data)
