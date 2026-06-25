import logging
import os
import json
import validators
from pathlib import Path

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.utils.opsec import OpSecManager, ProxychainsWrapper, get_opsec_manager
from reNgine.utils.task import run_command, run_command_with_retry, stream_command, save_subdomain, save_endpoint, save_subdomain_metadata
from reNgine.tasks.persistence import create_scan_activity
from api.serializers import SubdomainSerializer
from startScan.models import *
from targetApp.models import Domain

logger = logging.getLogger(__name__)

def amass_intel_discovery(self, host, ctx={}, description=None):
	"""Infrastructure discovery using Amass Intel.
	
	Args:
		host (str): Target domain to run intel on.
	"""
	config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
	use_amass_config = config.get(USE_AMASS_CONFIG, False)
	
	output_path = f'{self.results_dir}/amass_intel.txt'
	
	cmd = f'amass intel -d {host} -whois -o {output_path}'
	cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
	
	#proxy = get_random_proxy()
	#if proxy:
	#	cmd = f"export HTTP_PROXY='{proxy}' HTTPS_PROXY='{proxy}' && {cmd}"

	run_command(
		cmd,
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id
	)
	
	# Process results: finding other root domains
	discovered_count = 0
	if os.path.exists(output_path):
		with open(output_path, 'r') as f:
			for line in f:
				domain_name = line.strip()
				if domain_name and domain_name != host:
					discovered_count += 1
					logger.info(f"Discovered associated domain: {domain_name}")
					
	if discovered_count > 0:
		self.notify(fields={'Infrastructure Discovery': f'Discovered {discovered_count} associated domains/assets via Amass Intel.'})
		
	return True


def subdomain_discovery(
		self,
		host=None,
		ctx=None,
		description=None):
	"""Uses a set of tools (see SUBDOMAIN_SCAN_DEFAULT_TOOLS) to scan all
	subdomains associated with a domain.

	Args:
		host (str): Hostname to scan.

	Returns:
		subdomains (list): List of subdomain names.
	"""
	if not host:
		host = self.subdomain.name if self.subdomain else self.domain.name

	if self.starting_point_path:
		logger.warning(f'Ignoring subdomains scan as an URL path filter was passed ({self.starting_point_path}).')
		return

	# Config
	config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL) or self.yaml_configuration.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	tools = config.get(USES_TOOLS, SUBDOMAIN_SCAN_DEFAULT_TOOLS)
	default_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=True).filter(is_subdomain_gathering=True)]
	custom_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=False).filter(is_subdomain_gathering=True)]
	send_subdomain_changes, send_interesting = False, False
	notif = Notification.objects.first()
	subdomain_scope_checker = SubdomainScopeChecker(self.out_of_scope_subdomains)
	if notif:
		send_subdomain_changes = notif.send_subdomain_changes_notif
		send_interesting = notif.send_interesting_notif

	# Gather tools to run for subdomain scan
	if ALL in tools:
		tools = SUBDOMAIN_SCAN_DEFAULT_TOOLS + custom_subdomain_tools
	tools = [t.lower() for t in tools]

	# Make exception for amass since tool name is amass, but command is amass-active/passive
	default_subdomain_tools.append('amass-passive')
	default_subdomain_tools.append('amass-active')
	# Append baddns so it is always registered as a supported default subdomain discovery tool
	default_subdomain_tools.append('baddns')

	# Run tools
	opsec = get_opsec_manager()
	existing_subs = set(Subdomain.objects.filter(scan_history=self.scan).values_list('name', flat=True))
	new_discoveries = []

	for tool in tools:
		cmd = None
		results_file = None
		logger.info(f'Scanning subdomains for {host} with {tool}')
		proxy = get_random_proxy()
		if tool in default_subdomain_tools:
			if tool == 'amass-passive':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				results_file = f'{self.results_dir}/subdomains_amass.txt'
				cmd = f'amass enum -passive -d {host} -o {results_file}'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
				#if proxy:
				#	cmd = f"export HTTP_PROXY='{proxy}' HTTPS_PROXY='{proxy}' && {cmd}"

			elif tool == 'amass-active':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				amass_wordlist_name = config.get(AMASS_WORDLIST, 'deepmagic.com-prefixes-top50000')
				wordlist_path = f'/usr/src/wordlist/{amass_wordlist_name}.txt'
				results_file = f'{self.results_dir}/subdomains_amass_active.txt'
				cmd = f'amass enum -active -d {host} -o {results_file}'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
				cmd += f' -brute -w {wordlist_path}'
				#if proxy:
				#	cmd = f"export HTTP_PROXY='{proxy}' HTTPS_PROXY='{proxy}' && {cmd}"

			elif tool == 'sublist3r':
				results_file = f'{self.results_dir}/subdomains_sublister.txt'
				cmd = f'python3 /usr/src/github/Sublist3r/sublist3r.py -d {host} -t {threads} -o {results_file}'

			elif tool == 'subfinder':
				results_file = f'{self.results_dir}/subdomains_subfinder.txt'
				cmd = f'subfinder -d {host} -all -o {results_file}'
				use_subfinder_config = config.get(USE_SUBFINDER_CONFIG, False)
				cmd += ' -config /root/.config/subfinder/config.yaml' if use_subfinder_config else ''
				#cmd += f' -proxy {proxy}' if proxy else ''
				cmd += f' -timeout {timeout}' if timeout else ''
				cmd += f' -t {threads}' if threads else ''
				cmd += f' -silent'

			elif tool == 'oneforall':
				results_file = f'{self.results_dir}/subdomains_oneforall.txt'
				cmd = f'python3 /usr/src/github/OneForAll/oneforall.py --target {host} run'
				cmd_extract = f'cut -d\',\' -f6 /usr/src/github/OneForAll/results/{host}.csv | tail -n +2 > {results_file}'
				cmd_rm = f'rm -rf /usr/src/github/OneForAll/results/{host}.csv'
				cmd += f' && {cmd_extract} && {cmd_rm}'

			elif tool == 'ctfr':
				results_file = self.results_dir + '/subdomains_ctfr.txt'
				cmd = f'python3 /usr/src/github/ctfr/ctfr.py -d {host} -o {results_file}'
				cmd_extract = f"cat {results_file} | sed 's/\\*.//g' | tail -n +12 | uniq | sort > {results_file}_temp && mv {results_file}_temp {results_file}"
				cmd += f' && {cmd_extract}'

			elif tool == 'tlsx':
				results_file = self.results_dir + '/subdomains_tlsx.txt'
				cmd = f'tlsx -san -cn -silent -ro -host {host}'
				cmd += rf" | sed -n '/^\([a-zA-Z0-9]\([-a-zA-Z0-9]*[a-zA-Z0-9]\)\?\.\)\+{host}$/p' | uniq | sort"
				cmd += f' > {results_file}'

			elif tool == 'netlas':
				results_file = self.results_dir + '/subdomains_netlas.txt'
				cmd = f'netlas search -d domain -i domain domain:"*.{host}" -f json'
				netlas_key = get_netlas_key()
				cmd += f' -a {netlas_key}' if netlas_key else ''
				cmd_extract = rf"grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+{host}'"
				cmd += f' | {cmd_extract} > {results_file}'

			elif tool == 'chaos':
				# we need to find api key if not ignore
				chaos_key = get_chaos_key()
				if not chaos_key:
					logger.error('Chaos API key not found. Skipping.')
					continue
				results_file = self.results_dir + '/subdomains_chaos.txt'
				cmd = f'chaos -d {host} -silent -key {chaos_key} -o {results_file}'

			elif tool == 'baddns':
				results_file = self.results_dir + '/baddns_report.json'
				# Run baddns in silent mode (JSON format) and redirect stdout to results_file
				cmd = f'baddns -s {host} > {results_file}'


		elif tool in custom_subdomain_tools:
			tool_query = InstalledExternalTool.objects.filter(name__icontains=tool.lower())
			if not tool_query.exists():
				logger.error(f'{tool} configuration does not exists. Skipping.')
				continue
			custom_tool = tool_query.first()
			cmd = custom_tool.subdomain_gathering_command
			if '{TARGET}' not in cmd:
				logger.error(f'Missing {{TARGET}} placeholders in {tool} configuration. Skipping.')
				continue
			if '{OUTPUT}' not in cmd:
				logger.error(f'Missing {{OUTPUT}} placeholders in {tool} configuration. Skipping.')
				continue

			results_file = f'{self.results_dir}/subdomains_{tool}.txt'
			cmd = cmd.replace('{TARGET}', host)
			cmd = cmd.replace('{OUTPUT}', results_file)
			cmd = cmd.replace('{PATH}', custom_tool.github_clone_path) if '{PATH}' in cmd else cmd
		else:
			logger.warning(
				f'Subdomain discovery tool "{tool}" is not supported by reNgine. Skipping.')
			continue

		# Apply OpSec stealth
		cmd = opsec.apply_stealth(tool, cmd, proxy=proxy)

		# Run tool (with empty-file retry up to 3 attempts)
		try:
			logger.warning(f'Running {tool} with command: {cmd}')
			run_command_with_retry(
				cmd,
				results_file=results_file,
				shell=True,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id,
				proxy=proxy if tool not in ['amass-passive', 'amass-active', 'subfinder'] else None)

			# If the tool is baddns, extract discovered subdomains from the JSON results
			if tool == 'baddns' and os.path.exists(results_file):
				import re
				extracted_file = self.results_dir + '/subdomains_baddns.txt'
				discovered_subs = set()
				try:
					with open(results_file, 'r') as f:
						for line in f:
							line = line.strip()
							if not line:
								continue
							try:
								data = json.loads(line)
								# Extract target and trigger fields which can contain subdomains/domains
								for key in ['target', 'trigger']:
									val = data.get(key)
									if val and isinstance(val, str):
										# Clean wildcard or prefix (like _dmarc.example.com -> example.com)
										val = re.sub(r'^_[\w\-]+\.', '', val)
										val = val.strip().lower()
										# Check if it's a valid domain/IP
										if validators.domain(val) or validators.ipv4(val) or validators.ipv6(val):
											# Ensure it belongs to the target domain scope (host)
											if host in val:
												discovered_subs.add(val)
							except json.JSONDecodeError:
								# Fallback: if not JSON, try to extract domain-like strings from plain text line
								for part in line.split():
									part = part.strip().lower()
									if host in part and (validators.domain(part) or validators.ipv4(part)):
										discovered_subs.add(part)
					
					if discovered_subs:
						with open(extracted_file, 'w') as f_out:
							for sub in sorted(discovered_subs):
								f_out.write(f'{sub}\n')
						logger.info(f"Extracted {len(discovered_subs)} subdomains from baddns output: {discovered_subs}")
				except Exception as parse_err:
					logger.error(f"Error parsing baddns output to extract subdomains: {parse_err}")
					logger.exception(parse_err)

		except Exception as e:
			logger.error(
				f'Subdomain discovery tool "{tool}" raised an exception')
			logger.exception(e)

	# Gather all the tools' results in one single file. Write subdomains into
	# separate files, and sort all subdomains.
	run_command(
		f'cat {self.results_dir}/subdomains_*.txt > {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	run_command(
		f'sort -u {self.output_path} -o {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	if not os.path.isfile(self.output_path):
		logger.warning('subdomain_discovery: output file not found at %s, no subdomains collected.', self.output_path)
		return

	with open(self.output_path) as f:
		lines = f.readlines()

	# Parse the output_file file and store Subdomain and EndPoint objects found
	# in db.
	subdomain_count = 0
	subdomains = []
	urls = []
	for line in lines:
		subdomain_name = line.strip()
		valid_url = bool(validators.url(subdomain_name))
		valid_domain = (
			bool(validators.domain(subdomain_name)) or
			bool(validators.ipv4(subdomain_name)) or
			bool(validators.ipv6(subdomain_name)) or
			valid_url
		)
		if not valid_domain:
			logger.error(f'Subdomain {subdomain_name} is not a valid domain, IP or URL. Skipping.')
			continue

		if valid_url:
			subdomain_name = urlparse(subdomain_name).netloc

		if subdomain_scope_checker.is_out_of_scope(subdomain_name):
			logger.error(f'Subdomain {subdomain_name} is out of scope. Skipping.')
			continue

		# Add subdomain
		subdomain, created = save_subdomain(subdomain_name, ctx=ctx)
		if subdomain:
			subdomain_count += 1
			# Special handling for baddns findings (if it was a takeover)
			# We'll check the baddns report file specifically for this subdomain
			baddns_report = f'{self.results_dir}/baddns_report.json'
			if os.path.exists(baddns_report):
				with open(baddns_report, 'r') as f:
					for b_line in f:
						b_line = b_line.strip()
						if not b_line:
							continue
						if subdomain_name in b_line:
							is_takeover = False
							# Try parsing as JSON first
							try:
								data = json.loads(b_line)
								desc = data.get('description', '').lower()
								sig = data.get('signature', '').lower()
								mod = data.get('module', '').lower()
								# Check if it's a takeover finding
								if 'takeover' in desc or 'takeover' in sig or mod in ['cname', 'ns', 'mx']:
									# Exclude non-takeover DNS findings like DMARC, SPF, etc.
									if not any(x in desc or x in sig for x in ['dmarc', 'spf', 'mta-sts', 'nsec', 'zonetransfer']):
										is_takeover = True
							except Exception:
								# Fallback to plain text check
								if '[takeover]' in b_line.lower() or 'takeover' in b_line.lower():
									is_takeover = True

							if is_takeover:
								subdomain.is_important = True
								subdomain.save()
								# Create Critical Vulnerability
								description_text = f"baddns detected a potential subdomain takeover on {subdomain_name}."
								try:
									data = json.loads(b_line)
									if data.get('description'):
										description_text = f"baddns: {data.get('description')}"
								except Exception:
									pass
								
								save_vulnerability(
									name=f"Subdomain Takeover on {subdomain_name}",
									description=f"{description_text} Line: {b_line}",
									severity='critical',
									type='Subdomain Takeover',
									subdomain=subdomain,
									scan_history=self.scan,
									target_domain=self.domain,
									validation_status='unverified',
									source='baddns'
								)
			subdomains.append(subdomain)
			urls.append(subdomain.name)

	# Bulk crawl subdomains - removed to avoid collisions; delegated to next stage in pipeline
	url_filter = ctx.get('url_filter')

	# Find root subdomain endpoints and save default endpoints.
	# save_endpoint requires a scheme — bare hostnames (no http://) are rejected
	# silently, which left http_crawl and fetch_url with nothing to process.
	for subdomain in subdomains:
		raw_url = f'{subdomain.name}{url_filter}' if url_filter else subdomain.name
		if not raw_url.startswith(('http://', 'https://')):
			raw_url = f'http://{raw_url}'
		endpoint, _ = save_endpoint(
			raw_url,
			ctx=ctx,
			is_default=True,
			subdomain=subdomain
		)
		if endpoint:
			save_subdomain_metadata(subdomain, endpoint)

	# Send notifications
	subdomains_str = '\n'.join([f'• `{subdomain.name}`' for subdomain in subdomains])
	self.notify(fields={
		'Subdomain count': len(subdomains),
		'Subdomains': subdomains_str,
	})
	if send_subdomain_changes and self.scan_id and self.domain_id:
		added = get_new_added_subdomain(self.scan_id, self.domain_id)
		removed = get_removed_subdomain(self.scan_id, self.domain_id)

		if added:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in added])
			self.notify(fields={'Added subdomains': subdomains_str})

		if removed:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in removed])
			self.notify(fields={'Removed subdomains': subdomains_str})

	if send_interesting and self.scan_id and self.domain_id:
		interesting_subdomains = get_interesting_subdomains(self.scan_id, self.domain_id)
		if interesting_subdomains:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in interesting_subdomains])
			self.notify(fields={'Interesting subdomains': subdomains_str})

	return SubdomainSerializer(subdomains, many=True).data



def save_imported_subdomains(subdomains, ctx={}):
	"""Take a list of subdomains imported and write them to from_imported.txt.

	Args:
		subdomains (list): List of subdomain names.
		scan_history (startScan.models.ScanHistory): ScanHistory instance.
		domain (startScan.models.Domain): Domain instance.
		results_dir (str): Results directory.
	"""
	domain_id = ctx['domain_id']
	domain = Domain.objects.get(pk=domain_id)
	results_dir = ctx.get('results_dir', RENGINE_RESULTS)

	# Validate each subdomain and de-duplicate entries
	subdomains = list(set([
		subdomain for subdomain in subdomains
		if validators.domain(subdomain) and domain.name == get_domain_from_subdomain(subdomain)
	]))
	if not subdomains:
		return

	logger.warning(f'Found {len(subdomains)} imported subdomains.')
	with open(f'{results_dir}/from_imported.txt', 'w+') as output_file:
		for name in subdomains:
			subdomain_name = name.strip()
			subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
			subdomain.is_imported_subdomain = True
			subdomain.save()
			output_file.write(f'{subdomain}\n')






