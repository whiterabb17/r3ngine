import logging
import os
import json
import xmltodict
from pathlib import Path

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.utils.opsec import OpSecManager, ProxychainsWrapper, get_opsec_manager
from reNgine.utils.task import run_command, run_command_with_retry, stream_command, save_endpoint
from reNgine.tasks.persistence import save_ip_address
from startScan.models import *
from scanEngine.models import Notification, Proxy

logger = logging.getLogger(__name__)

def port_scan(self, hosts=[], ctx={}, description=None, prepare_only=False, parse_only=None):
	"""Run port scan.

	Args:
		hosts (list, optional): Hosts to run port scan on.
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of open ports (dict).
	"""
	input_file = f'{self.results_dir}/input_subdomains_port_scan.txt'
	# projectdiscovery tools like naabu and httpx seem to fail when proxies are used
	# ensuring that proxies are never used for naabu
	proxy = ''

	# Config
	config = self.yaml_configuration.get(PORT_SCAN) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	exclude_ports = config.get(NAABU_EXCLUDE_PORTS, [])
	exclude_subdomains = config.get(NAABU_EXCLUDE_SUBDOMAINS, False)
	ports = config.get(PORTS, NAABU_DEFAULT_PORTS)
	ports = [str(port) for port in ports]
	rate_limit = config.get(NAABU_RATE) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	passive = config.get(NAABU_PASSIVE, False)
	use_naabu_config = config.get(USE_NAABU_CONFIG, False)
	exclude_ports_str = ','.join(return_iterable(exclude_ports))
	# nmap args
	nmap_enabled = config.get(ENABLE_NMAP, False)
	nmap_cmd = config.get(NMAP_COMMAND, '')
	nmap_script = config.get(NMAP_SCRIPT, '')
	nmap_script = ','.join(return_iterable(nmap_script))
	nmap_script_args = config.get(NMAP_SCRIPT_ARGS)

	if hosts:
		with open(input_file, 'w') as f:
			f.write('\n'.join(hosts))
	else:
		hosts = get_subdomains(
			write_filepath=input_file,
			exclude_subdomains=exclude_subdomains,
			ctx=ctx)

	if not hosts:
		logger.warning('port_scan: no hosts to scan, skipping.')
		return []

	# Build cmd
	cmd = 'naabu -json -exclude-cdn'
	cmd += f' -list {input_file}' if len(hosts) > 1 else f' -host {hosts[0]}'
	if 'full' in ports or 'all' in ports:
		ports_str = ' -p "-"'
	elif 'top-100' in ports:
		ports_str = ' -top-ports 100'
	elif 'top-1000' in ports:
		ports_str = ' -top-ports 1000'
	else:
		ports_str = ','.join(ports)
		ports_str = f' -p {ports_str}'
	cmd += ports_str
	cmd += ' -config /root/.config/naabu/config.yaml' if use_naabu_config else ''
	cmd += f' -proxy "{proxy}"' if proxy else ''
	cmd += f' -c {threads}' if threads else ''
	cmd += f' -rate {rate_limit}' if rate_limit > 0 else ''
	cmd += f' -timeout {timeout}s' if timeout > 0 else ''
	cmd += f' -passive' if passive else ''
	cmd += f' -exclude-ports {exclude_ports_str}' if exclude_ports else ''
	cmd += f' -silent'

	if prepare_only:
		return {
			"cmd": cmd,
			"input_file": input_file,
			"hosts": hosts,
			"nmap_enabled": nmap_enabled,
			"nmap_cmd": nmap_cmd,
			"nmap_script": nmap_script,
			"nmap_script_args": nmap_script_args,
			"rate_limit": rate_limit,
		}

	# Execute cmd and gather results
	results = []
	urls = []
	ports_data = {}

	if parse_only is not None:
		line_source = []
		for raw_line in parse_only.splitlines():
			raw_line = raw_line.strip()
			if not raw_line:
				continue
			try:
				line_source.append(json.loads(raw_line))
			except Exception:
				line_source.append(raw_line)
	else:
		line_source = stream_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)

	# One SELECT per unique host instead of one per port (N+1 fix).
	_subdomain_cache: dict = {}
	for line in line_source:
		if not isinstance(line, dict):
			continue
		results.append(line)
		port_number = line['port']
		ip_address = line['ip']
		host = line.get('host') or ip_address
		if port_number == 0:
			continue

		# Grab subdomain — lazy per-host cache; one DB hit per unique host, not per port.
		if host not in _subdomain_cache:
			_subdomain_cache[host] = Subdomain.objects.filter(
				name=host,
				target_domain=self.domain,
				scan_history=self.scan,
			).first()
		subdomain = _subdomain_cache[host]

		# Add IP DB — save_ip_address() already handles ip_subscan_ids.add(subscan)
		# when subscan= is passed, so no redundant M2M add needed here.
		ip, _ = save_ip_address(ip_address, subdomain, subscan=self.subscan, scan_id=self.scan_id, activity_id=self.activity_id)

		# Add endpoint to DB
		# port 80 and 443 not needed as http crawl already does that.
		if port_number not in [80, 443]:
			http_url = f'{host}:{port_number}'
			endpoint, _ = save_endpoint(
				http_url,
				crawl=False,
				ctx=ctx,
				subdomain=subdomain)
			if endpoint:
				http_url = endpoint.http_url
			urls.append(http_url)

		# Add Port in DB
		res = get_port_service_description(port_number)
		# get or create port
		port, created = update_or_create_port(
			port_number=port_number,
			service_name=res.get('service_name', ''),
			description=res.get('description', '')
		)

		if created:
			logger.warning(f'Added new port {port_number} to DB')

		# Centralized Brute-Force Candidate Registration for Naabu findings
		bf_protocols = {
			21: 'ftp',
			22: 'ssh',
			23: 'telnet',
			445: 'smb',
			3389: 'rdp'
		}
		if port_number in bf_protocols:
			from reNgine.utilities import save_auth_candidate
			try:
				save_auth_candidate(
					scan_history=self.scan,
					subdomain=subdomain,
					target=host,
					protocol=bf_protocols[port_number],
					port=port_number,
					source_tool='naabu',
					tech_hint=f"Open Port {port_number}"
				)
			except Exception as e:
				logger.error(f"Error registering AuthCandidate from Naabu port {port_number}: {e}")

		if port_number in UNCOMMON_WEB_PORTS:
			port.is_uncommon = True
			port.save()
		# M2M .add() writes directly to the join table — no parent ip.save() needed.
		ip.ports.add(port)
		if host in ports_data:
			ports_data[host].append(port_number)
		else:
			ports_data[host] = [port_number]

		# Send notification
		logger.warning(f'Found opened port {port_number} on {ip_address} ({host})')

	if len(ports_data) == 0:
		logger.info('Finished running naabu port scan - No open ports found.')
		if nmap_enabled:
			logger.warning('naabu found no open ports; running nmap independently as configured.')
			# Convert YAML port list to integers where possible; naabu-specific
			# tokens like 'top-100'/'all'/'full' are ignored and nmap will use
			# its own defaults (top-1000) when the resulting list is empty.
			nmap_fallback_ports = [int(p) for p in ports if p.isdigit()]
			for host in hosts:
				ctx_nmap = ctx.copy()
				ctx_nmap['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
				ctx_nmap['track'] = False
				ctx_nmap['activity_id'] = self.activity_id
				nmap(
					self,
					cmd=nmap_cmd,
					ports=nmap_fallback_ports,
					host=host,
					script=nmap_script,
					script_args=nmap_script_args,
					max_rate=rate_limit,
					ctx=ctx_nmap)
		return ports_data

	# Send notification
	fields_str = ''
	for host, ports in ports_data.items():
		ports_str = ', '.join([f'`{port}`' for port in ports])
		fields_str += f'• `{host}`: {ports_str}\n'
	self.notify(fields={'Ports discovered': fields_str})

	# Save output to file
	with open(self.output_path, 'w') as f:
		json.dump(results, f, indent=4)

	logger.info('Finished running naabu port scan.')

	# Process nmap results: 1 process per host
	if nmap_enabled:
		logger.warning(f'Starting nmap scans ...')
		logger.warning(ports_data)
		for host, port_list in ports_data.items():
			ports_str = '_'.join([str(p) for p in port_list])
			ctx_nmap = ctx.copy()
			ctx_nmap['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
			ctx_nmap['track'] = False
			ctx_nmap['activity_id'] = self.activity_id
			logger.info(f"Running nmap for {host} in port_scan.")
			nmap(
				self,
				cmd=nmap_cmd,
				ports=port_list,
				host=host,
				script=nmap_script,
				script_args=nmap_script_args,
				max_rate=rate_limit,
				ctx=ctx_nmap)

	# Network protocol enumeration
	if config.get(ENABLE_NETWORK_ENUM, False) and ports_data:
		from reNgine.network_tasks import run_network_enum
		run_network_enum(self, ctx, ports_data)

	return ports_data


def nmap(
		self,
		cmd=None,
		ports=[],
		host=None,
		input_file=None,
		script=None,
		script_args=None,
		max_rate=None,
		ctx={},
		description=None):
	"""Run nmap on a host.

	Args:
		cmd (str, optional): Existing nmap command to complete.
		ports (list, optional): List of ports to scan.
		host (str, optional): Host to scan.
		input_file (str, optional): Input hosts file.
		script (str, optional): NSE script to run.
		script_args (str, optional): NSE script args.
		max_rate (int): Max rate.
		description (str, optional): Task description shown in UI.
	"""
	notif = Notification.objects.first()
	# Deduplicate ports
	ports = list(dict.fromkeys(ports))
	ports_str = ','.join(str(port) for port in ports)
	self.filename = self.filename.replace('.txt', '.xml')
	filename_vulns = self.filename.replace('.xml', '_vulns.json')
	output_file = self.output_path
	output_file_xml = f'{self.results_dir}/{host}_{self.filename}'
	vulns_file = f'{self.results_dir}/{host}_{filename_vulns}'
	# Build cmd
	nmap_cmd = get_nmap_cmd(
		cmd=cmd,
		ports=ports_str,
		script=script,
		script_args=script_args,
		max_rate=max_rate,
		host=host,
		input_file=input_file,
		output_file=output_file_xml)
	
	if not nmap_cmd:
		logger.error('Could not build nmap command')
		return

	# Apply OpSec stealth
	proxy = get_random_proxy()
	opsec = get_opsec_manager()
	nmap_cmd = opsec.apply_stealth('nmap', nmap_cmd, proxy=proxy)

	# Run cmd
	run_command(
		nmap_cmd,
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	# Get nmap XML results and convert to JSON
	nmap_results = parse_nmap_results(output_file_xml, output_file)
	vulns = nmap_results['vulns']
	discovered_services = nmap_results['services']
	
	with open(vulns_file, 'w') as f:
		json.dump(vulns, f, indent=4)

	# Save vulnerabilities found by nmap
	vulns_str = ''
	for vuln_data in vulns:
		# URL is not necessarily an HTTP URL when running nmap (can be any
		# other vulnerable protocols). Look for existing endpoint and use its
		# URL as vulnerability.http_url if it exists.
		url = vuln_data['http_url']
		endpoint = EndPoint.objects.filter(http_url__contains=url).first()
		if endpoint:
			vuln_data['http_url'] = endpoint.http_url
		vuln, created = save_vulnerability(
			target_domain=self.domain,
			subdomain=self.subdomain,
			scan_history=self.scan,
			subscan=self.subscan,
			endpoint=endpoint,
			dedup_fields=['name', 'subdomain', 'scan_history'],
			**vuln_data)
		vulns_str += f'• {str(vuln)}\n'
		if created:
			logger.warning(str(vuln))
		
		# Register Auth Candidates from vulnerability tags (like auth_portal)
		if 'auth_portal' in (vuln_data.get('tags') or []):
			from reNgine.utilities import save_auth_candidate
			# Parse port safely from http_url
			url_str = vuln_data.get('http_url') or ''
			parsed_port = 80
			if url_str:
				try:
					from urllib.parse import urlparse
					parsed_url = urlparse(url_str)
					if parsed_url.port:
						parsed_port = parsed_url.port
					else:
						parsed_port = 443 if parsed_url.scheme == 'https' else 80
				except Exception:
					try:
						port_part = url_str.split(':')[-1]
						if port_part.isdigit():
							parsed_port = int(port_part)
					except Exception:
						pass
			save_auth_candidate(
				scan_history=self.scan,
				target=vuln_data['http_url'],
				protocol='http',
				port=parsed_port,
				source_tool='Nmap NSE',
				metadata={'tags': vuln_data.get('tags') or [], 'nse_script': vuln_data.get('name')},
				subdomain=self.subdomain,
				endpoint=endpoint
			)

	# Register Auth Candidates from discovered services (SMB, RDP, etc.)
	interesting_protocols = {
		'microsoft-ds': 'smb',
		'smb': 'smb',
		'ms-wbt-server': 'rdp',
		'rdp': 'rdp',
		'ssh': 'ssh',
		'ftp': 'ftp',
		'telnet': 'telnet'
	}
	
	from reNgine.utilities import save_auth_candidate
	for svc in discovered_services:
		proto = interesting_protocols.get(svc['service'])
		if proto:
			save_auth_candidate(
				scan_history=self.scan,
				target=svc['target'],
				protocol=proto,
				port=svc['port'],
				source_tool='Nmap Service Discovery',
				metadata={'banner': svc['banner']},
				subdomain=self.subdomain
			)

	# Send only 1 notif for all vulns to reduce number of notifs
	#if len(vulns) > 0:
	self.notify(
		severity=0,
		fields={'Vulnerabilities discovered': vulns_str},
		add_meta_info=False)

	return vulns



# dir_file_fuzz has been refactored to fuzzing_tasks.py


def parse_nmap_results(xml_file, output_file=None):
	"""Parse results from nmap output file.

	Args:
		xml_file (str): nmap XML report file path.

	Returns:
		list: List of vulnerabilities found from nmap results.
	"""
	with open(xml_file, encoding='utf8') as f:
		content = f.read()
		try:
			nmap_results = xmltodict.parse(content) # parse XML to dict
		except Exception as e:
			logger.exception(e)
			logger.error(f'Cannot parse {xml_file} to valid JSON. Skipping.')
			return {'vulns': [], 'services': []}

	# Write JSON to output file
	if output_file:
		with open(output_file, 'w') as f:
			json.dump(nmap_results, f, indent=4)
	logger.warning(json.dumps(nmap_results, indent=4))
	hosts = (
		nmap_results
		.get('nmaprun', {})
		.get('host', {})
	)
	all_vulns = []
	services = []
	if not hosts:
		return {'vulns': all_vulns, 'services': services}
	if isinstance(hosts, dict):
		hosts = [hosts]

	for host in hosts:
		# Grab hostname / IP from output
		hostnames_dict = host.get('hostnames', {})
		if hostnames_dict:
			# Ensure that hostnames['hostname'] is a list for consistency
			hostnames_list = hostnames_dict['hostname'] if isinstance(hostnames_dict['hostname'], list) else [hostnames_dict['hostname']]

			# Extract all the @name values from the list of dictionaries
			hostnames = [entry.get('@name') for entry in hostnames_list]
		else:
			address = host.get('address')
			if not address:
				continue
			if isinstance(address, list):
				addr = next((a.get('@addr') for a in address if a.get('@addrtype') in ('ipv4', 'ipv6')), None)
				if not addr:
					continue
				hostnames = [addr]
			else:
				addr = address.get('@addr')
				if not addr:
					continue
				hostnames = [addr]

		# Iterate over each hostname for each port
		for hostname in hostnames:

			# Grab ports from output
			ports = host.get('ports', {}).get('port', [])
			if isinstance(ports, dict):
				ports = [ports]

			for port in ports:
				# Skip closed ports
				state = port.get('state', {}).get('@state', 'unknown')
				if state != 'open':
					continue

				url_vulns = []
				port_number = port['@portid']
				url = sanitize_url(f'{hostname}:{port_number}')
				logger.info(f'Parsing nmap results for {hostname}:{port_number} ...')
				if not port_number or not port_number.isdigit():
					continue
				
				port_protocol = port['@protocol']
				service = port.get('service', {})
				service_name = service.get('@name', '').lower()
				
				# Register discovered service for brute-force candidates
				services.append({
					'target': hostname,
					'port': int(port_number),
					'service': service_name,
					'banner': service.get('@product', '')
				})
				port_protocol = port['@protocol']
				scripts = port.get('script', [])
				if isinstance(scripts, dict):
					scripts = [scripts]

				for script in scripts:
					script_id = script['@id']
					script_output = script['@output']
					script_output_table = script.get('table', [])
					service = port.get('service', {})
					service_product = service.get('@product', '')
					service_version = service.get('@version', '')
					service_title = f"{service_product} {service_version}".strip()
					logger.debug(f'Ran nmap script "{script_id}" on {port_number}/{port_protocol}:\n{script_output}\n')
					if script_id == 'vulscan':
						vulns = parse_nmap_vulscan_output(script_output)
						url_vulns.extend(vulns)
					elif script_id == 'vulners':
						vulns = parse_nmap_vulners_output(script_output, service_title=service_title)
						url_vulns.extend(vulns)
					elif script_id == 'http-server-header':
						vulns = parse_nmap_http_server_header_output(script_output)
						url_vulns.extend(vulns)
					elif script_id == 'fingerprint-strings':
						vulns = parse_nmap_fingerprint_strings_output(script_output)
						url_vulns.extend(vulns)
					elif script_id == 'https-redirect':
						vulns = parse_nmap_https_redirect_output(script_output)
						url_vulns.extend(vulns)
					elif script_id == 'http-title':
						vulns = parse_nmap_http_title_output(script_output)
						url_vulns.extend(vulns)
					elif script_id == 'http-vuln-*' or script_id.startswith('http-vuln'):
						vulns = parse_nmap_generic_vuln_output(script_id, script_output)
						url_vulns.extend(vulns)
					else:
						# Generic vuln script handling if script_id contains 'vuln'
						if 'vuln' in script_id:
							vulns = parse_nmap_generic_vuln_output(script_id, script_output)
							url_vulns.extend(vulns)
						else:
							# Robust catch-all for any script output indicating a vulnerability
							lower_output = script_output.lower()
							if "vulnerable" in lower_output or "vulnerability" in lower_output or "account found" in lower_output:
								vulns = parse_nmap_generic_vuln_output(script_id, script_output)
								url_vulns.extend(vulns)
							else:
								# Support for specific non-'vuln' scripts that can still find issues
								if any(s in script_id for s in ['csrf', 'xss', 'exec', 'exploit', 'injection', 'drown']):
									vulns = parse_nmap_generic_vuln_output(script_id, script_output)
									url_vulns.extend(vulns)
								else:
									logger.warning(f'Script output parsing for script "{script_id}" is not supported yet.')

				# Add URL & source to vuln
				for vuln in url_vulns:
					if 'source' not in vuln:
						vuln['source'] = NMAP
					# TODO: This should extend to any URL, not just HTTP
					vuln['http_url'] = url
					if 'http_path' in vuln:
						vuln['http_url'] += vuln['http_path']
					all_vulns.append(vuln)

	return {'vulns': all_vulns, 'services': services}


def parse_nmap_https_redirect_output(script_output):
	return [{
		'name': 'HTTPS Redirect Detected',
		'severity': 0,
		'description': f'Service redirects to HTTPS:\n{script_output}',
		'type': 'info'
	}]


def parse_nmap_http_server_header_output(script_output):
	return [{
		'name': 'HTTP Server Header',
		'severity': 0,
		'description': f'HTTP Server Header detected: {script_output}',
		'type': 'info'
	}]


def parse_nmap_fingerprint_strings_output(script_output):
	vulns = [{
		'name': 'Service Fingerprint',
		'severity': 0,
		'description': f'Nmap discovered service fingerprint strings:\n{script_output}',
		'type': 'info'
	}]
	# Deep inspection for titles
	title_match = re.search(r'<title>(.*?)</title>', script_output, re.IGNORECASE | re.DOTALL)
	if title_match:
		title = title_match.group(1).strip()
		vulns.append({
			'name': f'{title} (Service Fingerprint)',
			'severity': 0,
			'description': f'Extracted title "{title}" from service fingerprint.',
			'type': 'info',
			'tags': ['auth_portal'] if any(x in title.lower() for x in ['vpn', 'portal', 'login', 'auth', 'admin']) else []
		})
	return vulns


def parse_nmap_http_title_output(script_output):
	title = script_output.strip()
	return [{
		'name': f'HTTP Title: {title}',
		'severity': 0,
		'description': f'Detected HTTP page title: {title}',
		'type': 'info',
		'tags': ['auth_portal'] if any(x in title.lower() for x in ['vpn', 'portal', 'login', 'auth', 'admin']) else []
	}]


def parse_nmap_generic_vuln_output(script_id, script_output):
	if not script_output or not script_output.strip():
		return []

	lower_output = script_output.lower()

	# List of common "negative" indicators in nmap script output
	false_positive_indicators = [
		"couldn't find",
		"could not find",
		"error: script execution failed",
		"no reply from server",
		"timeout",
		"did not work",
		"might not be vulnerable",
		"not vulnerable",
		"no findings",
		"0 vulnerabilities found",
		"no vulnerabilities found",
		"vulnerabilities: 0",
		"vulnerable: no",
	]

	if any(indicator in lower_output for indicator in false_positive_indicators):
		return []

	return [{
		'name': f'Nmap Vuln Script: {script_id}',
		'severity': 2, # Medium by default for vuln scripts
		'description': f'Nmap script {script_id} flagged a potential issue:\n{script_output}',
		'type': 'Vulnerability',
		'tags': ['auth_portal'] if any(x in script_output.lower() for x in ['login', 'auth', 'brute', 'password']) else []
	}]



def parse_nmap_http_csrf_output(script_output):
	pass


def parse_nmap_vulscan_output(script_output):
	"""Parse nmap vulscan script output.

	Args:
		script_output (str): Vulscan script output.

	Returns:
		list: List of Vulnerability dicts.
	"""
	data = {}
	vulns = []
	provider_name = ''

	# Sort all vulns found by provider so that we can match each provider with
	# a function that pulls from its API to get more info about the
	# vulnerability.
	for line in script_output.splitlines():
		if not line:
			continue
		if not line.startswith('['): # provider line
			if "No findings" in line:
				logger.info(f"No findings: {line}")
				continue
			elif ' - ' in line:
				provider_name, provider_url = tuple(line.split(' - '))
				data[provider_name] = {'url': provider_url.rstrip(':'), 'entries': []}
				continue
			else:
				# Log a warning
				logger.warning(f"Unexpected line format: {line}")
				continue
		reg = r'\[(.*)\] (.*)'
		matches = re.match(reg, line)
		id, title = matches.groups()
		entry = {'id': id, 'title': title}
		data[provider_name]['entries'].append(entry)

	logger.warning('Vulscan parsed output:')
	logger.warning(pprint.pformat(data))

	for provider_name in data:
		if provider_name == 'Exploit-DB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'IBM X-Force':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'MITRE CVE':
			logger.error(f'Provider {provider_name} is not supported YET.')
			for entry in data[provider_name]['entries']:
				cve_id = entry['id']
				vuln = cve_to_vuln(cve_id)
				vulns.append(vuln)
		elif provider_name == 'OSVDB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'OpenVAS (Nessus)':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'SecurityFocus':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'VulDB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		else:
			logger.error(f'Provider {provider_name} is not supported.')
	return vulns


def get_severity_from_cvss(cvss_score):
	"""Get severity integer from CVSS score."""
	if cvss_score < 4:
		return NUCLEI_SEVERITY_MAP['low']
	elif cvss_score < 7:
		return NUCLEI_SEVERITY_MAP['medium']
	elif cvss_score < 9:
		return NUCLEI_SEVERITY_MAP['high']
	else:
		return NUCLEI_SEVERITY_MAP['critical']


def parse_nmap_vulners_output(script_output, url='', service_title=''):
	"""Parse nmap vulners script output.

	All findings for the same service are grouped into a single vulnerability
	record. Individual findings are rendered as a formatted table in the
	description so the UI shows one row per service rather than one row per CVE/ID.

	Args:
		script_output (str): Script output.

	Returns:
		list: Single-element list containing the grouped vulnerability, or [].
	"""
	if not script_output or not isinstance(script_output, str):
		return []

	findings = []
	lines = script_output.split('\n')
	for line in lines:
		line = line.strip()
		# Typical line: ID   SCORE   URL   [*EXPLOIT*]
		# Example: PACKETSTORM:173661      9.8     https://vulners.com/packetstorm/PACKETSTORM:173661      *EXPLOIT*
		parts = re.split(r'\s+', line)
		if len(parts) >= 3:
			vuln_id = parts[0]
			try:
				vuln_cvss = float(parts[1])
			except (ValueError, TypeError):
				continue  # Not a vuln line

			vuln_url = parts[2]
			is_exploit = '*EXPLOIT*' in line

			source_tag = ''
			vuln_url_lower = vuln_url.lower()
			if 'packetstorm' in vuln_url_lower:
				source_tag = 'packetstorm'
			elif 'githubexploit' in vuln_url_lower:
				source_tag = 'githubexploit'
			elif 'seebug' in vuln_url_lower or 'ssv:' in vuln_id.lower():
				source_tag = 'seebug'
			elif 'zdt' in vuln_url_lower or '1337day' in vuln_url_lower or '1337day' in vuln_id.lower():
				source_tag = '1337day'
			elif 'exploit-db' in vuln_url_lower or 'edb' in vuln_id.lower():
				source_tag = 'exploit-db'

			findings.append({
				'id': vuln_id,
				'cvss': vuln_cvss,
				'url': vuln_url,
				'is_exploit': is_exploit,
				'source_tag': source_tag,
			})

	# Fallback to CVE regex when the script output uses a non-standard format
	if not findings:
		CVE_REGEX = re.compile(r'.*(CVE-\d\d\d\d-\d+).*')
		matches = list(dict.fromkeys(CVE_REGEX.findall(script_output)))
		for cve_id in matches:
			findings.append({'id': cve_id, 'cvss': 0.0, 'url': '', 'is_exploit': False, 'source_tag': ''})

	if not findings:
		return []

	# Aggregate across all findings
	max_cvss = max(f['cvss'] for f in findings)
	all_tags = set()
	all_references = []
	best_exploit_url = None
	for f in findings:
		if f['is_exploit']:
			all_tags.add('is exploit')
			if best_exploit_url is None:
				best_exploit_url = f['url']
		if f['source_tag']:
			all_tags.add(f['source_tag'])
		if f['url']:
			all_references.append(f['url'])

	# Build a plain-text table for the description (rendered with pre-wrap in the UI)
	col_id_w = max(len(f['id']) for f in findings)
	col_id_w = max(col_id_w, 10)
	header_line  = f"{'ID':<{col_id_w}}  {'CVSS':>6}  {'Source':<15}  Exploit"
	divider_line = f"{'-' * col_id_w}  {'-' * 6}  {'-' * 15}  -------"
	rows = []
	for f in findings:
		exploit_marker = 'Yes' if f['is_exploit'] else 'No'
		rows.append(
			f"{f['id']:<{col_id_w}}  {f['cvss']:>6.1f}  {f['source_tag'] or '':<15}  {exploit_marker}"
		)

	product_label = service_title or 'Unknown service'
	description = (
		f"Vulnerabilities found by nmap vulners NSE script for: {product_label}\n"
		f"Total findings: {len(findings)}  |  Highest CVSS: {max_cvss}\n\n"
		f"{header_line}\n{divider_line}\n"
		+ '\n'.join(rows)
	)

	vuln_name = f"{service_title} (Vulners NSE)" if service_title else "Vulners NSE Findings"

	grouped_vuln = {
		'name': vuln_name,
		'type': 'nmap-vulners-nse',
		'severity': get_severity_from_cvss(max_cvss),
		'description': description,
		'cvss_score': max_cvss,
		'references': all_references,
		'cve_ids': [],
		'cwe_ids': [],
		'tags': list(all_tags),
		'source': 'VULNERS',
		'group_key': service_title,
	}
	if best_exploit_url:
		grouped_vuln['exploit_url'] = best_exploit_url

	return [grouped_vuln]


def cve_to_vuln(cve_id, vuln_type=''):
	"""Search for a CVE using CVESearch and return Vulnerability data.

	Args:
		cve_id (str): CVE ID in the form CVE-*

	Returns:
		dict: Vulnerability dict.
	"""
	cve_info = CVESearch('https://cve.circl.lu').id(cve_id)
	if not cve_info:
		logger.error(f'Could not fetch CVE info for cve {cve_id}. Skipping.')
		return None
	vuln_cve_id = cve_info.get('id', cve_info.get('CVE', cve_id))
	vuln_name = vuln_cve_id
	vuln_description = cve_info.get('summary', 'none').replace(vuln_cve_id, '').strip()
	try:
		vuln_cvss = float(cve_info.get('cvss', -1))
	except (ValueError, TypeError):
		vuln_cvss = -1
	vuln_cwe_id = cve_info.get('cwe', '')
	exploit_ids = cve_info.get('refmap', {}).get('exploit-db', [])
	osvdb_ids = cve_info.get('refmap', {}).get('osvdb', [])
	references = cve_info.get('references', [])
	capec_objects = cve_info.get('capec', [])

	# Parse ovals for a better vuln name / type
	ovals = cve_info.get('oval', [])
	if ovals and isinstance(ovals, list) and len(ovals) > 0:
		vuln_name = ovals[0].get('title', vuln_name)
		vuln_type = ovals[0].get('family', vuln_type)

	# Set vulnerability severity based on CVSS score
	vuln_severity = 'info'
	if vuln_cvss < 4:
		vuln_severity = 'low'
	elif vuln_cvss < 7:
		vuln_severity = 'medium'
	elif vuln_cvss < 9:
		vuln_severity = 'high'
	else:
		vuln_severity = 'critical'

	# Build console warning message
	msg = f'{vuln_name} | {vuln_severity.upper()} | {vuln_cve_id} | {vuln_cwe_id} | {vuln_cvss}'
	for id in osvdb_ids:
		msg += f'\n\tOSVDB: {id}'
	for exploit_id in exploit_ids:
		msg += f'\n\tEXPLOITDB: {exploit_id}'
	logger.warning(msg)
	vuln = {
		'name': vuln_name,
		'type': vuln_type,
		'severity': NUCLEI_SEVERITY_MAP[vuln_severity],
		'description': vuln_description,
		'cvss_score': vuln_cvss,
		'references': references,
		'cve_ids': [vuln_cve_id],
		'cwe_ids': [vuln_cwe_id]
	}
	return vuln





#-------------#
# OSInt utils #
#-------------#
def parse_sslscan_results(xml_file):
	"""Parse results from sslscan XML output file.

	Args:
		xml_file (str): sslscan XML report file path.

	Returns:
		str: Formatted description of SSL/TLS findings.
	"""
	if not os.path.isfile(xml_file):
		return "SSLScan XML report not found."

	try:
		with open(xml_file, 'r', encoding='utf8') as f:
			content = f.read()
		
		data = xmltodict.parse(content) or {}
		document = data.get('document') or {}
		ssltest = document.get('ssltest') or {}
		
		if not ssltest:
			return "No SSLScan results found in the report."
		
		host = ssltest.get('@host', '')
		port = ssltest.get('@port', '')
		
		description = f"SSLScan Results for {host}:{port}\n\n"
		
		# Protocols
		protocols = ssltest.get('protocol', [])
		if protocols is None: protocols = []
		if isinstance(protocols, dict):
			protocols = [protocols]
		
		description += "Protocols:\n"
		for proto in protocols:
			if not proto: continue
			status = "Enabled" if proto.get('@enabled') == '1' else "Disabled"
			description += f"- {proto.get('@type', 'UNKNOWN').upper()} {proto.get('@version', '')}: {status}\n"
		description += "\n"
		
		# Renegotiation
		reneg = ssltest.get('renegotiation') or {}
		if reneg:
			supp = "Supported" if reneg.get('@supported') == '1' else "Not supported"
			sec = "Secure" if reneg.get('@secure') == '1' else "Insecure"
			description += f"Renegotiation: {supp} ({sec})\n\n"
			
		# Heartbleed
		heartbleed = ssltest.get('heartbleed', [])
		if heartbleed is None: heartbleed = []
		if isinstance(heartbleed, dict):
			heartbleed = [heartbleed]
		
		vulnerable_to_heartbleed = False
		for hb in heartbleed:
			if hb and hb.get('@vulnerable') == '1':
				vulnerable_to_heartbleed = True
				break
		
		description += f"Heartbleed: {'Vulnerable' if vulnerable_to_heartbleed else 'Not vulnerable'}\n\n"
		
		# Ciphers
		ciphers = ssltest.get('cipher', [])
		if ciphers is None: ciphers = []
		if isinstance(ciphers, dict):
			ciphers = [ciphers]
		
		preferred_ciphers = [c for c in ciphers if c and c.get('@status') == 'preferred']
		if preferred_ciphers:
			description += "Preferred Ciphers:\n"
			for c in preferred_ciphers:
				description += f"- {c.get('@sslversion', '')}: {c.get('@cipher', '')} ({c.get('@bits', '')} bits, {c.get('@strength', '')} strength)\n"
			description += "\n"
			
		# Certificates
		certificates_sec = ssltest.get('certificates') or {}
		certs = certificates_sec.get('certificate', [])
		if certs is None: certs = []
		if isinstance(certs, dict):
			certs = [certs]
		
		if certs:
			description += "Certificate Information:\n"
			for cert in certs:
				if not cert: continue
				description += f"- Subject: {cert.get('subject', 'N/A')}\n"
				description += f"- Issuer: {cert.get('issuer', 'N/A')}\n"
				description += f"- Signature Algorithm: {cert.get('signature-algorithm', 'N/A')}\n"
				pk = cert.get('pk') or {}
				description += f"- Key: {pk.get('@type', 'N/A')} {pk.get('@bits', 'N/A')} bits\n"
				description += f"- Not Valid After: {cert.get('not-valid-after', 'N/A')}\n"
				if cert.get('expired') == 'true':
					description += "- Status: EXPIRED\n"
				description += "\n"
			description += "\n"
			
		return description

	except Exception as e:
		logger.exception(e)
		return f"Error parsing SSLScan XML: {str(e)}"


def firewall_vpn_scan(self, ctx={}, description=None):
	"""
	Specialized scan for Firewalls and VPNs (Sophos focus).
	Runs ike-scan and sslscan.
	"""
	config = self.yaml_configuration.get(FIREWALL_VPN_SCAN) or {}
	run_ike_scan = config.get('run_ike_scan', True)
	run_sslscan = config.get('run_sslscan', True)
	ssl_ports = config.get('ports', [443, 4444, 8443])

	target = self.domain.name

	# 1. IKE-scan
	if run_ike_scan:
		logger.warning(f'Running IKE-scan on {target}')
		ike_output_file = f'{self.results_dir}/ike_scan_{target}.txt'
		# ike-scan does not natively support HTTP/SOCKS proxies
		cmd = f'ike-scan --multiline {target} > {ike_output_file}'
		#proxy = get_random_proxy()
		run_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)

		if os.path.isfile(ike_output_file):
			with open(ike_output_file, 'r') as f:
				content = f.read()
			if "Main Mode" in content or "Aggressive Mode" in content:
				vuln_data = {
					'name': 'IPSec VPN Detected',
					'severity': 0,
					'description': f'IKE-scan detected an IPSec VPN service.\n\nResults:\n{content}',
					'http_url': target,
					'type': 'Infrastructure',
					'source': 'ike-scan',
				}
				save_vulnerability(target_domain=self.domain, scan_history=self.scan, **vuln_data)

	# 2. SSLScan
	if run_sslscan:
		for port in ssl_ports:
			logger.warning(f'Running SSLScan on {target}:{port}')
			ssl_output_file = f'{self.results_dir}/sslscan_{target}_{port}.xml'
			# sslscan does not natively support proxies
			cmd = f'sslscan --xml={ssl_output_file} {target}:{port}'
			#proxy = get_random_proxy()
			run_command(
				cmd,
				shell=True,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id)

			if os.path.isfile(ssl_output_file):
				vuln_data = {
					'name': f'SSL/TLS Configuration Audit (Port {port})',
					'severity': 0,
					'description': parse_sslscan_results(ssl_output_file),
					'http_url': f'https://{target}:{port}',
					'type': 'SSL/TLS',
					'source': 'sslscan',
				}
				save_vulnerability(target_domain=self.domain, scan_history=self.scan, **vuln_data)
	
	# TLS deep audit (testssl.sh + crt.sh)
	from reNgine.firewall_tasks import run_crt_sh, run_tls_deep_audit
	if config.get(ENABLE_TESTSSL, False):
		run_tls_deep_audit(self, ctx, config)
	if config.get(ENABLE_CRT_SH, False):
		run_crt_sh(self, ctx, target)

	return True


