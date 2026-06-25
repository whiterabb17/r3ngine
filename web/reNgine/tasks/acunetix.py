import logging
import time
import requests
import validators
from urllib.parse import urlparse

from reNgine.common_func import *
from reNgine.definitions import *
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from dashboard.models import AcunetixAPIKey

logger = logging.getLogger(__name__)


def map_acunetix_severity(severity):
	# Acunetix: 3 (High), 2 (Medium), 1 (Low), 0 (Informational)
	# reNgine: 4 (Critical), 3 (High), 2 (Medium), 1 (Low), 0 (Info)
	mapping = {
		3: 3,
		2: 2,
		1: 1,
		0: 0
	}
	if isinstance(severity, str):
		sev_map = {'high': 3, 'medium': 2, 'low': 1, 'info': 0}
		return sev_map.get(severity.lower(), 0)
	return mapping.get(severity, 0)


def _validate_subdomain_name(subdomain_name: str) -> bool:
	"""
	Validate subdomain name format before using in API calls.

	Args:
		subdomain_name: The subdomain to validate

	Returns:
		bool: True if valid or empty/None (optional parameter)

	Raises:
		ValueError: If subdomain format is invalid
	"""
	if not subdomain_name:
		return True

	if not validators.domain(subdomain_name):
		raise ValueError(f"Invalid subdomain format: {subdomain_name}")

	return True


def _build_vuln_detail_url(base_url: str, scan_id: str, session_id: str, vuln_id: str) -> str:
	"""
	Build the correct vulnerability detail URL based on available session info.

	AWVS API uses different URL patterns across versions:
	- With session_id: /scans/{scan_id}/results/{session_id}/vulnerabilities/{vuln_id}
	- Fallback: /vulnerabilities/{vuln_id}

	Args:
		base_url: Base Acunetix API URL
		scan_id: Scan ID
		session_id: Session or result ID
		vuln_id: Vulnerability ID

	Returns:
		str: The correct vulnerability detail endpoint URL
	"""
	if scan_id and session_id:
		return f"{base_url}/api/v1/scans/{scan_id}/results/{session_id}/vulnerabilities/{vuln_id}"
	return f"{base_url}/api/v1/vulnerabilities/{vuln_id}"


def _normalize_acunetix_target_url(target_url: str, target_name: str) -> str:
	normalized_url = (target_url or '').strip()
	if normalized_url and validators.url(normalized_url):
		parsed_host = urlparse(normalized_url).hostname
		if parsed_host == target_name:
			return normalized_url.rstrip('/')
		logger.warning(
			f"Ignoring mismatched Acunetix target URL '{normalized_url}' for target '{target_name}'. "
			"Falling back to the subdomain name."
		)
	return f"https://{target_name}".rstrip('/')


def _find_acunetix_target(targets_data: dict, target_name: str, target_url: str):
	normalized_url = _normalize_acunetix_target_url(target_url, target_name)
	normalized_host = urlparse(normalized_url).hostname or target_name
	for target in targets_data.get('targets', []):
		address = str(target.get('address', '')).rstrip('/')
		address_host = urlparse(address).hostname or address
		if address == normalized_url or address_host == normalized_host:
			return target
	return None


def _get_acunetix_profile_id(base_url: str, headers: dict, verify, timeout: int):
	fallback_profile_id = "11111111-1111-1111-1111-111111111111"
	try:
		resp = requests.get(
			f"{base_url}/api/v1/scanning_profiles",
			headers=headers,
			verify=verify,
			timeout=timeout,
		)
		if resp.status_code != 200:
			return fallback_profile_id

		data = resp.json()
		profiles = (
			data.get('scanning_profiles')
			or data.get('profiles')
			or data.get('data')
			or []
		)
		for profile in profiles:
			name = str(profile.get('name', '')).lower()
			profile_id = profile.get('profile_id')
			if profile_id and ('full scan' in name or name == 'full scan'):
				return profile_id
		if profiles and profiles[0].get('profile_id'):
			return profiles[0]['profile_id']
	except Exception as exc:
		logger.warning("Could not fetch Acunetix scanning profiles: %s", exc)
	return fallback_profile_id


def _create_or_reuse_acunetix_target(base_url: str, headers: dict, verify, timeout: int, target_name: str, target_url: str):
	targets_resp = requests.get(
		f"{base_url}/api/v1/targets",
		headers=headers,
		verify=verify,
		timeout=timeout,
	)
	if targets_resp.status_code == 200:
		targets_data = targets_resp.json()
		existing_target = _find_acunetix_target(targets_data, target_name, target_url)
		if existing_target:
			return existing_target.get('target_id')

	normalized_url = _normalize_acunetix_target_url(target_url, target_name)
	create_payload = {
		'address': normalized_url,
		'description': f'r3ngine target {target_name}',
		'criticality': 10,
	}
	create_resp = requests.post(
		f"{base_url}/api/v1/targets",
		headers=headers,
		json=create_payload,
		verify=verify,
		timeout=timeout,
	)
	if create_resp.status_code not in (200, 201):
		logger.error(
			f"Failed to create Acunetix target for {target_name}. "
			f"status={create_resp.status_code} body={create_resp.text[:500]}"
		)
		return None

	create_data = create_resp.json()
	target_id = create_data.get('target_id')
	if target_id:
		return target_id

	refetched_targets_resp = requests.get(
		f"{base_url}/api/v1/targets",
		headers=headers,
		verify=verify,
		timeout=timeout,
	)
	if refetched_targets_resp.status_code == 200:
		refetched_target = _find_acunetix_target(refetched_targets_resp.json(), target_name, target_url)
		if refetched_target:
			return refetched_target.get('target_id')
	return None


def _start_acunetix_scan_direct(base_url: str, headers: dict, verify, timeout: int, target_id: str):
	profile_id = _get_acunetix_profile_id(base_url, headers, verify, timeout)
	scan_payload = {
		'target_id': target_id,
		'profile_id': profile_id,
		'schedule': {
			'disable': False,
			'start_date': None,
			'time_sensitive': False,
		},
	}
	scan_resp = requests.post(
		f"{base_url}/api/v1/scans",
		headers=headers,
		json=scan_payload,
		verify=verify,
		timeout=timeout,
	)
	if scan_resp.status_code not in (200, 201):
		logger.error(
			f"Failed to start Acunetix scan for target_id={target_id}. "
			f"status={scan_resp.status_code} body={scan_resp.text[:500]}"
		)
		return None
	return scan_resp.json()


def _fetch_acunetix_vulnerabilities(vulns_url: str, headers: dict, verify, timeout: int):
	collected_vulnerabilities = []
	next_url = vulns_url
	visited_urls = set()

	while next_url and next_url not in visited_urls:
		visited_urls.add(next_url)
		resp = requests.get(
			next_url,
			headers=headers,
			verify=verify,
			timeout=timeout,
		)
		logger.info(f"Acunetix vulnerabilities response code: {resp.status_code} for {next_url}")
		if resp.status_code != 200:
			return resp, collected_vulnerabilities

		data = resp.json()
		collected_vulnerabilities.extend(data.get('vulnerabilities', []))

		pagination = data.get('pagination', {}) or {}
		next_cursor = pagination.get('next_cursor')
		next_link = pagination.get('next')
		if next_link:
			next_url = next_link
		elif next_cursor:
			separator = '&' if '?' in vulns_url else '?'
			next_url = f"{vulns_url}{separator}c={next_cursor}"
		else:
			next_url = None

	return None, collected_vulnerabilities


def acunetix_scan(
		self,
		domain_id,
		scan_history_id=None,
		ctx=None,
		description=None,
		subdomain_id=None,
		subdomain_name=None,
		subdomain_http_url=None):
	"""
	Run Acunetix (AWVS) scan for the given domain or a subdomain target.
	"""
	if ctx is None:
		ctx = {}

	if subdomain_name:
		try:
			_validate_subdomain_name(subdomain_name)
		except ValueError as e:
			logger.error(f"Invalid subdomain provided to acunetix_scan: {e}")
			return False

	logger.info(f"Starting Acunetix scan for domain ID: {domain_id}")
	scan_history = ScanHistory.objects.get(pk=scan_history_id) if scan_history_id else None
	domain = Domain.objects.get(pk=domain_id)

	# Resolve subdomain and subscan objects for association
	from startScan.models import SubScan
	subdomain = None
	if subdomain_id:
		subdomain = Subdomain.objects.filter(pk=subdomain_id).first()
	if not subdomain and subdomain_name:
		subdomain = Subdomain.objects.filter(name=subdomain_name, scan_history=scan_history).first()
		if not subdomain and scan_history:
			subdomain = Subdomain.objects.filter(name=subdomain_name, target_domain=domain).first()
	if not subdomain:
		subdomain = getattr(self, 'subdomain', None)

	if subdomain:
		subdomain_name = subdomain.name
		subdomain_http_url = subdomain.http_url or subdomain_http_url

	target_name = subdomain_name or domain.name
	target_url = subdomain_http_url or f"https://{target_name}"

	subscan = getattr(self, 'subscan', None)

	# Get credentials from vault
	creds = AcunetixAPIKey.objects.first()
	if not (creds and creds.server_url and creds.api_key):
		logger.error("Acunetix API keys not fully configured in vault. Skipping.")
		return False
	logger.info(f"Acunetix credentials configured for: {creds.server_url}")
	try:
		logger.info(f"Starting Acunetix scan for {target_url}")

		base_url = f"{creds.server_url}".rstrip('/')
		headers = {
			'X-Auth': creds.api_key,
			'Content-Type': 'application/json'
		}
		import os as _os
		_acunetix_verify = _os.environ.get('ACUNETIX_CA_BUNDLE', False)

		target_id = _create_or_reuse_acunetix_target(
			base_url=base_url,
			headers=headers,
			verify=_acunetix_verify,
			timeout=settings.ACUNETIX_REQUEST_TIMEOUT,
			target_name=target_name,
			target_url=target_url,
		)
		if not target_id:
			logger.error(f"Could not create or locate Acunetix target for {target_name}")
			return False

		scan_info = _start_acunetix_scan_direct(
			base_url=base_url,
			headers=headers,
			verify=_acunetix_verify,
			timeout=settings.ACUNETIX_REQUEST_TIMEOUT,
			target_id=target_id,
		) or {}
		scan_id = scan_info.get('scan_id')

		if not target_id:
			logger.error(f"Target {target_name} not found in Acunetix after start_scan.")
			return False

		# If scan_id wasn't in scan_info, try to find it from scans query by target_id
		if not scan_id:
			scans_resp = requests.get(f"{base_url}/api/v1/scans?q=target_id:{target_id}", headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)
			if scans_resp.status_code == 200:
				scans_data = scans_resp.json()
				scans_list = scans_data.get('scans', [])
				if scans_list:
					scan_id = scans_list[0].get('scan_id')

		if not scan_id:
			logger.error(f"Could not determine scan_id for Acunetix scan on target {target_name}")
			return False

		# Wait for scan to complete
		max_retries = settings.ACUNETIX_MAX_RETRIES
		poll_interval = settings.ACUNETIX_POLL_INTERVAL
		retries = 0
		while retries < max_retries:
			scan_resp = requests.get(f"{base_url}/api/v1/scans/{scan_id}", headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)
			if scan_resp.status_code == 200:
				scan_data = scan_resp.json()
				current_session = scan_data.get('current_session', {})
				current_status = current_session.get('status')
				logger.info(f"Acunetix scan {scan_id} status: {current_status} (retry {retries}/{max_retries})")

				if current_status == 'completed':
					logger.info(f"Acunetix scan for {target_name} completed.")
					break
				elif current_status in ['failed', 'aborted']:
					logger.error(f"Acunetix scan for {target_name} ended with status: {current_status}.")
					return False
			else:
				logger.warning(f"Failed to fetch scan status for {scan_id}, status code: {scan_resp.status_code}")

			time.sleep(poll_interval)
			retries += 1
		else:
			logger.error(f"Acunetix scan for {target_name} timed out after {max_retries} retries.")
			return False

		# Fetch Vulnerabilities for the specific scan
		vulns_url = None
		session_id = None
		scan_detail_resp = requests.get(f"{base_url}/api/v1/scans/{scan_id}", headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)
		if scan_detail_resp.status_code == 200:
			scan_detail = scan_detail_resp.json()
			session = scan_detail.get('current_session', {})
			session_id = session.get('scan_session_id') or session.get('result_id')
			if session_id:
				vulns_url = f"{base_url}/api/v1/scans/{scan_id}/results/{session_id}/vulnerabilities"

		if not vulns_url:
			# Fallback to querying by target_id
			vulns_url = f"{base_url}/api/v1/vulnerabilities?q=target_id:{target_id}"

		active_vulns_url = vulns_url
		logger.info(f"Fetching Acunetix vulnerabilities from: {active_vulns_url}")
		vulns_resp = requests.get(active_vulns_url, headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)
		logger.info(f"Acunetix vulnerabilities response code: {vulns_resp.status_code}")

		# If the URL returned 400 or 404, try fallbacks
		if vulns_resp.status_code in [400, 404]:
			fallback_url = f"{base_url}/api/v1/scans/{scan_id}/vulnerabilities"
			logger.info(f"Retrying with fallback 1 URL: {fallback_url}")
			vulns_resp = requests.get(fallback_url, headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)
			logger.info(f"Fallback 1 response code: {vulns_resp.status_code}")
			active_vulns_url = fallback_url

			if vulns_resp.status_code in [400, 404]:
				fallback_url = f"{base_url}/api/v1/vulnerabilities?q=target_id:{target_id}"
				logger.info(f"Retrying with fallback 2 URL: {fallback_url}")
				vulns_resp = requests.get(fallback_url, headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)
				logger.info(f"Fallback 2 response code: {vulns_resp.status_code}")
				active_vulns_url = fallback_url

		v_list = []
		if vulns_resp.status_code == 200:
			_, v_list = _fetch_acunetix_vulnerabilities(
				active_vulns_url,
				headers=headers,
				verify=_acunetix_verify,
				timeout=settings.ACUNETIX_REQUEST_TIMEOUT,
			)
		elif vulns_resp.status_code in [400, 404]:
			logger.warning("Acunetix vulnerability fetch did not return a valid list after fallbacks.")

		if v_list:
			logger.info(f"Found {len(v_list)} vulnerabilities in Acunetix scan report.")
			for vuln in v_list:
				vuln_detail_url = _build_vuln_detail_url(base_url, scan_id, session_id, vuln['vuln_id'])

				vuln_detail_resp = requests.get(vuln_detail_url, headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)
				if vuln_detail_resp.status_code == 404:
					global_url = f"{base_url}/api/v1/vulnerabilities/{vuln['vuln_id']}"
					vuln_detail_resp = requests.get(global_url, headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)

				if vuln_detail_resp.status_code == 200:
					v_detail = vuln_detail_resp.json()

					save_v_data = {
						'scan_history': scan_history,
						'target_domain': domain,
						'source': 'Acunetix',
						'name': v_detail.get('vt_name'),
						'severity': map_acunetix_severity(v_detail.get('severity')),
						'description': v_detail.get('description'),
						'impact': v_detail.get('impact'),
						'remediation': v_detail.get('recommendation'),
						'http_url': v_detail.get('affects_url'),
						'request': v_detail.get('request'),
						'response': v_detail.get('response'),
						'template_id': v_detail.get('vt_id'),
					}

					refs = []
					for r in v_detail.get('references', []):
						if isinstance(r, dict):
							refs.append(r.get('href'))
						else:
							refs.append(str(r))
					save_v_data['references'] = refs

					cves = []
					for ref in v_detail.get('references', []):
						if isinstance(ref, dict) and 'CVE-' in ref.get('rel', ''):
							cves.append(ref.get('rel'))
					save_v_data['cve_ids'] = cves

					cwes = []
					if v_detail.get('cwe_id'):
						cwes.append(f"CWE-{v_detail['cwe_id']}")
					save_v_data['cwe_ids'] = cwes

					if subdomain:
						save_v_data['subdomain'] = subdomain
					if subscan:
						save_v_data['subscan'] = subscan

					save_vulnerability(**save_v_data)

		return True

	except Exception as e:
		logger.error(f"Error in Acunetix scan: {str(e)}")
		return False
