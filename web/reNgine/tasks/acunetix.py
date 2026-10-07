import logging
import time
import requests
import validators
from urllib.parse import urlparse

from django.conf import settings
from datetime import timedelta, timezone as dt_timezone

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from reNgine.common_func import *
from reNgine.definitions import *
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from dashboard.models import AcunetixAPIKey

logger = logging.getLogger(__name__)


def _fail(task, message: str) -> bool:
	"""Log why the scan gave up and expose the reason on the task object.

	The Temporal wrapper turns a False return into a generic
	"execution returned False/failed" exception; storing the reason on
	`task.error` lets it surface the real cause on the scan timeline.
	"""
	logger.error("Acunetix scan failed: %s", message)
	task.error = message
	return False


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
			"Ignoring mismatched Acunetix target URL '%s' for target '%s'. Falling back to the subdomain name.", normalized_url, target_name
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


def _acunetix_target_host(address: str) -> str:
	address = str(address or '').rstrip('/')
	return (urlparse(address).hostname or address).lower()


ACUNETIX_TARGET_PAGE_SIZE = 100
ACUNETIX_MAX_TARGET_PAGES = 200


def _list_acunetix_targets(base_url: str, headers: dict, verify, timeout: int) -> dict | None:
	"""Map host -> target_id for every AWVS target, or None when the list cannot be read.

	A plain GET /targets returns one page, so a per-host lookup against it misses
	every target past that page and registers the host a second time. Pages are
	requested by offset; a page holding only targets already seen (a server that
	ignores the offset) ends the walk instead of looping.
	"""
	targets: dict = {}
	seen_ids: set = set()
	for page in range(ACUNETIX_MAX_TARGET_PAGES):
		resp = requests.get(
			f"{base_url}/api/v1/targets",
			params={'c': page * ACUNETIX_TARGET_PAGE_SIZE, 'l': ACUNETIX_TARGET_PAGE_SIZE},
			headers=headers,
			verify=verify,
			timeout=timeout,
		)
		if resp.status_code != 200:
			logger.warning("Could not list Acunetix targets: status=%s", resp.status_code)
			return None
		page_targets = (resp.json() or {}).get('targets') or []
		new_targets = [t for t in page_targets if t.get('target_id') not in seen_ids]
		for target in new_targets:
			seen_ids.add(target.get('target_id'))
			host = _acunetix_target_host(target.get('address'))
			if host and target.get('target_id'):
				targets.setdefault(host, target['target_id'])
		if len(page_targets) < ACUNETIX_TARGET_PAGE_SIZE or not new_targets:
			return targets
	logger.warning("Stopped listing Acunetix targets after %d pages", ACUNETIX_MAX_TARGET_PAGES)
	return targets


def _create_or_reuse_acunetix_target(
		base_url: str,
		headers: dict,
		verify,
		timeout: int,
		target_name: str,
		target_url: str,
		known_targets: dict | None = None):
	"""Return the target_id for `target_name`, creating the AWVS target when missing.

	`known_targets` (from _list_acunetix_targets) replaces the per-call lookup and is
	updated with every target created, so a long submission pass reads the list once.
	"""
	normalized_url = _normalize_acunetix_target_url(target_url, target_name)
	if known_targets is not None:
		existing_id = known_targets.get(_acunetix_target_host(normalized_url))
		if existing_id:
			return existing_id
	else:
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
			"Failed to create Acunetix target for %s. status=%s body=%s", target_name, create_resp.status_code, create_resp.text[:500]
		)
		return None

	create_data = create_resp.json()
	target_id = create_data.get('target_id')
	if target_id:
		if known_targets is not None:
			known_targets[_acunetix_target_host(normalized_url)] = target_id
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
			"Failed to start Acunetix scan for target_id=%s. status=%s body=%s", target_id, scan_resp.status_code, scan_resp.text[:500]
		)
		return None
	return scan_resp.json()


def _existing_acunetix_scan(base_url: str, headers: dict, verify, timeout: int, target_id: str, since):
	"""The target's latest AWVS scan started at or after ``since``, if reusable.

	A Temporal retry (the previous attempt was killed, e.g. by its time limit) or a
	manual retry of the step would otherwise start another multi-hour scan of the
	same target. A scan still running is waited for; one that completed already
	holds the findings to import. Failed or operator-aborted scans are not reused,
	so an explicit retry starts a fresh AWVS scan. (When the poll loop itself sees
	``aborted``, findings are still imported and the step returns success so
	Temporal does not auto-retry mid-activity.)

	Returns ``{'scan_id': ..., 'status': ...}`` or None.
	"""
	if since is None:
		return None
	resp = requests.get(
		f"{base_url}/api/v1/scans?q=target_id:{target_id}",
		headers=headers, verify=verify, timeout=timeout,
	)
	if resp.status_code != 200:
		logger.warning("Could not list Acunetix scans for target_id=%s (status %s)", target_id, resp.status_code)
		return None
	candidates = []
	for scan in resp.json().get('scans', []):
		session = scan.get('current_session') or {}
		started = parse_datetime(session.get('start_date') or '')
		if started is not None and timezone.is_naive(started):
			started = timezone.make_aware(started, dt_timezone.utc)
		if not scan.get('scan_id') or started is None or started < since:
			continue
		candidates.append((started, scan['scan_id'], session.get('status')))
	if not candidates:
		return None
	_started, scan_id, status = max(candidates)
	if status in ('failed', 'aborted'):
		return None
	return {'scan_id': scan_id, 'status': status}


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
		logger.info("Acunetix vulnerabilities response code: %s for %s", resp.status_code, next_url)
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
			return _fail(self, f"Invalid subdomain provided to acunetix_scan: {e}")

	logger.info("Starting Acunetix scan for domain ID: %s", domain_id)
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

	# Show the exact host on this task's timeline entry — one activity row is
	# created per Acunetix target, and they are otherwise indistinguishable.
	self.target_host = target_name[:500]

	subscan = getattr(self, 'subscan', None)

	# Get credentials from vault
	creds = AcunetixAPIKey.objects.first()
	if not (creds and creds.server_url and creds.api_key):
		return _fail(self, "Acunetix API keys not fully configured in vault.")
	logger.info("Acunetix credentials configured for: %s", creds.server_url)
	try:
		logger.info("Starting Acunetix scan for %s", target_url)

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
			return _fail(self, f"Could not create or locate Acunetix target for {target_name}")

		existing = _existing_acunetix_scan(
			base_url=base_url,
			headers=headers,
			verify=_acunetix_verify,
			timeout=settings.ACUNETIX_REQUEST_TIMEOUT,
			target_id=target_id,
			since=scan_history.start_scan_date if scan_history else None,
		)
		if existing:
			scan_id = existing['scan_id']
			logger.info(
				"Reusing Acunetix scan %s for %s (status %s), started during this scan",
				scan_id, target_name, existing['status'],
			)
		else:
			scan_info = _start_acunetix_scan_direct(
				base_url=base_url,
				headers=headers,
				verify=_acunetix_verify,
				timeout=settings.ACUNETIX_REQUEST_TIMEOUT,
				target_id=target_id,
			) or {}
			scan_id = scan_info.get('scan_id')

		# If scan_id wasn't in scan_info, try to find it from scans query by target_id
		if not scan_id:
			scans_resp = requests.get(f"{base_url}/api/v1/scans?q=target_id:{target_id}", headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)
			if scans_resp.status_code == 200:
				scans_data = scans_resp.json()
				scans_list = scans_data.get('scans', [])
				if scans_list:
					scan_id = scans_list[0].get('scan_id')

		if not scan_id:
			return _fail(self, f"Could not determine scan_id for Acunetix scan on target {target_name}")

		# Wait for scan to complete
		max_retries = settings.ACUNETIX_MAX_RETRIES
		poll_interval = settings.ACUNETIX_POLL_INTERVAL
		retries = 0
		current_status = None
		while retries < max_retries:
			scan_resp = requests.get(f"{base_url}/api/v1/scans/{scan_id}", headers=headers, verify=_acunetix_verify, timeout=settings.ACUNETIX_REQUEST_TIMEOUT)
			if scan_resp.status_code == 200:
				scan_data = scan_resp.json()
				current_session = scan_data.get('current_session', {})
				current_status = current_session.get('status')
				logger.info("Acunetix scan %s status: %s (retry %s/%s)", scan_id, current_status, retries, max_retries)

				if current_status in ('completed', 'failed', 'aborted'):
					# A stopped or failed scan still holds what it found until then.
					logger.info("Acunetix scan for %s ended with status %s.", target_name, current_status)
					break
			else:
				logger.warning("Failed to fetch scan status for %s, status code: %s", scan_id, scan_resp.status_code)

			time.sleep(poll_interval)
			retries += 1
		else:
			return _fail(self, f"Acunetix scan for {target_name} timed out after {max_retries} retries.")

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

		# The AWVS API exposes the result list under different paths across versions,
		# so each candidate is tried in turn. _fetch_acunetix_vulnerabilities both
		# probes the URL and walks its pagination, returning the failing response
		# when there is one — probing separately first would fetch every page twice.
		def _collect(url: str, label: str):
			logger.info("Fetching Acunetix vulnerabilities from %s (%s)", url, label)
			return _fetch_acunetix_vulnerabilities(
				url,
				headers=headers,
				verify=_acunetix_verify,
				timeout=settings.ACUNETIX_REQUEST_TIMEOUT,
			)

		failed_resp, v_list = _collect(vulns_url, "primary")
		for label, candidate_url in (
			("fallback 1", f"{base_url}/api/v1/scans/{scan_id}/vulnerabilities"),
			("fallback 2", f"{base_url}/api/v1/vulnerabilities?q=target_id:{target_id}"),
		):
			if failed_resp is None or failed_resp.status_code not in (400, 404):
				break
			failed_resp, candidate_list = _collect(candidate_url, label)
			# A URL that broke half way through its pagination still returns the
			# pages it did read. Only take over from it when the next candidate
			# actually found more, so a fallback answering with nothing does not
			# throw those findings away.
			if len(candidate_list) > len(v_list):
				v_list = candidate_list

		if failed_resp is not None:
			logger.warning(
				"Acunetix vulnerability fetch did not return a valid list after fallbacks "
				"(last status %s); keeping the %d finding(s) collected so far.",
				failed_resp.status_code, len(v_list),
			)

		imported = 0
		if v_list:
			logger.info("Found %s vulnerabilities in Acunetix scan report.", len(v_list))
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
					imported += 1

		if current_status == 'failed':
			# Retrying is worthwhile here: the failed scan is not reused, so the next
			# attempt scans again, and saving the same finding again is a no-op.
			return _fail(
				self,
				f"Acunetix scan for {target_name} ended with status: failed; "
				f"imported {imported} finding(s) it reported before failing.",
			)
		if current_status == 'aborted':
			# Stopped by the operator: keep what it found and do not retry, which
			# would start another scan of the same target.
			logger.warning(
				"Acunetix scan for %s was aborted; imported %d finding(s) found before it stopped.",
				target_name, imported,
			)
		return True

	except Exception as e:
		# The exception text carries the AWVS server URL (and, for some client
		# errors, the request headers), and `error_message` is served to every
		# role by the scan summary API. Keep the detail in the server log and
		# expose only the failure class. See security rule 8.1.
		logger.exception("Error in Acunetix scan for %s", target_name)
		return _fail(
			self,
			f"Acunetix scan for {target_name} failed with {type(e).__name__}. "
			"See the server logs for details.",
		)


def _record_submission(task, command: str, output: str, return_code: int = 0) -> None:
	"""Write one line of the submission log onto the task's timeline entry.

	The scan detail overlay lists a task's Command rows, so recording each decision
	here is what makes "which hosts were added" visible in the UI.
	"""
	from django.utils import timezone as _tz

	from startScan.models import Command

	try:
		Command.objects.create(
			command=command,
			output=output,
			return_code=return_code,
			time=_tz.now(),
			scan_history=getattr(task, 'scan', None),
			activity=getattr(task, 'activity', None),
		)
	except Exception as exc:
		logger.warning("Could not record Acunetix submission for %s: %s", command, exc)


def get_live_subdomains_for_submission(scan_history_id: int):
	"""Return the subdomains of a scan that are worth sending to Acunetix.

	"Live and externally reachable" means: it answered HTTP with a usable status
	(the same definition the scan summary uses for its alive count), it has a URL
	to scan, and it is not resolved exclusively to private addresses.

	Args:
		scan_history_id: ScanHistory PK the subdomains were discovered in.

	Returns:
		QuerySet[Subdomain]: ordered by name so submissions are deterministic.
	"""
	from django.db.models import Count, Q

	return (
		Subdomain.objects
		.filter(scan_history_id=scan_history_id)
		.filter(http_status__gt=0, http_status__lt=500)
		.exclude(http_status=404)
		.exclude(Q(http_url__isnull=True) | Q(http_url__exact=''))
		.annotate(
			public_ip_count=Count('ip_addresses', filter=Q(ip_addresses__is_private=False)),
			ip_count=Count('ip_addresses'),
		)
		.filter(Q(public_ip_count__gt=0) | Q(ip_count=0))
		.order_by('name')
		.distinct()
	)


DEFAULT_RESUBMIT_AFTER_DAYS = 3
MIN_RESUBMIT_AFTER_DAYS = 1

DEFAULT_SUBMISSION_BATCH_SIZE = 20
MAX_SUBMISSION_BATCH_SIZE = 200
DEFAULT_SUBMISSION_BATCH_PAUSE = 5
MAX_SUBMISSION_BATCH_PAUSE = 300
DEFAULT_MAX_SCANS_PER_RUN = 20
MAX_SCANS_PER_RUN = 500


def _resolve_int_option(raw, name: str, default: int, minimum: int, maximum: int | None = None) -> int:
	"""Turn an engine YAML value into an int within [minimum, maximum].

	A non-numeric value falls back to the default rather than raising out of the
	task; an out-of-range one is clamped.
	"""
	if raw is None:
		return default

	try:
		value = int(raw)
	except (TypeError, ValueError):
		logger.warning("Ignoring malformed Acunetix %s %r, using %d", name, raw, default)
		return default

	if value < minimum:
		logger.warning("Acunetix %s %s is below the minimum of %d, clamping", name, value, minimum)
		return minimum
	if maximum is not None and value > maximum:
		logger.warning("Acunetix %s %s is above the maximum of %d, clamping", name, value, maximum)
		return maximum
	return value


def _resolve_resubmit_after_days(raw) -> int:
	"""Turn the engine YAML value into a usable re-submission window.

	The window is what stops a daily scan re-registering the same host, so a
	value of 0 (cutoff = now, everything looks stale) defeats its only purpose.
	"""
	return _resolve_int_option(
		raw, 'resubmit_after_days', DEFAULT_RESUBMIT_AFTER_DAYS, MIN_RESUBMIT_AFTER_DAYS,
	)


def _last_submissions(hosts: list) -> dict:
	"""Map host -> last submission time for every host ever pushed to Acunetix."""
	from dashboard.models import AcunetixTargetSubmission

	rows = AcunetixTargetSubmission.objects.filter(host__in=hosts).values_list('host', 'last_submitted_at')
	return dict(rows)


def _persist_acunetix_submission(host: str, target_url: str, target_id: str, scan_history_id) -> None:
	"""Record that `host` was pushed to Acunetix, refreshing an existing row.

	`host` is unique, so two scans submitting the same host concurrently can
	collide on the insert. The write runs in its own atomic block: an
	IntegrityError then rolls back only this savepoint and leaves the
	surrounding transaction usable for the remaining hosts.
	"""
	from django.db import transaction
	from django.utils import timezone as _tz

	from dashboard.models import AcunetixTargetSubmission

	now = _tz.now()
	with transaction.atomic():
		row, created = AcunetixTargetSubmission.objects.get_or_create(
			host=host,
			defaults={
				'target_url': target_url,
				'acunetix_target_id': str(target_id),
				'last_submitted_at': now,
				'last_scan_history_id': scan_history_id,
			},
		)
		if not created:
			row.target_url = target_url
			row.acunetix_target_id = str(target_id)
			row.last_submitted_at = now
			row.submission_count += 1
			row.last_scan_history_id = scan_history_id
			row.save(update_fields=[
				'target_url', 'acunetix_target_id', 'last_submitted_at',
				'submission_count', 'last_scan_history_id',
			])


def _submit_acunetix_host(
		task,
		host: str,
		target_url: str,
		base_url: str,
		headers: dict,
		verify,
		start_scan_on_submit: bool,
		scan_history_id,
		known_targets: dict | None = None,
		defer_scan_reason: str | None = None) -> bool:
	"""Submit one host and write its timeline row. Never raises.

	Every host is independent: a timeout on the AWVS call, a failed scan start
	or a colliding insert is recorded against this host only, so the caller can
	carry on with the rest of the list.

	With `defer_scan_reason` the target is added but no scan is started, and the
	host is not recorded as submitted, so a later run still starts its scan.
	"""
	command = f"acunetix submit {host}"
	try:
		target_id = _create_or_reuse_acunetix_target(
			base_url=base_url,
			headers=headers,
			verify=verify,
			timeout=settings.ACUNETIX_REQUEST_TIMEOUT,
			target_name=host,
			target_url=target_url,
			known_targets=known_targets,
		)
		if not target_id:
			_record_submission(
				task, command,
				"FAILED — could not create or locate the Acunetix target",
				return_code=1,
			)
			return False

		if defer_scan_reason:
			_record_submission(
				task, command,
				"TARGET ADDED — target_id=%s url=%s; scan not started: %s" % (
					target_id, target_url, defer_scan_reason,
				),
				return_code=0,
			)
			return True

		scan_started = False
		if start_scan_on_submit:
			scan_info = _start_acunetix_scan_direct(
				base_url=base_url,
				headers=headers,
				verify=verify,
				timeout=settings.ACUNETIX_REQUEST_TIMEOUT,
				target_id=target_id,
			)
			scan_started = bool(scan_info)
			if not scan_started:
				_record_submission(
					task, command,
					"FAILED — target_id=%s url=%s target added but scan did not start" % (target_id, target_url),
					return_code=1,
				)
				return False

		_persist_acunetix_submission(host, target_url, target_id, scan_history_id)
	except Exception as exc:
		logger.error("Acunetix target submission failed for %s: %s", host, exc)
		_record_submission(
			task, command,
			"FAILED — %s while submitting the target" % type(exc).__name__,
			return_code=1,
		)
		return False

	_record_submission(
		task, command,
		"SUBMITTED — target_id=%s url=%s%s" % (
			target_id, target_url, " (scan started)" if scan_started else ""
		),
		return_code=0,
	)
	return True


def acunetix_submit_live_subdomains(
		self,
		scan_history_id=None,
		ctx=None,
		description=None):
	"""Register every live subdomain of a scan as an Acunetix target.

	Each host is submitted at most once per `resubmit_after_days` window, and every
	decision — submitted, skipped, deferred, failed — is written as a Command row on
	this task's timeline entry, so the scan timeline shows exactly what was added.
	``www.<host>`` is skipped when ``<host>`` itself is live: both serve the same site.

	Hosts go out in batches of `submission_batch_size` with `submission_batch_pause`
	seconds between batches. With `start_scan_on_submit`, at most `max_scans_per_run`
	scans are started; the hosts past that limit are added as targets only and are
	not recorded as submitted, so the next run starts the next slice of them instead
	of queueing hundreds of scans in Acunetix at once.

	Args:
		scan_history_id: ScanHistory PK.
		ctx: Temporal workflow context; carries the engine's yaml configuration.
		description: Human-readable task description (unused, kept for the task API).

	Returns:
		bool: True when the submission pass completed, False when it could not run.
	"""
	ctx = ctx or {}
	scan_history_id = scan_history_id or ctx.get('scan_history_id')
	yaml_configuration = ctx.get('yaml_configuration') or getattr(self, 'yaml_configuration', {}) or {}
	acunetix_config = (yaml_configuration.get('vulnerability_scan') or {}).get('acunetix') or {}

	resubmit_after_days = _resolve_resubmit_after_days(
		acunetix_config.get('resubmit_after_days', DEFAULT_RESUBMIT_AFTER_DAYS)
	)
	start_scan_on_submit = bool(acunetix_config.get('start_scan_on_submit', False))
	batch_size = _resolve_int_option(
		acunetix_config.get('submission_batch_size'), 'submission_batch_size',
		DEFAULT_SUBMISSION_BATCH_SIZE, 1, MAX_SUBMISSION_BATCH_SIZE,
	)
	batch_pause = _resolve_int_option(
		acunetix_config.get('submission_batch_pause'), 'submission_batch_pause',
		DEFAULT_SUBMISSION_BATCH_PAUSE, 0, MAX_SUBMISSION_BATCH_PAUSE,
	)
	max_scans = _resolve_int_option(
		acunetix_config.get('max_scans_per_run'), 'max_scans_per_run',
		DEFAULT_MAX_SCANS_PER_RUN, 1, MAX_SCANS_PER_RUN,
	)

	creds = AcunetixAPIKey.objects.first()
	if not (creds and creds.server_url and creds.api_key):
		return _fail(self, "Acunetix API keys not fully configured in vault.")

	subdomains = list(get_live_subdomains_for_submission(scan_history_id))
	if not subdomains:
		logger.info("No live subdomains to submit to Acunetix for scan %s", scan_history_id)
		return True

	hosts = [s.name for s in subdomains]
	last_submitted = _last_submissions(hosts)
	cutoff = timezone.now() - timedelta(days=resubmit_after_days)
	recent = {host: at for host, at in last_submitted.items() if at >= cutoff}
	logger.info(
		"Acunetix submission for scan %s: %d live subdomains, %d already sent in the last %d day(s)",
		scan_history_id, len(hosts), len(recent), resubmit_after_days,
	)

	base_url = str(creds.server_url).rstrip('/')
	headers = {'X-Auth': creds.api_key, 'Content-Type': 'application/json'}
	import os as _os
	verify = _os.environ.get('ACUNETIX_CA_BUNDLE', False)

	from reNgine.host_dedup import duplicate_hosts, www_twin

	live_hosts = set(hosts)
	# Hosts serving the same site as another one (Target Deduplication), plus the
	# www rule for engines that run without that step: scanning both doubles the
	# Acunetix work for the same findings.
	duplicates = duplicate_hosts(scan_history_id)
	pending = []
	for subdomain in subdomains:
		host = subdomain.name
		same_site_as = www_twin(host, live_hosts)
		if same_site_as is None and host.lower() in duplicates:
			target, reason = duplicates[host.lower()]
			same_site_as = f"{target} ({reason})"
		if same_site_as:
			_record_submission(
				self,
				f"acunetix submit {host}",
				f"SKIPPED — same site as {same_site_as}",
				return_code=0,
			)
		elif host in recent:
			_record_submission(
				self,
				f"acunetix submit {host}",
				f"SKIPPED — already submitted {recent[host].isoformat()} "
				f"(within {resubmit_after_days}d window)",
				return_code=0,
			)
		else:
			pending.append((host, subdomain.http_url or f"https://{host}"))
	skipped = len(subdomains) - len(pending)
	# Never-submitted hosts first, then the longest-waiting ones, so with a scan
	# limit per run the end of a long host list is not starved once the hosts at
	# its start leave the re-submission window again.
	pending.sort(key=lambda item: (item[0] in last_submitted, last_submitted.get(item[0], cutoff)))

	known_targets = None
	try:
		if pending:
			known_targets = _list_acunetix_targets(base_url, headers, verify, settings.ACUNETIX_REQUEST_TIMEOUT)
	except (requests.exceptions.RequestException, ValueError) as exc:
		logger.warning("Could not list Acunetix targets, looking each host up instead: %s", type(exc).__name__)

	defer_reason = f"the limit of {max_scans} scans per run was reached; a later scan run starts it"
	submitted, deferred, failed = 0, 0, 0
	batches = [pending[i:i + batch_size] for i in range(0, len(pending), batch_size)]
	for index, batch in enumerate(batches, start=1):
		if index > 1 and batch_pause:
			time.sleep(batch_pause)
		logger.info(
			"Acunetix submission for scan %s: batch %d/%d (%d hosts)",
			scan_history_id, index, len(batches), len(batch),
		)
		for host, target_url in batch:
			defer = start_scan_on_submit and submitted >= max_scans
			if not _submit_acunetix_host(
				self,
				host=host,
				target_url=target_url,
				base_url=base_url,
				headers=headers,
				verify=verify,
				start_scan_on_submit=start_scan_on_submit,
				scan_history_id=scan_history_id,
				known_targets=known_targets,
				defer_scan_reason=defer_reason if defer else None,
			):
				failed += 1
			elif defer:
				deferred += 1
			else:
				submitted += 1

	logger.info(
		"Acunetix submission complete for scan %s: submitted=%d deferred=%d skipped=%d failed=%d",
		scan_history_id, submitted, deferred, skipped, failed,
	)
	if failed and not (submitted or deferred):
		return _fail(self, f"All {failed} Acunetix target submissions failed.")
	return True
