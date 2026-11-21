import logging
import socket
import ssl
from dataclasses import dataclass

import requests
from django.db.models import Q
from django.utils import timezone

from dashboard.models import CensysAPIKey, ShodanAPIKey
from reNgine.utils.opsec import get_opsec_manager
from startScan.models import Subdomain, WafBypassFinding

logger = logging.getLogger(__name__)

# Hard WAF / edge block statuses. 401 (auth) and bare 503 (origin overload)
# are inconclusive without a challenge-body marker.
_WAF_BLOCK_STATUSES = frozenset({403, 406, 429})

# Candidate must land in this set (and not look blocked) to count as a bypass.
# 5xx / other transport failures are inconclusive, not "allowed".
_WAF_ALLOWED_STATUSES = frozenset({200, 201, 204, 301, 302, 303, 307, 308})

# Soft-block body markers when status alone is not decisive.
# Keep these specific — bare vendor names false-positive on normal pages.
_WAF_BLOCK_BODY_MARKERS = (
	'attention required',
	'access denied',
	'request blocked',
	'web application firewall',
	'cf-error',
	'the request could not be satisfied',
	'not acceptable',
)

_PROBE_PAYLOAD = '/etc/passwd'
_PROBE_TIMEOUT = 10
_VALIDATE_ROUNDS = 2


@dataclass(frozen=True)
class _ProbeResult:
	status_code: int
	body_snippet: str
	blocked: bool


def _response_looks_blocked(status_code: int, body: str) -> bool:
	if status_code in _WAF_BLOCK_STATUSES:
		return True
	lowered = (body or '').lower()
	return any(marker in lowered for marker in _WAF_BLOCK_BODY_MARKERS)


def _response_looks_allowed(status_code: int, body: str) -> bool:
	"""True only when the probe clearly got through (not blocked / not 5xx)."""
	if status_code not in _WAF_ALLOWED_STATUSES:
		return False
	return not _response_looks_blocked(status_code, body)


def _probe_result_from_response(response) -> _ProbeResult:
	body = ''
	try:
		body = (response.text or '')[:2000]
	except Exception:
		body = ''
	status_code = int(getattr(response, 'status_code', 0) or 0)
	return _ProbeResult(
		status_code=status_code,
		body_snippet=body,
		blocked=_response_looks_blocked(status_code, body),
	)


class OriginDiscoveryManager:
	"""
	Manager for discovering the original IP of a WAF-protected domain.
	"""
	def __init__(self, subdomain_obj):
		self.subdomain = subdomain_obj
		self.domain = subdomain_obj.name
		self.shodan_key = self._get_shodan_key()
		self.censys_key = self._get_censys_key()
		self.opsec = get_opsec_manager()

	def _get_shodan_key(self):
		key_obj = ShodanAPIKey.objects.first()
		return key_obj.key if key_obj else None

	def _get_censys_key(self):
		key_obj = CensysAPIKey.objects.first()
		return key_obj.api_key if key_obj else None

	def find_origin(self, use_shodan=True, use_censys=True, use_heuristics=True):
		results = set()

		if use_shodan and self.shodan_key:
			results.update(self._query_shodan())

		if use_censys and self.censys_key:
			results.update(self._query_censys())

		if use_heuristics:
			results.update(self._internal_heuristics())

		# Filter out known WAF/CDN IPs if possible
		# (For now we just return all found IPs)
		return list(results)

	def _query_shodan(self):
		ips = []
		try:
			# Query by hostname
			url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query=hostname:{self.domain}"
			response = requests.get(url, timeout=10)
			if response.status_code == 200:
				data = response.json()
				for match in data.get('matches', []):
					ips.append(match.get('ip_str'))

			# Query by SSL serial if available
			cert_serial = self._get_ssl_serial()
			if cert_serial:
				url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query=ssl.cert.serial:{cert_serial}"
				response = requests.get(url, timeout=10)
				if response.status_code == 200:
					data = response.json()
					for match in data.get('matches', []):
						ips.append(match.get('ip_str'))
		except Exception as e:
			logger.error("Shodan query failed for %s: %s", self.domain, str(e))
		return ips

	def _query_censys(self):
		ips = []
		try:
			from censys_platform import SDK, SearchQueryInputBody
			sdk = SDK(personal_access_token=self.censys_key)
			query = "services.tls.certificates.leaf_data.names: %s" % self.domain
			response = sdk.global_data.search(
				search_query_input_body=SearchQueryInputBody(query=query, page_size=100)
			)
			for hit in (response.result.hits or []):
				host = getattr(hit, 'host_v1', None)
				if host:
					resource = getattr(host, 'resource', None) or {}
					ip = getattr(resource, 'ip', None) or resource.get('ip')
					if ip:
						ips.append(ip)
		except Exception as e:
			logger.error("Censys query failed for %s: %s", self.domain, e)
		return ips

	def _internal_heuristics(self):
		ips = []
		# 1. Check for common 'origin' subdomains in the same project
		common_prefixes = ['direct', 'origin', 'dev', 'stage', 'backend', 'vps']
		base_domain = '.'.join(self.domain.split('.')[-2:])

		related_subdomains = Subdomain.objects.filter(
			Q(name__icontains='direct') |
			Q(name__icontains='origin') |
			Q(name__icontains='dev'),
			name__endswith=base_domain
		).exclude(id=self.subdomain.id)

		for sub in related_subdomains:
			# Get IP addresses for these subdomains
			for ip_obj in sub.ip_addresses.all():
				ips.append(ip_obj.address)

		return ips

	def _get_ssl_serial(self):
		"""
		Retrieves the SSL certificate serial number for the target domain.
		Used for origin discovery via Shodan.
		"""
		try:
			from cryptography import x509
			from cryptography.hazmat.backends import default_backend

			hostname = self.domain
			ctx = ssl.create_default_context()
			# Disable verification as we only need the serial metadata
			# Origin IPs often have self-signed or expired certificates
			ctx.check_hostname = False
			ctx.verify_mode = ssl.CERT_NONE

			with socket.create_connection((hostname, 443), timeout=5) as sock:
				with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
					cert_der = ssock.getpeercert(binary_form=True)
					cert = x509.load_der_x509_certificate(cert_der, default_backend())
					return cert.serial_number
		except Exception as e:
			logger.debug("SSL serial retrieval failed for %s: %s", self.domain, str(e))
			return None


class WafBypassOrchestrator:
	"""
	Orchestrator for testing WAF bypass techniques.

	Header probes are staged:
	1. baseline (payload, no bypass header) must look blocked
	2. candidate (same payload + header) must look allowed → potential
	3. confirmation round(s) must reproduce the differential → validated
	Only validated bypasses are persisted.
	"""
	def __init__(self, subdomain_obj):
		self.subdomain = subdomain_obj
		self.target_url = f"https://{subdomain_obj.name}"
		self.opsec = get_opsec_manager()

	def run_all_tests(self, use_nuclei=True, use_benchmarking=True):
		findings = []
		if use_benchmarking:
			findings.extend(self._test_headers())

		if use_nuclei:
			findings.extend(self._run_nuclei_bypass())

		return findings

	def _probe_url(self) -> str:
		return f"{self.target_url}?file={_PROBE_PAYLOAD}"

	def _send_probe(self, headers=None) -> _ProbeResult | None:
		try:
			response = requests.get(
				self._probe_url(),
				headers=headers or {},
				timeout=_PROBE_TIMEOUT,
				verify=False,
			)
			return _probe_result_from_response(response)
		except Exception as exc:
			logger.error(
				"WAF bypass probe failed for %s headers=%s: %s",
				self.subdomain.name,
				headers,
				exc,
			)
			return None

	def _record_command(self, activity, scan_history, header, value):
		from startScan.models import Command

		Command.objects.create(
			command=f"GET {self._probe_url()} [Header: {header}: {value}]",
			time=timezone.now(),
			scan_history=scan_history,
			activity=activity,
		)

	def _is_validated_bypass(self, header: str, value: str) -> tuple[bool, _ProbeResult | None, _ProbeResult | None]:
		"""Re-run baseline vs candidate; both must keep the differential."""
		last_baseline = None
		last_candidate = None
		for round_idx in range(1, _VALIDATE_ROUNDS + 1):
			baseline = self._send_probe()
			candidate = self._send_probe(headers={header: value})
			last_baseline, last_candidate = baseline, candidate
			if baseline is None or candidate is None:
				logger.info(
					"[WAF-BYPASS] validation abort | host=%s header=%s round=%s — probe error",
					self.subdomain.name, header, round_idx,
				)
				return False, last_baseline, last_candidate
			if not baseline.blocked:
				logger.info(
					"[WAF-BYPASS] validation reject | host=%s header=%s round=%s — baseline no longer blocked (%s)",
					self.subdomain.name, header, round_idx, baseline.status_code,
				)
				return False, last_baseline, last_candidate
			if not _response_looks_allowed(candidate.status_code, candidate.body_snippet):
				logger.info(
					"[WAF-BYPASS] validation reject | host=%s header=%s round=%s — candidate not clearly allowed (%s)",
					self.subdomain.name, header, round_idx, candidate.status_code,
				)
				return False, last_baseline, last_candidate
			# Soft-block pages often keep HTTP 200 while flipping blocked→allowed;
			# the differential is blocked vs clearly-allowed, not status inequality.
		return True, last_baseline, last_candidate

	def _test_headers(self):
		"""
		Test susceptibility to various HTTP headers used for WAF bypass.

		Candidates are only persisted after differential validation against a
		blocked baseline (same payload without the bypass header).
		"""
		bypass_headers = {
			'X-Forwarded-For': '127.0.0.1',
			'X-Originating-IP': '127.0.0.1',
			'X-Remote-IP': '127.0.0.1',
			'X-Remote-Addr': '127.0.0.1',
			'X-Client-IP': '127.0.0.1',
			'X-Real-IP': '127.0.0.1',
			'True-Client-IP': '127.0.0.1',
			'Client-IP': '127.0.0.1',
			'Forwarded': 'for=127.0.0.1;proto=http'
		}

		findings = []
		scan_history = self.subdomain.scan_history
		from startScan.models import ScanActivity
		activity = ScanActivity.objects.filter(scan_of=scan_history, name='waf_bypass').last()

		baseline = self._send_probe()
		if baseline is None:
			logger.warning(
				"[WAF-BYPASS] skip host=%s — baseline probe failed",
				self.subdomain.name,
			)
			return findings
		if not baseline.blocked:
			logger.info(
				"[WAF-BYPASS] skip host=%s — baseline not blocked (status=%s); "
				"header tests would be inconclusive",
				self.subdomain.name,
				baseline.status_code,
			)
			return findings

		logger.info(
			"[WAF-BYPASS] baseline blocked | host=%s status=%s — probing headers",
			self.subdomain.name,
			baseline.status_code,
		)

		for header, value in bypass_headers.items():
			try:
				candidate = self._send_probe(headers={header: value})
				if candidate is None:
					continue
				if not _response_looks_allowed(candidate.status_code, candidate.body_snippet):
					continue

				logger.info(
					"[WAF-BYPASS] potential | host=%s header=%s baseline=%s candidate=%s — validating",
					self.subdomain.name,
					header,
					baseline.status_code,
					candidate.status_code,
				)

				ok, validated_baseline, validated_candidate = self._is_validated_bypass(header, value)
				if not ok or validated_baseline is None or validated_candidate is None:
					logger.info(
						"[WAF-BYPASS] discarded potential | host=%s header=%s — failed validation",
						self.subdomain.name,
						header,
					)
					continue

				self._record_command(activity, scan_history, header, value)
				evidence = (
					f"Validated differential: baseline status={validated_baseline.status_code} "
					f"(blocked) vs {header}: {value} status={validated_candidate.status_code} "
					f"(allowed) over {_VALIDATE_ROUNDS} confirmation round(s)."
				)
				finding = WafBypassFinding.objects.create(
					subdomain=self.subdomain,
					technique=f"Header Injection: {header}",
					is_successful=True,
					payload_evidence=evidence,
				)
				findings.append(finding)
				logger.info(
					"[WAF-BYPASS] validated | host=%s header=%s baseline=%s/%s candidate=%s/%s",
					self.subdomain.name,
					header,
					validated_baseline.status_code,
					'blocked' if validated_baseline.blocked else 'allowed',
					validated_candidate.status_code,
					'blocked' if validated_candidate.blocked else 'allowed',
				)
			except Exception as e:
				logger.error("Header bypass test failed for %s: %s", header, str(e))

		return findings

	def _run_nuclei_bypass(self):
		"""
		Placeholder for Nuclei bypass execution.
		In reNgine, this is usually handled by calling the nuclei binary.
		"""
		# This will be implemented in the Celery task to use the existing Nuclei infrastructure
		return []
