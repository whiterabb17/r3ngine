"""Vulnerability persistence (save_vulnerability) and tool-output parsers (Semgrep, Retire.js, InQL, LLM reports).

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import os
import re
import logging

from urllib.parse import urlparse
from django.utils import timezone

from reNgine.definitions import SEMGREP_SEVERITY_MAP
from reNgine.utilities import replace_nulls
from startScan.models import CveId, CweId, Vulnerability, VulnerabilityReference, VulnerabilityTags
from reNgine.common_func.url_utils import get_subdomain_from_url

logger = logging.getLogger(__name__)


def save_vulnerability(vuln_data=None, scan_history=None, target_domain=None, dedup_fields=None, **kwargs):
	# Support both positional and keyword arguments for backward compatibility
	if vuln_data and isinstance(vuln_data, dict):
		vuln_data.update(kwargs)
		if scan_history:
			vuln_data['scan_history'] = scan_history
		if target_domain:
			vuln_data['target_domain'] = target_domain
	else:
		vuln_data = kwargs
		if scan_history:
			vuln_data['scan_history'] = scan_history
		if target_domain:
			vuln_data['target_domain'] = target_domain

	# Ensure severity is an integer if passed as a string
	severity = vuln_data.get('severity')
	if isinstance(severity, str):
		from reNgine.definitions import NUCLEI_SEVERITY_MAP
		vuln_data['severity'] = NUCLEI_SEVERITY_MAP.get(severity.lower(), 2)  # default to Medium

	references = vuln_data.pop('references', [])
	cve_ids = vuln_data.pop('cve_ids', [])
	cwe_ids = vuln_data.pop('cwe_ids', [])
	tags = vuln_data.pop('tags', [])
	subscan = vuln_data.pop('subscan', None)

	exploit_url = vuln_data.pop('exploit_url', None)
	validation_status = vuln_data.pop('validation_status', 'new')

	# If subdomain is not provided, try to find it from http_url
	subdomain = vuln_data.get('subdomain')
	http_url = vuln_data.get('http_url')
	scan_history = vuln_data.get('scan_history')
	target_domain = vuln_data.get('target_domain')

	if not subdomain and http_url and scan_history and target_domain:
		from reNgine.utils.task import save_subdomain
		subdomain_name = get_subdomain_from_url(http_url)
		subdomain, _ = save_subdomain(subdomain_name, ctx={
			'scan_history_id': scan_history.id,
			'domain_id': target_domain.id,
		})
		if subdomain:
			vuln_data['subdomain'] = subdomain

	# remove nulls
	vuln_data = replace_nulls(vuln_data)

	# agent_enrichment is NOT NULL jsonb with no DB-level DEFAULT. Explicit None
	# (or a missing key on some insert paths) raises IntegrityError on create.
	enrichment = vuln_data.get('agent_enrichment', None)
	if enrichment is None or not isinstance(enrichment, dict):
		vuln_data['agent_enrichment'] = {}

	# Check for False Positive rules
	is_suppressed = False
	try:
		from startScan.models import FalsePositiveRule
		rules = FalsePositiveRule.objects.filter(target_domain=target_domain, is_active=True)
		for rule in rules:
			if rule.matches(vuln_data.get('name', ''), http_url):
				is_suppressed = True
				break
	except Exception as e:
		logger.error("Error checking FP rules: %s", e)

	if is_suppressed:
		vuln_data['is_suppressed'] = True

	# Create vulnerability — use narrower dedup key when caller specifies one,
	# so volatile fields like description don't cause duplicate rows on re-scan.
	if not dedup_fields:
		dedup_fields = ['name', 'scan_history']
		if 'subdomain' in vuln_data:
			dedup_fields.append('subdomain')
		if 'http_url' in vuln_data:
			dedup_fields.append('http_url')

	lookup = {k: vuln_data.pop(k) for k in dedup_fields if k in vuln_data}
	vuln, created = Vulnerability.objects.update_or_create(defaults=vuln_data, **lookup)
	vuln_data.update(lookup)  # restore for use below (tags, auth-candidate, etc.)
	if created:
		vuln.discovered_date = timezone.now()
		vuln.open_status = True
		if exploit_url:
			vuln.exploit_url = exploit_url
		vuln.validation_status = validation_status
		vuln.save()

		# Centralized Brute-Force Candidate Registration
		auth_keywords = ['login', 'admin', 'auth', 'portal', 'credentials', 'password']
		name = (vuln_data.get('name') or '').lower()
		description = (vuln_data.get('description') or '').lower()
		
		if any(k in name or k in description for k in auth_keywords):
			try:
				from reNgine.utilities import save_auth_candidate
				http_url = vuln_data.get('http_url', '')
				parsed = urlparse(http_url)
				port = parsed.port or (443 if parsed.scheme == 'https' else 80)
				target = parsed.hostname
				
				if target:
					save_auth_candidate(
						scan_history=scan_history,
						subdomain=subdomain,
						target=target,
						protocol='http',
						port=port,
						source_tool=vuln_data.get('type', 'vulnerability_engine'),
						tech_hint=name
					)
			except Exception as e:
				logger.error("Error registering AuthCandidate from vulnerability %s: %s", name, e)
	elif exploit_url and not vuln.exploit_url:
		vuln.exploit_url = exploit_url
		vuln.save()

	# Save vuln tags — collect then add in one call; no save() needed after M2M add
	if tags:
		tag_objs = []
		for tag_name in tags:
			tag, _ = VulnerabilityTags.objects.get_or_create(name=tag_name)
			tag_objs.append(tag)
		vuln.tags.add(*tag_objs)

	# Save CVEs
	if cve_ids:
		cve_objs = []
		for cve_id in cve_ids:
			if not cve_id or not str(cve_id).strip():
				continue
			normalized = str(cve_id).strip().upper()
			# Accept bare YYYY-NNNNN values (missing the CVE- prefix)
			if re.match(r'^\d{4}-\d+$', normalized):
				normalized = 'CVE-' + normalized
			cve, _ = CveId.objects.get_or_create(name=normalized)
			cve_objs.append(cve)
		if cve_objs:
			vuln.cve_ids.add(*cve_objs)

	# Save CWEs
	if cwe_ids:
		cwe_objs = []
		for cwe_id in cwe_ids:
			if not cwe_id or not str(cwe_id).strip():
				continue
			cwe, _ = CweId.objects.get_or_create(name=str(cwe_id).strip())
			cwe_objs.append(cwe)
		if cwe_objs:
			vuln.cwe_ids.add(*cwe_objs)

	# Save vuln references
	if references:
		ref_objs = []
		for url in references:
			ref, _ = VulnerabilityReference.objects.get_or_create(url=url)
			ref_objs.append(ref)
		vuln.references.add(*ref_objs)

	# Save subscan id in vuln object
	if subscan:
		from startScan.models import SubScan
		subscan_pk = subscan.pk if hasattr(subscan, 'pk') else subscan
		if SubScan.objects.filter(pk=subscan_pk).exists():
			vuln.vuln_subscan_ids.add(subscan)
			# No vuln.save() needed — M2M add writes directly to the join table

	return vuln, created


def parse_llm_vulnerability_report(report):
	# Do not globally strip '**' as we want to preserve markdown bolding in the Remediation playbook.
	data = {}
	# Split on the main headers, optionally allowing markdown bold/italic asterisks or header hashes around them.
	sections = re.split(r'\n(?=[#\s\*]*(?:Description|Impact|Remediation|References)[#\s\*]*\s*:)', report.strip(), flags=re.IGNORECASE)

	for section in sections:
		if not section.strip():
			continue

		# Accept headers with or without asterisks/hashes, and with or without spaces.
		match = re.match(
			r'^[#\s\*]*(Description|Impact|Remediation|References)[#\s\*]*\s*:\s*(.*)',
			section.strip(),
			re.DOTALL | re.IGNORECASE,
		)
		if not match:
			continue

		section_title = match.group(1).title()
		content = match.group(2).strip()

		if section_title == 'Description':
			data['description'] = content
		elif section_title == 'Impact':
			data['impact'] = content
		elif section_title == 'Remediation':
			data['remediation'] = content
		elif section_title == 'References':
			data['references'] = [ref.strip() for ref in content.split('\n') if ref.strip()]

	return data


_SEMGREP_LABEL_MAP = {
	'detected-facebook-oauth': 'Facebook OAuth Token',
	'detected-github-oauth': 'GitHub OAuth Token',
	'detected-google-oauth': 'Google OAuth Token',
	'detected-twitter-oauth': 'Twitter OAuth Token',
	'generic-api-key': 'Generic API Key',
	'detected-aws-account-id': 'AWS Account ID',
	'detected-aws-access-key': 'AWS Access Key',
	'detected-aws-secret-key': 'AWS Secret Key',
	'stripe-secret-key': 'Stripe Secret Key',
	'stripe-publishable-key': 'Stripe Publishable Key',
	'slack-api-token': 'Slack API Token',
	'slack-webhook-url': 'Slack Webhook URL',
	'github-personal-access-token': 'GitHub Personal Access Token',
	'gitlab-personal-access-token': 'GitLab Personal Access Token',
	'sendgrid-api-token': 'SendGrid API Token',
	'twilio-api-key': 'Twilio API Key',
	'jwt-token': 'JWT Token',
	'private-key': 'Private Key',
	'rsa-private-key': 'RSA Private Key',
	'ssh-private-key': 'SSH Private Key',
	'password-in-url': 'Password in URL',
	'hardcoded-password': 'Hardcoded Password',
	'hardcoded-secret': 'Hardcoded Secret',
	'basic-auth-credentials': 'Basic Auth Credentials',
	'firebase-api-key': 'Firebase API Key',
	'heroku-api-key': 'Heroku API Key',
	'mailchimp-api-key': 'Mailchimp API Key',
	'paypal-braintree-access-token': 'PayPal Braintree Token',
	'shopify-access-token': 'Shopify Access Token',
	'twitch-api-key': 'Twitch API Key',
}


_SEMGREP_STRIP_PREFIXES = {
	'usr', 'src', 'github', 'semgrep_rules', 'rules', 'app', 'p',
	'semgrep_vulnerability_temp', 'semgrep_secret_temp', 'temp',
}


_SEMGREP_BOILERPLATE = {'detected', 'generic', 'security'}


def clean_semgrep_check_id(check_id: str) -> str:
	"""Return a human-readable label for a Semgrep check ID.

	Lookup table takes priority; unknown slugs are smart-parsed.
	"""
	if not check_id:
		return ""

	parts = check_id.split('.')

	# Strip leading path prefixes
	start_idx = 0
	while start_idx < len(parts) and parts[start_idx].lower() in _SEMGREP_STRIP_PREFIXES:
		start_idx += 1
	clean_parts = parts[start_idx:]

	if not clean_parts:
		return check_id

	# Deduplicate repeating suffix
	if len(clean_parts) >= 2 and clean_parts[-1].lower() == clean_parts[-2].lower():
		clean_parts.pop()

	# Try lookup against the final dot-segment
	slug = clean_parts[-1]
	if slug in _SEMGREP_LABEL_MAP:
		return _SEMGREP_LABEL_MAP[slug]

	# Smart-parse fallback: title-case words, drop boilerplate
	words = slug.replace('-', ' ').split()
	words = [w for w in words if w.lower() not in _SEMGREP_BOILERPLATE]
	return ' '.join(w.title() for w in words) if words else slug


def categorize_secret_type(label: str) -> tuple[str, str]:
	"""Return (category_name, color_key) for a human-readable secret label.

	color_key matches the frontend colorKey: 'error' | 'warning' | 'info' | 'default'.
	"""
	lower = label.lower()
	if any(kw in lower for kw in ('private key', 'rsa', 'ssh')):
		return ('Private Key', 'error')
	# Check oauth before 'auth' to avoid 'oauth' matching the credential 'auth' substring
	if any(kw in lower for kw in ('oauth', 'access token')):
		return ('OAuth Token', 'info')
	if any(kw in lower for kw in ('password', 'credential', 'auth', 'login', 'hardcoded secret')):
		return ('Credential', 'error')
	if any(kw in lower for kw in ('api key', 'api token', 'access key')):
		return ('API Key', 'warning')
	return ('Secret', 'warning')


def parse_semgrep_result(result):
	"""Parses a single Semgrep match into reNgine vulnerability format.

	Args:
		result (dict): Semgrep finding match dictionary.

	Returns:
		dict: Vulnerability data dictionary ready for saving.
	"""
	check_id = result.get('check_id', '')
	# NOTE: clean_semgrep_check_id returns human-readable labels since v3.6.4; historical DB rows retain dotted-path format.
	cleaned_check_id = clean_semgrep_check_id(check_id)
	return {
		'name': f"Semgrep: {cleaned_check_id}",
		'description': result.get('extra', {}).get('message', ''),
		'severity': SEMGREP_SEVERITY_MAP.get(result.get('extra', {}).get('severity', 'INFO'), 0),
		'http_url': result.get('path', ''),
		'type': 'SAST',
		'source': 'Semgrep',
	}


def parse_retire_result(result):
	"""Parses a single Retire.js vulnerability into reNgine vulnerability format.

	Args:
		result (dict): Retire.js finding dictionary.

	Returns:
		dict: Vulnerability data dictionary ready for saving.
	"""
	return {
		'name': f"Retire.js: {result.get('component')} ({result.get('version')})",
		'description': result.get('info', ''),
		'severity': 2, # Default medium for library vulnerabilities
		'http_url': result.get('file', ''),
		'type': 'SCA',
		'source': 'Retire.js',
	}


def parse_inql_results(directory_path):
	"""
	Parses InQL output directory for discovered GraphQL endpoints.
	InQL creates a directory structure like:
	target_domain/
		queries/
		schema.json
		...
	"""
	endpoints = []
	if not os.path.exists(directory_path):
		return endpoints

	# InQL often identifies the GraphQL endpoint by its structure
	# We look for files or directories that indicate a successful discovery
	for root, dirs, files in os.walk(directory_path):
		for file in files:
			if file == 'schema.json' or file.endswith('.graphql'):
				# The parent directory or the root might be the endpoint path
				# This is a heuristic. In reNgine, we often know the base URL.
				# We return the "fact" that GraphQL was found.
				endpoints.append({
					'type': 'GraphQL',
					'discovered_file': os.path.join(root, file)
				})
	return endpoints
