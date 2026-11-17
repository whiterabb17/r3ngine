import logging

from reNgine.definitions import *

logger = logging.getLogger(__name__)


# Public (all-users) ACL flags that mean the bucket is misconfigured for assessment.
_S3_PUBLIC_PERM_LABELS = (
	('perm_all_users_read', 'public read'),
	('perm_all_users_write', 'public write'),
	('perm_all_users_read_acl', 'public read ACL'),
	('perm_all_users_write_acl', 'public write ACL'),
	('perm_all_users_full_control', 'public full control'),
)


def parse_s3scanner_result(line):
	'''
		Parses and returns s3Scanner Data
	'''
	bucket = line['bucket']
	return {
		'name': bucket['name'],
		'region': bucket['region'],
		'provider': bucket['provider'],
		'owner_display_name': bucket['owner_display_name'],
		'owner_id': bucket['owner_id'],
		'perm_auth_users_read': bucket['perm_auth_users_read'],
		'perm_auth_users_write': bucket['perm_auth_users_write'],
		'perm_auth_users_read_acl': bucket['perm_auth_users_read_acl'],
		'perm_auth_users_write_acl': bucket['perm_auth_users_write_acl'],
		'perm_auth_users_full_control': bucket['perm_auth_users_full_control'],
		'perm_all_users_read': bucket['perm_all_users_read'],
		'perm_all_users_write': bucket['perm_all_users_write'],
		'perm_all_users_read_acl': bucket['perm_all_users_read_acl'],
		'perm_all_users_write_acl': bucket['perm_all_users_write_acl'],
		'perm_all_users_full_control': bucket['perm_all_users_full_control'],
		'num_objects': bucket['num_objects'],
		'size': bucket['bucket_size']
	}


def s3_bucket_public_issues(bucket_result):
	"""Return human-readable public ACL issues from a parsed s3scanner result."""
	issues = []
	for key, label in _S3_PUBLIC_PERM_LABELS:
		if int(bucket_result.get(key) or 0):
			issues.append(label)
	return issues


def s3_bucket_misconfig_severity(bucket_result):
	"""Severity for a misconfigured bucket: write/full-control → high, read → medium."""
	if any(int(bucket_result.get(k) or 0) for k in (
		'perm_all_users_write',
		'perm_all_users_write_acl',
		'perm_all_users_full_control',
	)):
		return 3
	if any(int(bucket_result.get(k) or 0) for k in (
		'perm_all_users_read',
		'perm_all_users_read_acl',
	)):
		return 2
	return 2


def build_s3_bucket_misconfig_vuln(bucket_result, issues=None):
	"""Build save_vulnerability kwargs for a publicly misconfigured bucket.

	Returns None when the bucket has no public ACL issues.
	"""
	issues = list(issues) if issues is not None else s3_bucket_public_issues(bucket_result)
	if not issues:
		return None

	provider = (bucket_result.get('provider') or 'unknown').strip() or 'unknown'
	name = (bucket_result.get('name') or '').strip()
	region = (bucket_result.get('region') or '').strip() or 'unknown'
	num_objects = int(bucket_result.get('num_objects') or 0)
	size = int(bucket_result.get('size') or 0)
	issue_list = ', '.join(issues)
	http_url = f's3://{provider}/{name}'

	return {
		'name': f'Misconfigured Cloud Bucket ({provider}): {name}',
		'severity': s3_bucket_misconfig_severity(bucket_result),
		'type': 'Cloud Misconfiguration',
		'source': 's3scanner',
		'template_id': 's3scanner-public-acl',
		'http_url': http_url,
		'description': (
			f'Cloud object-storage bucket `{name}` on provider `{provider}` '
			f'(region `{region}`) allows {issue_list}. '
			f'Enumerated objects={num_objects}, size={size}.'
		),
		'impact': (
			'Public bucket ACLs can expose or allow modification of stored objects, '
			'leading to data disclosure, tampering, malware hosting, or account abuse.'
		),
		'remediation': (
			'Remove public ACLs / policies that grant AllUsers read or write. '
			'Prefer private buckets with least-privilege IAM or signed URLs. '
			'Confirm bucket ownership and rotate any exposed credentials.'
		),
		'tags': ['cloud', 'bucket', 's3', 'misconfiguration', provider],
		'dedup_fields': ['name', 'http_url', 'scan_history'],
	}


def is_nuclei_finding(line):
	"""Return True for nuclei match JSON; False for -stats / other noise.

	Nuclei is invoked with ``-j -stats`` (and often ``-hang-monitor``). Stats
	lines are valid JSON objects without an ``info`` block, e.g.
	``{"duration":"...","percent":"37",...}``. Treating those as findings
	raises ``KeyError('info')`` and fails the whole RunNucleiActivity after the
	go-executor returns buffered stdout.
	"""
	if not isinstance(line, dict):
		return False
	info = line.get('info')
	return isinstance(info, dict)


def parse_nuclei_result(line):
	"""Parse results from nuclei JSON output.

	Args:
		line (dict): Nuclei JSON line output.

	Returns:
		dict | None: Vulnerability data, or None when ``line`` is not a finding
		(e.g. a ``-stats`` progress object from the go-executor stream).
	"""
	if not is_nuclei_finding(line):
		return None
	info = line['info']
	classification = info.get('classification') or {}
	return {
		'name': info.get('name', ''),
		'type': line.get('type', ''),
		'severity': NUCLEI_SEVERITY_MAP[info.get('severity', 'unknown')],
		'template': line.get('template', ''),
		'template_url': line.get('template-url', []),
		'template_id': line.get('template-id', ''),
		'description': info.get('description', ''),
		'matcher_name': line.get('matcher-name', ''),
		'curl_command': line.get('curl-command'),
		'request': line.get('request'),
		'response': line.get('response'),
		'extracted_results': line.get('extracted-results', []),
		'cvss_metrics': classification.get('cvss-metrics', ''),
		'cvss_score': classification.get('cvss-score'),
		'cve_ids': classification.get('cve-id', []) or classification.get('cve_id', []) or [],
		'cwe_ids': classification.get('cwe-id', []) or classification.get('cwe_id', []) or [],
		'references': info.get('reference', []) or [],
		'tags': info.get('tags', []) or [],
		'source': NUCLEI,
	}


def parse_dalfox_result(line):
	"""Parse results from dalfox JSON output.

	Args:
		line (dict): Dalfox JSON line output.

	Returns:
		dict: Vulnerability data.
	"""

	description = ''
	description += f" Evidence: {line.get('evidence')} <br>" if line.get('evidence') else ''
	description += f" Message: {line.get('message')} <br>" if line.get('message') else ''
	description += f" Payload: {line.get('message_str')} <br>" if line.get('message_str') else ''
	description += f" Vulnerable Parameter: {line.get('param')} <br>" if line.get('param') else ''

	return {
		'name': 'XSS (Cross Site Scripting)',
		'type': 'XSS',
		'severity': DALFOX_SEVERITY_MAP[line.get('severity', 'unknown')],
		'description': description,
		'source': DALFOX,
		'cwe_ids': [line.get('cwe')]
	}


def parse_crlfuzz_result(url):
	"""Parse CRLF results

	Args:
		url (str): CRLF Vulnerable URL

	Returns:
		dict: Vulnerability data.
	"""

	return {
		'name': 'CRLF (HTTP Response Splitting)',
		'type': 'CRLF',
		'severity': 2,
		'description': 'A CRLF (HTTP Response Splitting) vulnerability has been discovered.',
		'source': CRLFUZZ,
	}

def parse_smugglex_result(finding):
	return {
		'name': 'HTTP Request Smuggling',
		'type': 'HTTP Request Smuggling',
		'severity': 3,
		'description': f"Check Type: {finding.get('check_type')}\nMethod: {finding.get('method')}\nPayloads: {finding.get('payloads')}\nEndpoint: {finding.get('endpoint')}",
		'source': 'Smugglex',
		'extracted_results': str(finding)
	}

_SECOND_ORDER_SEVERITY: dict = {
	'LogNon200Queries': 3,  # HIGH — broken external resource, potential takeover
	'LogQueries': 0,        # INFO — external reference harvest (recon)
	'LogInline': 0,         # INFO — inline content harvest (recon)
}

_SECOND_ORDER_TYPE: dict = {
	'LogNon200Queries': 'Potential Resource Takeover',
	'LogQueries': 'External Resource Reference',
	'LogInline': 'Inline Content Discovered',
}

_SECOND_ORDER_NAME: dict = {
	'LogNon200Queries': 'Second-Order: Non-200 External Resource',
	'LogQueries': 'Second-Order: External Attribute Reference',
	'LogInline': 'Second-Order: Inline Content',
}


def parse_second_order_finding(mode: str, page_url: str, element_key: str, values: list) -> dict:
	"""Parse one entry from a second-order output file.

	Args:
		mode: JSON top-level key ('LogQueries', 'LogInline', 'LogNon200Queries').
		page_url: the page URL that was scanned (nested dict key in output).
		element_key: CSS-style selector ('img[src]') or element name ('script').
		values: list of values found for this selector on this page.

	Returns:
		dict suitable for **kwargs to save_vulnerability().
	"""
	description = (
		"Page: %s\nSelector: %s\nValues:\n%s"
		% (page_url, element_key, "\n".join("  - %s" % v for v in values))
	)
	return {
		'name': _SECOND_ORDER_NAME.get(mode, 'Second-Order Finding'),
		'type': _SECOND_ORDER_TYPE.get(mode, 'Information Disclosure'),
		'severity': _SECOND_ORDER_SEVERITY.get(mode, 0),
		'description': description,
		'http_url': page_url,
		'source': 'Second-Order',
		'extracted_results': values,
	}

def parse_favirecon_result(finding):
	return {
		'name': 'Favicon Discovered',
		'type': 'Info',
		'severity': 0,
		'description': f"Hash: {finding.get('hash', 'N/A')}",
		'source': 'Favirecon'
	}

def parse_sourcemapper_result(url, directory):
	return {
		'name': 'Exposed Source Maps',
		'type': 'Information Disclosure',
		'severity': 2,
		'description': f"Source maps extracted into {directory}",
		'http_url': url,
		'source': 'Sourcemapper'
	}

def parse_grpcurl_result(url, output):
	return {
		'name': 'gRPC Server Reflection Enabled',
		'type': 'Information Disclosure',
		'severity': 2,
		'description': f"Services:\n{output}",
		'http_url': url,
		'source': 'gRPCurl'
	}

def parse_julius_result(finding):
	return {
		'name': 'LLM Platform Exposed',
		'type': 'Information Disclosure',
		'severity': 2,
		'description': str(finding),
		'http_url': finding.get('url', ''),
		'source': 'Julius'
	}

def parse_gqlspection_result(url, output):
	return {
		'name': 'GraphQL Introspection Enabled',
		'type': 'Information Disclosure',
		'severity': 2,
		'description': "GraphQL introspection is enabled.",
		'http_url': url,
		'source': 'GQLSpection'
	}
