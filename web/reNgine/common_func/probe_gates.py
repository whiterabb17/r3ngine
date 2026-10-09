"""Scan-tier gates: GraphQL / OpenAPI endpoint probes and JWT token detection.

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import re
import logging

import requests

from startScan.models import EndPoint, Parameter, SecretLeak

logger = logging.getLogger(__name__)


_JWT_PARAM_RE = re.compile(
	r'\b(jwt|bearer|authorization|access_token|refresh_token|id_token|auth_token)\b',
	re.IGNORECASE,
)


_JWT_SECRET_TYPE_RE = re.compile(
	r'jwt|json[\s_-]?web[\s_-]?token|bearer[\s_-]?token',
	re.IGNORECASE,
)


# Paths probed to detect a GraphQL endpoint before running InQL / graphql-cop.
_GRAPHQL_PROBE_PATHS = [
	'/graphql',
	'/api/graphql',
	'/__graphql',
	'/graphiql',
	'/api/graphiql',
	'/v1/graphql',
]


# Paths probed to detect an OpenAPI spec — mirrors openapi_discoverer._SPEC_PROBE_PATHS
# so has_openapi_spec() and discover() cover the same set of paths.
_OPENAPI_PROBE_PATHS = [
	'/openapi.json',
	'/openapi.yaml',
	'/swagger.json',
	'/swagger.yaml',
	'/api-docs',
	'/api-docs.json',
	'/api/docs',
	'/api/openapi.json',
	'/api/swagger.json',
	'/v1/api-docs',
	'/v2/api-docs',
	'/v3/api-docs',
	'/docs/openapi.json',
	'/.well-known/openapi.json',
]


_PROBE_HEADERS = {'User-Agent': 'r3ngine-probe/1.0'}


_PROBE_TIMEOUT = 5  # seconds per HEAD request


#: A URL whose path *ends* at a GraphQL endpoint, rather than one that merely
#: mentions graphql somewhere. A front-end bundle ships its dependency tree, so
#: /node_modules/graphql/error/syntaxError.js contains "/graphql" and used to
#: both switch the GraphQL tooling on and become one of its targets.
#: Usable both as a Django `__iregex` lookup and with `re.search(..., re.I)`,
#: so the database filter and the Python check can never disagree.
GRAPHQL_ENDPOINT_URL_REGEX = r'/graphi?ql/?($|[?#])'


def is_graphql_endpoint_url(url: str) -> bool:
	"""True when the URL addresses a GraphQL endpoint itself."""
	return bool(url and re.search(GRAPHQL_ENDPOINT_URL_REGEX, url, re.IGNORECASE))


def has_graphql_endpoint(scan_id, url, proxy=None):
	"""Return True if a GraphQL endpoint has been detected for this scan.

	Checks existing EndPoint records first (zero network cost). Falls back to
	HEAD-probing common GraphQL paths if the DB has no evidence.
	"""
	logger.info('[GATE] has_graphql_endpoint: DB query — scan_id=%s url=%s', scan_id, url)
	db_match = EndPoint.objects.filter(
		scan_history_id=scan_id,
		http_url__iregex=GRAPHQL_ENDPOINT_URL_REGEX,
	).exists()
	if db_match:
		logger.info('[GATE] has_graphql_endpoint: DB hit — GraphQL endpoint already recorded for scan %s', scan_id)
		return True
	logger.info('[GATE] has_graphql_endpoint: DB miss — probing %d paths for %s (timeout=%ds each)', len(_GRAPHQL_PROBE_PATHS), url, _PROBE_TIMEOUT)

	from urllib.parse import urlparse as _urlparse
	parsed = _urlparse(url)
	base = '%s://%s' % (parsed.scheme, parsed.netloc)
	proxies = {'http': proxy, 'https': proxy} if proxy else None

	for path in _GRAPHQL_PROBE_PATHS:
		probe_url = base + path
		logger.info('[GATE] has_graphql_endpoint: probing %s', probe_url)
		try:
			resp = requests.head(
				probe_url,
				timeout=_PROBE_TIMEOUT,
				proxies=proxies,
				allow_redirects=True,
				headers=_PROBE_HEADERS,
			)
			logger.info('[GATE] has_graphql_endpoint: %s → HTTP %d', probe_url, resp.status_code)
			if resp.status_code not in (400, 404, 410):
				logger.info('[GATE] GraphQL endpoint candidate at %s (HTTP %d)', probe_url, resp.status_code)
				return True
		except requests.RequestException as e:
			logger.info('[GATE] has_graphql_endpoint: %s → error (%s)', probe_url, e)
			continue

	logger.info('[GATE] has_graphql_endpoint: no GraphQL endpoint found for %s', url)
	return False


def has_openapi_spec(url, proxy=None):
	"""Return True if an OpenAPI/Swagger spec is reachable at the given base URL.

	Uses HEAD requests only (fast existence check). For 200 responses the
	Content-Type header is inspected; if ambiguous a minimal GET confirms the
	body contains OpenAPI/Swagger keys. Using HEAD avoids downloading full spec
	bodies for probe paths that return 404 or connection-refused.
	"""
	from urllib.parse import urlparse as _urlparse
	parsed = _urlparse(url)
	base = '%s://%s' % (parsed.scheme, parsed.netloc)
	proxies = {'http': proxy, 'https': proxy} if proxy else None

	logger.info('[GATE] has_openapi_spec: probing %d paths for %s (timeout=%ds each)', len(_OPENAPI_PROBE_PATHS), url, _PROBE_TIMEOUT)
	for path in _OPENAPI_PROBE_PATHS:
		probe_url = base + path
		logger.info('[GATE] has_openapi_spec: probing %s', probe_url)
		try:
			resp = requests.head(
				probe_url,
				timeout=_PROBE_TIMEOUT,
				proxies=proxies,
				allow_redirects=True,
				headers=_PROBE_HEADERS,
			)
			logger.info('[GATE] has_openapi_spec: %s → HTTP %d', probe_url, resp.status_code)
			if resp.status_code != 200:
				continue
			# HEAD returned 200 — accept json/yaml content types directly
			ct = resp.headers.get('Content-Type', '')
			if 'json' in ct or 'yaml' in ct:
				logger.info('[GATE] OpenAPI spec found at %s (Content-Type: %s)', probe_url, ct)
				return True
			# For ambiguous content types confirm with a lightweight GET
			logger.info('[GATE] has_openapi_spec: ambiguous Content-Type %r — issuing GET %s', ct, probe_url)
			get_resp = requests.get(
				probe_url,
				timeout=_PROBE_TIMEOUT * 2,
				proxies=proxies,
				allow_redirects=True,
				headers=_PROBE_HEADERS,
			)
			if get_resp.status_code != 200:
				continue
			try:
				data = get_resp.json()
				if isinstance(data, dict) and ('paths' in data or 'openapi' in data or 'swagger' in data):
					logger.info('[GATE] OpenAPI spec confirmed at %s', probe_url)
					return True
			except (ValueError, RecursionError):
				# Not a JSON document (or a pathologically nested one).
				continue
		except requests.RequestException as e:
			logger.info('[GATE] has_openapi_spec: %s → error (%s)', probe_url, e)
			continue

	logger.info('[GATE] has_openapi_spec: no OpenAPI spec found for %s', url)
	return False


def has_jwt_tokens(scan_id, subdomain=None):
	"""Return True if JWT tokens have been detected in the given scan.

	Checks Parameter records with is_auth_related=True whose name matches
	JWT patterns, and SecretLeak records whose secret_type indicates a JWT
	or Bearer token. When subdomain is provided the Parameter check is
	scoped to that subdomain; SecretLeak always covers the full scan so
	that scan-wide secret discoveries gate per-subdomain runs correctly.
	"""
	subdomain_label = subdomain.name if subdomain is not None else 'scan-wide'
	logger.info('[GATE] has_jwt_tokens: querying auth parameters — scan_id=%s scope=%s', scan_id, subdomain_label)
	param_qs = Parameter.objects.filter(
		endpoint__scan_history_id=scan_id,
		is_auth_related=True,
	)
	if subdomain is not None:
		param_qs = param_qs.filter(endpoint__subdomain=subdomain)
	for name in param_qs.values_list('name', flat=True):
		if _JWT_PARAM_RE.search(name):
			logger.info('[GATE] has_jwt_tokens: JWT param match on %r — scan_id=%s scope=%s', name, scan_id, subdomain_label)
			return True

	logger.info('[GATE] has_jwt_tokens: no JWT params found, querying SecretLeak — scan_id=%s', scan_id)
	for secret_type in SecretLeak.objects.filter(scan_history_id=scan_id).values_list('secret_type', flat=True):
		if _JWT_SECRET_TYPE_RE.search(secret_type):
			logger.info('[GATE] has_jwt_tokens: JWT secret match on %r — scan_id=%s', secret_type, scan_id)
			return True

	logger.info('[GATE] has_jwt_tokens: no JWT tokens found — scan_id=%s scope=%s', scan_id, subdomain_label)
	return False
