"""
openapi_discoverer.py — OpenAPI / Swagger Schema Discovery

Probes a list of base URLs for common OpenAPI/Swagger specification paths
and parses any found specs to extract endpoint routes and their parameters.

OpenAPI findings are treated as the highest-confidence evidence source
(confidence=90) because they are machine-generated documentation that
precisely describes the API contract.

Supported spec formats
----------------------
- OpenAPI 3.x (application/json or application/yaml)
- Swagger 2.x (application/json)
"""

import logging
from urllib.parse import urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Ordered list of common paths to probe for API spec files.
# Ordered by likelihood — most applications serve one of the first few.
_SPEC_PROBE_PATHS = [
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

_REQUEST_TIMEOUT = 10  # seconds per probe


def _parse_spec(spec: dict, source_url: str) -> list[dict]:
    """Extract parameter findings from a parsed OpenAPI/Swagger spec dict.

    Handles OpenAPI 3.x (paths → parameters/requestBody) and Swagger 2.x
    (paths → parameters).

    Args:
        spec (dict): Parsed JSON/YAML spec.
        source_url (str): URL the spec was fetched from (for provenance).

    Returns:
        list[dict]: Parameter findings in CPDE finding format.
    """
    findings = []
    paths = spec.get('paths', {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in ('get', 'post', 'put', 'patch', 'delete', 'options', 'head'):
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue

            # ── Path/Query/Header parameters ────────────────────────────────
            params = operation.get('parameters', [])
            for param in params:
                if not isinstance(param, dict):
                    continue
                name = param.get('name', '')
                if not name:
                    continue

                location_raw = param.get('in', '')
                location_map = {
                    'query': 'query_string',
                    'path': 'path',
                    'header': 'header',
                    'cookie': 'query_string',
                    'body': 'json_body',
                    'formData': 'form_data',
                }
                location = location_map.get(location_raw, location_raw or None)

                # Extract data type from schema
                schema = param.get('schema', {}) or {}
                data_type = schema.get('type') or param.get('type')

                findings.append({
                    'name': name,
                    'location': location,
                    'data_type': data_type,
                    'source_url': source_url,
                    'confidence': 90,
                    'is_auth_related': location == 'header' and bool(
                        name.lower() in ('authorization', 'x-api-key', 'x-auth-token')
                    ),
                    'context': f'openapi:{method.upper()}:{path}',
                })

            # ── OpenAPI 3.x requestBody ─────────────────────────────────────
            request_body = operation.get('requestBody', {})
            if isinstance(request_body, dict):
                content = request_body.get('content', {})
                for content_type, media_type in content.items():
                    if not isinstance(media_type, dict):
                        continue
                    schema = media_type.get('schema', {}) or {}
                    properties = schema.get('properties', {}) or {}
                    for prop_name, prop_schema in properties.items():
                        if not isinstance(prop_schema, dict):
                            continue
                        is_form = 'form' in content_type
                        findings.append({
                            'name': prop_name,
                            'location': 'form_data' if is_form else 'json_body',
                            'data_type': prop_schema.get('type'),
                            'source_url': source_url,
                            'confidence': 90,
                            'is_auth_related': False,
                            'context': f'openapi:{method.upper()}:{path}:requestBody',
                        })

    logger.info(
        '[CPDE:openapi] Extracted %d parameter findings from %s',
        len(findings), source_url,
    )
    return findings


def discover(base_urls: list[str], proxy: str | None = None) -> list[dict]:
    """Probe base URLs for OpenAPI/Swagger specs and extract parameter findings.

    For each base URL, probes common spec paths. Stops probing a host once a
    valid spec is found (to avoid redundant requests).

    Args:
        base_urls (list[str]): Base URLs to probe (e.g. ['https://api.example.com']).
        proxy (str | None): Optional HTTP proxy URL.

    Returns:
        list[dict]: Parameter findings from all discovered specs.
    """
    all_findings: list[dict] = []
    seen_hosts: set[str] = set()
    proxies = {'http': proxy, 'https': proxy} if proxy else None

    session = requests.Session()
    session.headers['User-Agent'] = 'r3ngine-cpde/1.0 (OpenAPI Discovery)'

    for base_url in base_urls:
        # Normalise base URL to scheme + host only
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        host_root = f'{parsed.scheme}://{parsed.netloc}'

        if host_root in seen_hosts:
            continue

        for probe_path in _SPEC_PROBE_PATHS:
            spec_url = urljoin(host_root + '/', probe_path.lstrip('/'))
            try:
                resp = session.get(
                    spec_url,
                    timeout=_REQUEST_TIMEOUT,
                    proxies=proxies,
                    allow_redirects=True,
                    verify=False,
                )
                if resp.status_code != 200:
                    continue

                content_type = resp.headers.get('Content-Type', '')

                # Try JSON
                if 'json' in content_type or probe_path.endswith('.json'):
                    try:
                        spec = resp.json()
                    except Exception:
                        continue
                # Try YAML
                elif 'yaml' in content_type or probe_path.endswith('.yaml'):
                    try:
                        import yaml  # type: ignore
                        spec = yaml.safe_load(resp.text)
                    except Exception:
                        continue
                else:
                    # Attempt JSON first, then YAML
                    try:
                        spec = resp.json()
                    except Exception:
                        try:
                            import yaml  # type: ignore
                            spec = yaml.safe_load(resp.text)
                        except Exception:
                            continue

                # Validate it looks like an OpenAPI/Swagger spec
                if not isinstance(spec, dict):
                    continue
                if not ('paths' in spec or 'openapi' in spec or 'swagger' in spec):
                    continue

                logger.info(
                    '[CPDE:openapi] Found spec at %s (%s)',
                    spec_url, spec.get('info', {}).get('title', 'unknown'),
                )
                findings = _parse_spec(spec, spec_url)
                all_findings.extend(findings)
                seen_hosts.add(host_root)
                break  # Found a valid spec for this host — no need to probe more paths

            except requests.RequestException as exc:
                logger.debug('[CPDE:openapi] Probe failed %s: %s', spec_url, exc)

    logger.info(
        '[CPDE:openapi] Discovered %d parameter findings from OpenAPI specs across %d hosts',
        len(all_findings), len(seen_hosts),
    )
    return all_findings
