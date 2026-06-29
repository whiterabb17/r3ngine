"""
post_scan_processing.py — Tier 6 Post-Scan Processing Task

Runs as the final activity inside NucleiPlannerWorkflow, after all Tier 6 tools
(Nuclei, Vigolium, WPScan, etc.) have completed. The task consults the fully-
populated database and performs three passes:

  1. Endpoint deduplication — final content-signature sweep across all endpoints.
  2. OpenAPI/Swagger spec extraction — queries Vulnerability + EndPoint records
     for swagger/openapi URLs discovered by Vigolium or Nuclei, fetches Swagger
     UI HTML pages to extract embedded spec URLs, downloads and parses specs via
     CPDE's openapi_discoverer to extract parameters.
  3. GraphQL re-dispatch — detects any GraphQL-pattern endpoints found by
     Vigolium after web_api_discovery ran, runs InQL and graphql-cop against
     those new endpoints only.

All I/O-bound work (spec fetching, parameter persistence) is dispatched via a
thread pool to keep wall-clock time reasonable even with many candidate URLs.
"""

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# ── Regex patterns for extracting spec URL from Swagger UI HTML ───────────────
# Matches the most common Swagger UI initialisation patterns:
#   SwaggerUIBundle({ ..., url: "/path/to/openapi.json", ... })
#   window.onload = function() { const ui = SwaggerUIBundle({ url: "..." }) }
#   url: '/api/v1/swagger.json'  (bare in any JS context)
_SWAGGER_BUNDLE_RE = re.compile(
    r'SwaggerUIBundle\s*\(\s*\{[^}]*?[\'"]{0,1}url[\'"]{0,1}\s*:\s*["\']([^"\']+)["\']',
    re.DOTALL,
)
_SWAGGER_INIT_RE = re.compile(
    r'window\s*\.\s*onload\s*=.*?url\s*:\s*["\']([^"\']+)["\']',
    re.DOTALL,
)
# Fallback: any JSON-looking url field that ends in .json/.yaml/api-docs
_SWAGGER_URL_RE = re.compile(
    r'["\']url["\']\s*:\s*["\']([^"\']*(?:openapi|swagger|api-docs)[^"\']*)["\']',
    re.IGNORECASE,
)

# Patterns used to identify OpenAPI/Swagger candidate URLs in the DB
_SWAGGER_URL_IREGEX = r'swagger|openapi|api-docs|/docs|/redoc'

# GraphQL endpoint iregex (mirrors has_graphql_endpoint DB check)
_GRAPHQL_URL_IREGEX = r'/graphi?ql'

_REQUEST_TIMEOUT = 15  # seconds
_THREAD_WORKERS = 8


def _extract_spec_url_from_swagger_ui(html: str, page_url: str) -> str | None:
    """Extract the raw OpenAPI spec URL embedded in a Swagger UI page.

    Swagger UI pages embed the spec URL inside the SwaggerUIBundle JS call.
    Tries multiple regex patterns in order of specificity.

    Args:
        html: Full HTML content of the Swagger UI page.
        page_url: The URL the page was fetched from (for urljoin resolution).

    Returns:
        Absolute URL of the spec, or None if not found.
    """
    for pattern in (_SWAGGER_BUNDLE_RE, _SWAGGER_INIT_RE, _SWAGGER_URL_RE):
        match = pattern.search(html)
        if match:
            spec_path = match.group(1).strip()
            if spec_path:
                return urljoin(page_url, spec_path)
    return None


def _fetch_and_parse_spec(candidate_url: str, proxy: str | None) -> list[dict]:
    """Fetch a candidate URL and extract OpenAPI parameter findings.

    Handles two cases:
    - Swagger UI HTML page -> extract embedded spec URL, then download spec.
    - Raw OpenAPI/Swagger JSON/YAML -> parse directly.

    Args:
        candidate_url: URL to fetch (Swagger UI page or raw spec).
        proxy: Optional HTTP proxy string.

    Returns:
        List of parameter finding dicts (CPDE format), possibly empty.
    """
    from reNgine.cpde.openapi_discoverer import _parse_spec

    proxies = {'http': proxy, 'https': proxy} if proxy else None
    session = requests.Session()
    session.headers['User-Agent'] = 'r3ngine-post-scan/1.0 (OpenAPI Discovery)'

    try:
        resp = session.get(
            candidate_url,
            timeout=_REQUEST_TIMEOUT,
            proxies=proxies,
            allow_redirects=True,
            verify=False,
        )
        if resp.status_code != 200:
            logger.debug('[POST_SCAN] %s -> HTTP %d, skipping', candidate_url, resp.status_code)
            return []
    except requests.RequestException as exc:
        logger.debug('[POST_SCAN] fetch failed %s: %s', candidate_url, exc)
        return []

    content_type = resp.headers.get('Content-Type', '')
    spec = None

    # ── Case 1: Raw JSON spec ────────────────────────────────────────────────
    if 'json' in content_type:
        try:
            spec = resp.json()
        except Exception:
            pass

    # ── Case 2: Raw YAML spec ────────────────────────────────────────────────
    elif 'yaml' in content_type:
        try:
            import yaml
            spec = yaml.safe_load(resp.text)
        except Exception:
            pass

    # ── Case 3: HTML — Swagger UI page; extract embedded spec URL ───────────
    elif 'html' in content_type or 'text/plain' in content_type:
        spec_url = _extract_spec_url_from_swagger_ui(resp.text, candidate_url)
        if spec_url:
            logger.info('[POST_SCAN] Swagger UI at %s -> spec URL: %s', candidate_url, spec_url)
            return _fetch_and_parse_spec(spec_url, proxy)
        else:
            logger.debug('[POST_SCAN] No spec URL found in Swagger UI page %s', candidate_url)
            return []

    # ── Case 4: Ambiguous content-type — try JSON then YAML ─────────────────
    else:
        try:
            spec = resp.json()
        except Exception:
            try:
                import yaml
                spec = yaml.safe_load(resp.text)
            except Exception:
                # Last resort: check if it looks like HTML (Swagger UI page)
                if '<html' in resp.text[:500].lower():
                    spec_url = _extract_spec_url_from_swagger_ui(resp.text, candidate_url)
                    if spec_url:
                        logger.info('[POST_SCAN] Swagger UI (ambiguous CT) at %s -> spec URL: %s',
                                    candidate_url, spec_url)
                        return _fetch_and_parse_spec(spec_url, proxy)
                return []

    if not isinstance(spec, dict):
        return []
    if not ('paths' in spec or 'openapi' in spec or 'swagger' in spec):
        logger.debug('[POST_SCAN] Response at %s does not look like an OpenAPI spec', candidate_url)
        return []

    logger.info('[POST_SCAN] OpenAPI spec found at %s — title: %s',
                candidate_url, spec.get('info', {}).get('title', 'unknown'))
    return _parse_spec(spec, candidate_url)


def _persist_openapi_findings(findings: list[dict], scan_id: int, domain_id: int,
                               ctx: dict) -> int:
    """Persist CPDE-format OpenAPI findings to the Parameter model.

    Groups findings by their source_url (spec URL) and resolves endpoints.
    Returns the number of parameters created or updated.
    """
    from reNgine.utils.task import save_endpoint, save_parameter

    if not findings:
        return 0

    persisted = 0
    for finding in findings:
        source_url = finding.get('source_url', '')
        if not finding.get('name') or not source_url:
            continue

        # Resolve or create the endpoint for this spec's host
        parsed = urlparse(source_url)
        host_root = f'{parsed.scheme}://{parsed.netloc}/'
        endpoint, _ = save_endpoint(
            host_root,
            ctx=ctx,
            source='PostScan (OpenAPI)',
            is_default=False,
        )
        if not endpoint:
            continue

        save_parameter(
            endpoint=endpoint,
            name=finding['name'],
            param_type='openapi',
            confidence=finding.get('confidence', 85),
            param_location=finding.get('location'),
            data_type=finding.get('data_type'),
            is_auth_related=finding.get('is_auth_related', False),
            observed_in_openapi=True,
            scan_history_id=scan_id,
        )
        persisted += 1

    return persisted


def post_scan_processing(self, ctx: dict = {}, description: str = None):
    """Final Tier 6 task — dedup, OpenAPI extraction, GraphQL dispatch.

    Runs after all other NucleiPlannerWorkflow activities so it has access
    to the fully-populated Vulnerability and EndPoint tables.

    Args:
        self: TemporalTaskProxy instance (provides scan_id, domain, domain_id, etc.).
        ctx: Temporal workflow context dict.
        description: Activity label shown in UI timeline.
    """
    from reNgine.definitions import VULNERABILITY_SCAN, RUN_POST_SCAN_PROCESSING
    from reNgine.common_func import get_random_proxy
    from reNgine.tasks.persistence import remove_duplicate_endpoints
    from reNgine.utils.task import activity_heartbeat_safe
    from startScan.models import Vulnerability, EndPoint

    scan_id = self.scan_id
    domain_id = getattr(self, 'domain_id', None) or (
        self.scan.domain.id if self.scan and self.scan.domain else None
    )
    yaml_config = self.yaml_configuration or {}
    vuln_config = yaml_config.get(VULNERABILITY_SCAN, {})

    if not vuln_config.get(RUN_POST_SCAN_PROCESSING, True):
        logger.info('[POST_SCAN] Disabled in configuration. Skipping.')
        return

    proxy = get_random_proxy() or None

    # ── Pass 1: Endpoint deduplication ──────────────────────────────────────
    activity_heartbeat_safe('Post-scan: deduplicating endpoints')
    logger.info('[POST_SCAN] Pass 1 — endpoint deduplication for scan_id=%s', scan_id)
    try:
        if scan_id and domain_id:
            remove_duplicate_endpoints(
                scan_history_id=scan_id,
                domain_id=domain_id,
            )
            logger.info('[POST_SCAN] Pass 1 complete — endpoint deduplication done')
    except Exception as exc:
        logger.warning('[POST_SCAN] Pass 1 dedup error (non-fatal): %s', exc)

    # ── Pass 2: OpenAPI/Swagger spec discovery from DB ───────────────────────
    activity_heartbeat_safe('Post-scan: discovering OpenAPI specs from scan findings')
    logger.info('[POST_SCAN] Pass 2 — OpenAPI spec extraction for scan_id=%s', scan_id)

    candidate_urls: set = set()

    # Source A: Vulnerability records (Vigolium, Nuclei, etc.)
    try:
        vuln_candidates = list(Vulnerability.objects.filter(
            scan_history_id=scan_id,
            http_url__iregex=_SWAGGER_URL_IREGEX,
        ).values_list('http_url', flat=True).distinct())
        for url in vuln_candidates:
            if url:
                candidate_urls.add(url)
        logger.info('[POST_SCAN] Pass 2 — %d swagger/openapi URLs from Vulnerability table',
                    len(vuln_candidates))
    except Exception as exc:
        logger.warning('[POST_SCAN] Pass 2 Vulnerability query error (non-fatal): %s', exc)

    # Source B: EndPoint records (crawled swagger-looking paths)
    try:
        ep_candidates = list(EndPoint.objects.filter(
            scan_history_id=scan_id,
            http_url__iregex=_SWAGGER_URL_IREGEX,
        ).values_list('http_url', flat=True).distinct())
        for url in ep_candidates:
            if url:
                candidate_urls.add(url)
        logger.info('[POST_SCAN] Pass 2 — %d swagger/openapi URLs from EndPoint table',
                    len(ep_candidates))
    except Exception as exc:
        logger.warning('[POST_SCAN] Pass 2 EndPoint query error (non-fatal): %s', exc)

    logger.info('[POST_SCAN] Pass 2 — %d total candidate URLs to probe', len(candidate_urls))

    # Threaded spec fetch + parse
    all_openapi_findings: list = []
    if candidate_urls:
        with ThreadPoolExecutor(max_workers=_THREAD_WORKERS) as pool:
            future_to_url = {
                pool.submit(_fetch_and_parse_spec, url, proxy): url
                for url in candidate_urls
            }
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    findings = future.result()
                    if findings:
                        logger.info('[POST_SCAN] %s -> %d parameter findings', url, len(findings))
                        all_openapi_findings.extend(findings)
                except Exception as exc:
                    logger.warning('[POST_SCAN] Pass 2 fetch error for %s (non-fatal): %s', url, exc)

    if all_openapi_findings:
        activity_heartbeat_safe(f'Post-scan: persisting {len(all_openapi_findings)} OpenAPI parameters')
        persisted = _persist_openapi_findings(all_openapi_findings, scan_id, domain_id, ctx)
        logger.info('[POST_SCAN] Pass 2 complete — %d parameters persisted from %d findings',
                    persisted, len(all_openapi_findings))
    else:
        logger.info('[POST_SCAN] Pass 2 complete — no new OpenAPI parameters found')

    # ── Pass 3: GraphQL re-dispatch for post-CPDE discoveries ───────────────
    activity_heartbeat_safe('Post-scan: checking for post-CPDE GraphQL endpoints')
    logger.info('[POST_SCAN] Pass 3 — GraphQL re-dispatch for scan_id=%s', scan_id)

    dispatched_subdomains: set = set()
    try:
        from reNgine.tasks.api import run_graphql_cop
        from reNgine.cpde.graphql_enricher import enrich_graphql_params
        from reNgine.utils.task import run_command
        from startScan.models import Subdomain, ScanActivity
        from reNgine.definitions import SUCCESS_TASK

        # Only dispatch for subdomains NOT already covered by web_api_discovery
        wad_activity = ScanActivity.objects.filter(
            scan_of__id=scan_id,
            name='web_api_discovery',
            status=SUCCESS_TASK,
        ).first()

        graphql_eps = EndPoint.objects.filter(
            scan_history_id=scan_id,
            http_url__iregex=_GRAPHQL_URL_IREGEX,
        ).select_related('subdomain')

        results_dir = getattr(self, 'results_dir', None) or f'/tmp/scan_{scan_id}'
        os.makedirs(f'{results_dir}/post_scan', exist_ok=True)

        for ep in graphql_eps:
            subdomain = ep.subdomain
            if not subdomain or subdomain.name in dispatched_subdomains:
                continue

            if wad_activity and ep.discovered_date and ep.discovered_date <= wad_activity.time:
                logger.debug('[POST_SCAN] Pass 3 — %s covered by web_api_discovery, skipping',
                             subdomain.name)
                continue

            dispatched_subdomains.add(subdomain.name)
            logger.info('[POST_SCAN] Pass 3 — running InQL on new GraphQL endpoint: %s', ep.http_url)

            inql_output = f'{results_dir}/post_scan/inql_{subdomain.name}'
            cmd = f'inql -t {ep.http_url} -o {inql_output}'
            if proxy:
                cmd += f' -p {proxy}'
            try:
                run_command(cmd, shell=True, scan_id=scan_id, activity_id=self.activity_id)
                if os.path.exists(inql_output):
                    enrich_graphql_params(inql_output, ep.http_url, subdomain, ctx)
            except Exception as exc:
                logger.warning('[POST_SCAN] Pass 3 InQL error for %s: %s', subdomain.name, exc)

            try:
                run_graphql_cop(self, ctx, ep.http_url, subdomain)
            except Exception as exc:
                logger.warning('[POST_SCAN] Pass 3 graphql-cop error for %s: %s', subdomain.name, exc)

        if dispatched_subdomains:
            logger.info('[POST_SCAN] Pass 3 complete — dispatched for %d subdomains: %s',
                        len(dispatched_subdomains), dispatched_subdomains)
        else:
            logger.info('[POST_SCAN] Pass 3 complete — no new GraphQL endpoints requiring dispatch')

    except Exception as exc:
        logger.warning('[POST_SCAN] Pass 3 GraphQL dispatch error (non-fatal): %s', exc)

    logger.info('[POST_SCAN] All passes complete for scan_id=%s', scan_id)
    return {
        'openapi_findings': len(all_openapi_findings),
        'graphql_subdomains_dispatched': len(dispatched_subdomains),
    }
