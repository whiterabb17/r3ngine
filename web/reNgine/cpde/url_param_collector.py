"""
url_param_collector.py — Parameter Discovery from Tool Output Files

Reads the results directory produced by the scan pipeline (fetch_url,
web_api_discovery) and extracts parameter findings from every tool that
writes output there.  This gives CPDE access to all parameters already
discovered by Arjun, ParamSpider, Kiterunner, LinkFinder, and URL
discovery tools (Katana, gau, gospider, waybackurls).

Output format per finding
-------------------------
{
    "name":           "userId",
    "location":       "query_string",   # or form_data / unknown
    "data_type":      None,
    "source_url":     "https://example.com/api?userId=FUZZ",
    "confidence":     60,
    "context":        "arjun:GET",
    "is_auth_related": False,
}

Confidence levels by source
---------------------------
Arjun (active scanner, reliable)    75
Kiterunner (API brute-force)        65
LinkFinder (JS endpoint extraction) 60
ParamSpider (passive, URL-based)    55
URL discovery files (passive crawl) 50
"""

import glob
import json
import logging
import os
import re
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

# Static asset extensions — skip these URLs; js_collector handles .js files
_SKIP_EXTENSIONS: frozenset[str] = frozenset([
    '.js', '.mjs', '.jsx', '.ts', '.tsx',
    '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot',
    '.mp4', '.mp3', '.wav', '.pdf',
    '.zip', '.tar', '.gz', '.map', '.min',
])

# Auth-related parameter name patterns (matches ast_analyzer._AUTH_PATTERNS)
_AUTH_RE = re.compile(
    r'(?i)(token|auth|session|apikey|api[-_]?key|secret|password|passwd|'
    r'credential|bearer|jwt|x[-_]?api[-_]?key|x[-_]?auth|x[-_]?token|'
    r'authorization|access[-_]?token|refresh[-_]?token)',
)


def _is_auth_related(name: str) -> bool:
    return bool(_AUTH_RE.search(name))


def _finding(
    name: str,
    location: str,
    source_url: str,
    confidence: int,
    context: str,
) -> dict:
    """Build a single CPDE finding dict."""
    return {
        'name': name,
        'location': location,
        'data_type': None,
        'source_url': source_url,
        'confidence': confidence,
        'context': context,
        'is_auth_related': _is_auth_related(name),
    }


def collect_from_url_files(results_dir: str) -> list[dict]:
    """Read all `urls_*.txt` files and extract query-string parameter names.

    Skips JS and static asset URLs (handled by js_collector). Only URLs that
    have a query string produce findings.

    Args:
        results_dir: Path to the scan results directory.

    Returns:
        List of CPDE finding dicts with confidence=50.
    """
    findings: list[dict] = []
    pattern = os.path.join(results_dir, 'urls_*.txt')
    file_paths = glob.glob(pattern)

    for filepath in file_paths:
        # Extract tool name from filename: urls_katana.txt → katana
        basename = os.path.basename(filepath)
        tool_name = basename[5:].rsplit('.', 1)[0]  # strip 'urls_' prefix and extension
        context = f'url_discovery:{tool_name}'

        try:
            with open(filepath, encoding='utf-8', errors='replace') as fh:
                for raw_line in fh:
                    url = raw_line.strip()
                    if not url or not url.startswith('http'):
                        continue
                    parsed = urlparse(url)
                    # Skip static assets
                    path_lower = parsed.path.lower()
                    if any(path_lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
                        continue
                    if not parsed.query:
                        continue
                    for key in parse_qs(parsed.query, keep_blank_values=True).keys():
                        if not key:
                            continue
                        findings.append(_finding(key, 'query_string', url, 50, context))
        except OSError as exc:
            logger.warning('[CPDE:url_collector] Failed to read %s: %s', filepath, exc)

    logger.info('[CPDE:url_collector] URL files: %d findings from %d file(s)', len(findings), len(file_paths))
    return findings


def collect_from_arjun_files(results_dir: str) -> list[dict]:
    """Read all `arjun_*.json` files and extract parameter findings.

    Arjun produces JSON keyed by target URL. The params value is either a
    dict of {method: [param, ...]} or a flat list with a top-level 'method'
    key (two output formats supported by the Arjun version in use).

    Args:
        results_dir: Path to the scan results directory.

    Returns:
        List of CPDE finding dicts with confidence=75.
    """
    findings: list[dict] = []
    pattern = os.path.join(results_dir, 'arjun_*.json')
    file_paths = glob.glob(pattern)

    for filepath in file_paths:
        try:
            with open(filepath, encoding='utf-8') as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                continue
            for target_url, details in data.items():
                if not isinstance(details, dict):
                    continue
                params = details.get('params', {})
                if isinstance(params, dict):
                    for method, param_list in params.items():
                        if not isinstance(param_list, list):
                            continue
                        location = 'query_string' if method.upper() == 'GET' else 'form_data'
                        for name in param_list:
                            name = str(name).strip()
                            if not name:
                                continue
                            findings.append(_finding(
                                name, location, target_url, 75, f'arjun:{method.upper()}'
                            ))
                elif isinstance(params, list):
                    method = str(details.get('method', 'unknown')).upper()
                    location = 'query_string' if method == 'GET' else 'form_data'
                    for name in params:
                        name = str(name).strip()
                        if not name:
                            continue
                        findings.append(_finding(
                            name, location, target_url, 75, f'arjun:{method}'
                        ))
        except (json.JSONDecodeError, OSError, AttributeError) as exc:
            logger.warning('[CPDE:url_collector] Failed to parse Arjun file %s: %s', filepath, exc)

    logger.info('[CPDE:url_collector] Arjun files: %d findings from %d file(s)', len(findings), len(file_paths))
    return findings


def collect_from_paramspider_files(results_dir: str) -> list[dict]:
    """Read all `ps_*.txt` files and extract query-string parameters.

    ParamSpider writes one URL per line with `FUZZ` as the placeholder value.
    Extract the key names from the query string of each line.

    Args:
        results_dir: Path to the scan results directory.

    Returns:
        List of CPDE finding dicts with confidence=55.
    """
    findings: list[dict] = []
    pattern = os.path.join(results_dir, 'ps_*.txt')
    file_paths = glob.glob(pattern)

    for filepath in file_paths:
        try:
            with open(filepath, encoding='utf-8', errors='replace') as fh:
                for raw_line in fh:
                    url = raw_line.strip()
                    if not url or not url.startswith('http'):
                        continue
                    parsed = urlparse(url)
                    if not parsed.query:
                        continue
                    for key in parse_qs(parsed.query, keep_blank_values=True).keys():
                        if not key:
                            continue
                        findings.append(_finding(key, 'query_string', url, 55, 'paramspider:query'))
        except OSError as exc:
            logger.warning('[CPDE:url_collector] Failed to read ParamSpider file %s: %s', filepath, exc)

    logger.info('[CPDE:url_collector] ParamSpider files: %d findings from %d file(s)', len(findings), len(file_paths))
    return findings


def collect_from_kiterunner_files(results_dir: str) -> list[dict]:
    """Read all `kr_*.json` files (JSONL) and extract query parameters.

    Each line is a JSON object with a 'path' key. Only paths that contain
    a query string (`?`) produce findings.

    Args:
        results_dir: Path to the scan results directory.

    Returns:
        List of CPDE finding dicts with confidence=65.
    """
    findings: list[dict] = []
    pattern = os.path.join(results_dir, 'kr_*.json')
    file_paths = glob.glob(pattern)

    for filepath in file_paths:
        try:
            with open(filepath, encoding='utf-8', errors='replace') as fh:
                for raw_line in fh:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        entry = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue
                    path = entry.get('path', '')
                    if not path or '?' not in path:
                        continue
                    parsed = urlparse(path)
                    for key in parse_qs(parsed.query, keep_blank_values=True).keys():
                        if not key:
                            continue
                        findings.append(_finding(key, 'query_string', path, 65, 'kiterunner:api_brute'))
        except OSError as exc:
            logger.warning('[CPDE:url_collector] Failed to read Kiterunner file %s: %s', filepath, exc)

    logger.info('[CPDE:url_collector] Kiterunner files: %d findings from %d file(s)', len(findings), len(file_paths))
    return findings


def collect_from_linkfinder_files(results_dir: str) -> list[dict]:
    """Read all `lf_*.txt` files (LinkFinder output) and extract query parameters.

    LinkFinder writes endpoint paths or full URLs (one per line). Extract
    query param names from any line that starts with `/` or `http`.

    Args:
        results_dir: Path to the scan results directory.

    Returns:
        List of CPDE finding dicts with confidence=60.
    """
    findings: list[dict] = []
    pattern = os.path.join(results_dir, 'lf_*.txt')
    file_paths = glob.glob(pattern)

    for filepath in file_paths:
        try:
            with open(filepath, encoding='utf-8', errors='replace') as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue
                    if not (line.startswith('/') or line.startswith('http')):
                        continue
                    parsed = urlparse(line)
                    if not parsed.query:
                        continue
                    for key in parse_qs(parsed.query, keep_blank_values=True).keys():
                        if not key:
                            continue
                        findings.append(_finding(key, 'query_string', line, 60, 'linkfinder:js_links'))
        except OSError as exc:
            logger.warning('[CPDE:url_collector] Failed to read LinkFinder file %s: %s', filepath, exc)

    logger.info('[CPDE:url_collector] LinkFinder files: %d findings from %d file(s)', len(findings), len(file_paths))
    return findings


def collect_all(results_dir: str) -> list[dict]:
    """Collect parameter findings from all tool output files in results_dir.

    Calls all per-source collectors and concatenates their findings.
    The correlation engine will deduplicate and merge them downstream.

    Args:
        results_dir: Path to the scan results directory.

    Returns:
        Combined list of CPDE finding dicts from all sources.
    """
    if not results_dir or not os.path.isdir(results_dir):
        logger.warning('[CPDE:url_collector] results_dir not found: %s', results_dir)
        return []

    all_findings: list[dict] = []
    all_findings.extend(collect_from_url_files(results_dir))
    all_findings.extend(collect_from_arjun_files(results_dir))
    all_findings.extend(collect_from_paramspider_files(results_dir))
    all_findings.extend(collect_from_kiterunner_files(results_dir))
    all_findings.extend(collect_from_linkfinder_files(results_dir))

    logger.info('[CPDE:url_collector] collect_all: %d total findings from results_dir', len(all_findings))
    return all_findings
