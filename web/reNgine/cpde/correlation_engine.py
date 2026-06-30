"""
correlation_engine.py — Multi-Source Parameter Correlation

Merges parameter findings from multiple sources (JS/AST, OpenAPI, GraphQL),
normalizes parameter names, deduplicates, and computes confidence scores.

Confidence Scoring Model
------------------------
Base score = max(individual finding confidence scores for this parameter)

Bonus rules (applied after deduplication):
  +20  if observed in ≥ 2 distinct source types
  +10  if observed in OpenAPI (authoritative)
  +5   if observed in ≥ 3 distinct source types

Scores are capped at 100.

Name Normalization
------------------
Parameters are deduplicated after normalization:
  userId / user_id / UserId / USERID → "userid"

The original (most common) casing is kept in the output record.
"""

import logging
import re
from collections import defaultdict

logger = logging.getLogger(__name__)

# Auth-related parameter patterns — used to auto-detect auth parameters
_AUTH_RE = re.compile(
    r'(?i)(token|auth|session|apikey|api[-_]?key|secret|password|passwd|'
    r'credential|bearer|jwt|x[-_]?api[-_]?key|x[-_]?auth|x[-_]?token|'
    r'authorization|access[-_]?token|refresh[-_]?token)',
)

# Minimum confidence to include in output (below this is discarded)
_MIN_CONFIDENCE = 50

# Source type labels that map finding['context'] / source strings to categories
_SOURCE_CATEGORIES = {
    'js_ast': 'js',
    'js': 'js',
    'esprima': 'js',
    'regex': 'js',
    'openapi': 'openapi',
    'swagger': 'openapi',
    'inql': 'graphql',
    'graphql': 'graphql',
    'arjun': 'active_scan',
    'paramspider': 'passive_web',
    'linkfinder': 'js_links',
    'kiterunner': 'api_brute',
}

# ── Noise blocklist ───────────────────────────────────────────────────────────
# Parameter names that are known analytics/tracking noise and are never
# interesting from a security testing perspective. Applied in `correlate()`
# before output. The set is normalized the same way as param names (strip
# non-alphanumeric, lowercase) so variant spellings (utm-source, utm_source)
# are all blocked by the same entry.
_NOISE_PARAMS_RAW: frozenset[str] = frozenset([
    # Google Analytics campaign tracking
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'utm_id', 'utm_source_platform', 'utm_creative_format', 'utm_marketing_tactic',
    # Google Analytics session / client IDs
    '_ga', '_gl', '_gid',
    # Ad click tracking
    'fbclid', 'gclid', 'msclkid', 'dclid', 'gbraid', 'wbraid',
    # Cloudflare challenge tokens
    '__cf_chl_captcha_tk__', '__cf_chl_managed_tk__',
    # Build / cache busters that carry no semantic meaning
    '__hssc', '__hstc', '__hsfp', 'hsCtaTracking',
])

_NOISE_PARAMS_NORMALIZED: frozenset[str] = frozenset(
    re.sub(r'[^a-z0-9]', '', p.lower()) for p in _NOISE_PARAMS_RAW
)


def _normalize_name(name: str) -> str:
    """Normalize a parameter name for deduplication.

    Strips non-alphanumeric characters and lowercases.

    Args:
        name (str): Raw parameter name.

    Returns:
        str: Normalized key for grouping.
    """
    return re.sub(r'[^a-z0-9]', '', name.lower())


def _source_category(source: str) -> str:
    """Map a raw source string to a category label.

    Args:
        source (str): Raw source string from a finding.

    Returns:
        str: Category label.
    """
    for key, cat in _SOURCE_CATEGORIES.items():
        if key in source.lower():
            return cat
    return 'other'


def correlate(
    findings: list[dict],
    min_confidence: int = _MIN_CONFIDENCE,
    *,
    apply_noise_filter: bool = True,
) -> list[dict]:
    """Merge and score parameter findings from multiple sources.

    Args:
        findings (list[dict]): Raw findings from ast_analyzer, openapi_discoverer,
                               and any other CPDE source. Each finding must have
                               at minimum: 'name', 'location', 'source_url',
                               'confidence'.
        min_confidence (int): Minimum confidence to include in output. Default 50.
        apply_noise_filter (bool): When True (default), parameters that match the
                                   noise blocklist (_NOISE_PARAMS_NORMALIZED) are
                                   discarded regardless of their confidence score.
                                   Pass False to disable for debugging or exhaustive
                                   discovery runs.

    Returns:
        list[dict]: Correlated, deduplicated, confidence-scored parameter records
                    ready for persistence. Each dict has:
                    name, param_location, data_type, confidence, sources (list),
                    observed_in_js, observed_in_openapi, observed_in_graphql,
                    is_auth_related, source_urls (list).
    """
    # Group findings by normalized name + location
    # Key: (normalized_name, location)
    groups: dict[tuple, list[dict]] = defaultdict(list)

    for finding in findings:
        name = (finding.get('name') or '').strip()
        if not name or len(name) < 2:
            continue
        location = finding.get('location') or 'unknown'
        key = (_normalize_name(name), location)
        groups[key].append(finding)

    output: list[dict] = []

    for (norm_name, location), group in groups.items():
        # Pick the canonical (most frequent) name from the group
        name_counts: dict[str, int] = defaultdict(int)
        for f in group:
            name_counts[f['name']] += 1
        canonical_name = max(name_counts, key=name_counts.__getitem__)

        # Collect all unique source categories
        source_categories: set[str] = set()
        source_labels: list[str] = []
        source_urls: list[str] = []
        max_confidence = 0
        data_type = None
        is_auth = False

        for f in group:
            raw_source = (
                f.get('context', '') + ' ' +
                ' '.join(f.get('sources', []))
            )
            cat = _source_category(raw_source)
            source_categories.add(cat)

            if f.get('source_url') and f['source_url'] not in source_urls:
                source_urls.append(f['source_url'])

            conf = f.get('confidence', 0)
            if conf > max_confidence:
                max_confidence = conf

            if f.get('data_type') and not data_type:
                data_type = f['data_type']

            if f.get('is_auth_related'):
                is_auth = True

        # Build source label list from categories
        source_labels = list(source_categories)

        # Compute final confidence
        confidence = max_confidence
        n_categories = len(source_categories)
        if n_categories >= 2:
            confidence += 20
        if n_categories >= 3:
            confidence += 5
        if 'openapi' in source_categories:
            confidence += 10
        confidence = min(confidence, 100)

        # Check auth by name if not already flagged
        if not is_auth and _AUTH_RE.search(canonical_name):
            is_auth = True

        # Apply noise blocklist — filter known tracking/analytics params that
        # carry no security-testing value regardless of confidence.
        if apply_noise_filter and norm_name in _NOISE_PARAMS_NORMALIZED:
            logger.debug('[CPDE:correlation] Noise-filtered param: %s', canonical_name)
            continue

        if confidence < min_confidence:
            continue

        output.append({
            'name': canonical_name,
            'param_location': location,
            'data_type': data_type,
            'confidence': confidence,
            'sources': source_labels,
            'observed_in_js': 'js' in source_categories or 'js_links' in source_categories,
            'observed_in_openapi': 'openapi' in source_categories,
            'observed_in_graphql': 'graphql' in source_categories,
            'is_auth_related': is_auth,
            'source_urls': source_urls,
            '_occurrence_count': len(group),
        })

    # Sort by confidence descending, then alphabetically
    output.sort(key=lambda x: (-x['confidence'], x['name']))

    logger.info(
        '[CPDE:correlation] Input: %d findings → Output: %d correlated params (min_confidence=%d)',
        len(findings), len(output), min_confidence,
    )
    return output
