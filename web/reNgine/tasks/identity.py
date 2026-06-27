"""
Identity Infrastructure Detection Tasks

Detects identity systems (ADFS, OWA, Exchange, LDAP, SSO portals) by pattern
matching against existing scan data in PostgreSQL. No outbound HTTP calls made.

Detection signals:
  1. URL path patterns  (from Subdomain.http_url and EndPoint.http_url)
  2. Page title keywords (from Subdomain.page_title)
  3. HTTP header patterns (from HTTP response metadata)

A subdomain triggers a combined-signal detection when 2+ signals agree,
which increases the confidence_score.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Each entry: (compiled_regex, infra_type, base_confidence)
IDENTITY_URL_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"/adfs/", re.IGNORECASE), "adfs", 0.92),
    (re.compile(r"/federationmetadata/", re.IGNORECASE), "adfs", 0.85),
    (re.compile(r"[?&/]wsfed", re.IGNORECASE), "adfs", 0.80),
    (re.compile(r"/ecp/", re.IGNORECASE), "exchange", 0.88),
    (re.compile(r"/ews/exchange\.asmx", re.IGNORECASE), "exchange", 0.92),
    (re.compile(r"/autodiscover/", re.IGNORECASE), "exchange", 0.85),
    (re.compile(r"/owa/", re.IGNORECASE), "owa", 0.90),
    (re.compile(r"^ldaps?://", re.IGNORECASE), "ldap", 0.95),
    (re.compile(r":389/|:636/|:3268/|:3269/", re.IGNORECASE), "ldap", 0.80),
    (re.compile(r"/saml(/|2?/)", re.IGNORECASE), "saml_idp", 0.88),
    (re.compile(r"/sso/", re.IGNORECASE), "sso", 0.70),
    (re.compile(r"/idp/", re.IGNORECASE), "saml_idp", 0.72),
    (re.compile(r"/vpn/|/GlobalProtect|/sslvpn|/remote/login", re.IGNORECASE), "vpn_portal", 0.85),
    (re.compile(r"/login[/?]|/auth[/?]|/portal[/?]", re.IGNORECASE), "generic_auth_portal", 0.45),
]

IDENTITY_TITLE_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"active directory federation service", re.IGNORECASE), "adfs", 0.95),
    (re.compile(r"\bADFS\b", re.IGNORECASE), "adfs", 0.85),
    (re.compile(r"outlook web app|outlook web access", re.IGNORECASE), "owa", 0.92),
    (re.compile(r"exchange.*sign.?in|exchange.*login", re.IGNORECASE), "exchange", 0.85),
    (re.compile(r"microsoft.*sign.?in|sign.?in.*microsoft", re.IGNORECASE), "sso", 0.70),
    (re.compile(r"okta.*(sign.?in|login)|sign.?in.*okta", re.IGNORECASE), "saml_idp", 0.88),
    (re.compile(r"azure.*(sign.?in|login)", re.IGNORECASE), "sso", 0.82),
    (re.compile(r"VPN.*login|Pulse.*Secure|Global.*Protect", re.IGNORECASE), "vpn_portal", 0.85),
    (re.compile(r"single sign.?on|sso portal", re.IGNORECASE), "sso", 0.78),
    (re.compile(r"SAML.*login|identity provider", re.IGNORECASE), "saml_idp", 0.80),
    (re.compile(r"citrix.*login|citrix.*logon", re.IGNORECASE), "generic_auth_portal", 0.70),
]

IDENTITY_HEADER_PATTERNS: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r"^NTLM$", re.IGNORECASE), "ntlm_endpoint", 0.95),
    (re.compile(r"Negotiate", re.IGNORECASE), "ntlm_endpoint", 0.80),
    (re.compile(r"Bearer realm.*exchange", re.IGNORECASE), "exchange", 0.82),
]

# Confidence boost when two or more signals agree on the same host
_MULTI_SIGNAL_BOOST = 0.08


def classify_url(url: str) -> Optional[Tuple[str, float]]:
    """
    Match a URL against identity URL patterns.

    Returns (infra_type, confidence) if matched, else None.
    Security Rule 3.1: uses parsed URL scheme/path, not bare substring containment.
    """
    if not url:
        return None
    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None

    # LDAP scheme — direct scheme check per Rule 3.1
    if parsed.scheme in ("ldap", "ldaps"):
        return "ldap", 0.95

    # Match against path + query string only.
    # LDAP port patterns (:389/, :636/) live in the netloc, so include it for ldap checks.
    path_query = (parsed.path or "") + (("?" + parsed.query) if parsed.query else "")
    best: Optional[Tuple[str, float]] = None
    for pattern, infra_type, confidence in IDENTITY_URL_PATTERNS:
        # For LDAP port patterns the interesting part is the netloc; for all others
        # restrict matching to path+query to avoid false-positives from redirect URLs.
        search_target = (parsed.netloc + path_query) if infra_type == "ldap" else path_query
        if pattern.search(search_target):
            if best is None or confidence > best[1]:
                best = (infra_type, confidence)
    return best


def classify_title(title: str) -> Optional[Tuple[str, float]]:
    """
    Match a page title against identity title patterns.

    Returns (infra_type, confidence) if matched, else None.
    """
    if not title:
        return None
    for pattern, infra_type, confidence in IDENTITY_TITLE_PATTERNS:
        if pattern.search(title):
            return infra_type, confidence
    return None


def classify_header(headers: Dict[str, str]) -> Optional[Tuple[str, float]]:
    """
    Match HTTP response headers against identity patterns.

    Returns (infra_type, confidence) if matched, else None.
    """
    if not headers:
        return None
    www_auth = headers.get("WWW-Authenticate") or headers.get("www-authenticate") or ""
    for pattern, infra_type, confidence in IDENTITY_HEADER_PATTERNS:
        if pattern.search(www_auth):
            return infra_type, confidence
    return None


def _merge_signals(
    signals: List[Tuple[str, float, str]]
) -> Optional[Tuple[str, float, str]]:
    """
    Merge multiple signals for the same host into a single verdict.

    Args:
        signals: list of (infra_type, confidence, detection_method)

    Returns:
        (infra_type, final_confidence, detection_method) or None if no signals.
    """
    if not signals:
        return None
    if len(signals) == 1:
        return signals[0]

    type_groups: Dict[str, List[float]] = {}
    methods: Dict[str, List[str]] = {}
    for t, c, m in signals:
        type_groups.setdefault(t, []).append(c)
        methods.setdefault(t, []).append(m)

    best_type = max(type_groups, key=lambda t: max(type_groups[t]))
    best_confidence = max(type_groups[best_type])
    if len(signals) > 1:
        best_confidence = min(1.0, best_confidence + _MULTI_SIGNAL_BOOST)

    unique_methods = set(m for _, _, m in signals)
    detection_method = "combined" if len(unique_methods) > 1 else methods[best_type][0]
    return best_type, best_confidence, detection_method


def run_identity_intel(scan_history_id: int) -> List["IdentityInfraDiscovery"]:
    """
    Detect identity infrastructure from existing scan data.

    Reads Subdomain and EndPoint records for the scan and pattern-matches
    URLs and page titles. No outbound HTTP requests are made.

    Args:
        scan_history_id: ScanHistory.id

    Returns:
        List of IdentityInfraDiscovery instances created/updated.
    """
    from startScan.models import (
        ScanHistory, Subdomain, EndPoint, IdentityInfraDiscovery,
    )

    try:
        scan = ScanHistory.objects.select_related("domain").get(id=scan_history_id)
    except ScanHistory.DoesNotExist:
        logger.error("identity_tasks: ScanHistory %s not found", scan_history_id)
        return []

    domain = scan.domain
    results: List[IdentityInfraDiscovery] = []

    # Per-host signals accumulator: host → [(infra_type, confidence, detection_method)]
    host_signals: Dict[str, List[Tuple[str, float, str]]] = {}
    host_meta: Dict[str, dict] = {}

    # --- Signal 1: Subdomain URLs and page titles
    subdomains = Subdomain.objects.filter(
        scan_history_id=scan_history_id
    ).only("name", "http_url", "page_title", "id")

    for sub in subdomains:
        host = sub.name
        host_meta.setdefault(host, {"subdomain_id": sub.id})

        if sub.http_url:
            match = classify_url(sub.http_url)
            if match:
                host_signals.setdefault(host, []).append(
                    (match[0], match[1], "url_pattern")
                )

        if sub.page_title:
            match = classify_title(sub.page_title)
            if match:
                host_signals.setdefault(host, []).append(
                    (match[0], match[1], "title_keyword")
                )

    # --- Signal 2: EndPoint URLs
    endpoints = EndPoint.objects.filter(
        scan_history_id=scan_history_id
    ).select_related("subdomain").only("http_url", "subdomain__name")

    for ep in endpoints:
        if not ep.http_url:
            continue
        host = ep.subdomain.name if ep.subdomain else None
        if not host:
            continue
        match = classify_url(ep.http_url)
        if match:
            host_signals.setdefault(host, []).append(
                (match[0], match[1], "url_pattern")
            )

    # Pre-load all referenced subdomain objects in one query to avoid N+1.
    _sub_ids = [v["subdomain_id"] for v in host_meta.values() if "subdomain_id" in v]
    _subdomain_by_id: Dict[int, Subdomain] = {
        s.id: s for s in Subdomain.objects.filter(id__in=_sub_ids)
    }

    # --- Persist results
    for host, signals in host_signals.items():
        merged = _merge_signals(signals)
        if not merged:
            continue
        infra_type, confidence, detection_method = merged

        # Skip very-low-confidence generic portals unless a multi-signal boost applied
        if confidence < 0.50 and infra_type == "generic_auth_portal":
            continue

        meta = host_meta.get(host, {})
        subdomain_obj = _subdomain_by_id.get(meta.get("subdomain_id"))

        defaults = {
            "target_domain": domain,
            "subdomain": subdomain_obj,
            "url": "https://%s/" % host,
            "host": host,
            "infra_type": infra_type,
            "detection_method": detection_method,
            "confidence_score": round(confidence, 3),
            "is_externally_accessible": True,
            "additional_signals": {"signal_count": len(signals)},
        }

        obj, created = IdentityInfraDiscovery.objects.update_or_create(
            scan_history=scan,
            host=host,
            infra_type=infra_type,
            defaults=defaults,
        )
        results.append(obj)
        logger.info(
            "identity_tasks: %s %s @ %s (confidence=%.2f)",
            "Created" if created else "Updated",
            infra_type, host, confidence,
        )

    logger.info(
        "identity_tasks: Found %d identity infra records for scan %s",
        len(results), scan_history_id,
    )
    return results
