"""Assessment-scoped canonical asset correlation service.

Delegates per-scan work to ExposureCorrelationEngine (which stays scan-
scoped and untouched). Rolls up the resulting Exposure records — plus
Subdomain/EndPoint observations — into canonical assessment-scoped Asset
rows and AssetSource link rows.

See docs/superpowers/plans/2026-07-05-phases-5-6-neo4j-and-correlation.md
§4 for design.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.utils import timezone

from engagements.models import Assessment, Asset, AssetSource
from reNgine.exposure_correlation import (
    ExposureCorrelationEngine,
    _ASSET_TYPE_WEIGHTS,
    _SEVERITY_TO_SCORE,
    _HIGH_RISK_PORTS,
)
from startScan.models import Exposure, Subdomain, EndPoint, Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class AssetCorrelationResult:
    new_assets: int = 0
    updated_assets: int = 0
    new_sources: int = 0
    scans_processed: int = 0


def _normalize_url(raw: str) -> str:
    """Return `scheme://host[:non-default-port]/` for an HTTP-ish URL.

    Falls back to the raw string lowercased when parsing fails.
    """
    if not raw:
        return ""
    try:
        p = urlparse(raw.strip())
        scheme = (p.scheme or 'http').lower()
        host = (p.hostname or '').lower()
        if not host:
            return raw.strip().lower()
        port = p.port
        default = 443 if scheme == 'https' else 80
        port_part = f":{port}" if port and port != default else ''
        return f"{scheme}://{host}{port_part}/"
    except (ValueError, AttributeError):
        return raw.strip().lower()


def _normalize_host(name: str) -> str:
    if not name:
        return ""
    return "host://" + name.lower().rstrip('.')


def _hostname_from_canonical(canonical: str) -> str:
    """Extract the bare hostname from either canonical asset form.

    Handles both `host://<name>` (Subdomain/Exposure-derived) and
    `scheme://<name>[:port]/` (EndPoint-derived URL form).
    """
    if not canonical:
        return ""
    if canonical.startswith('host://'):
        return canonical.removeprefix('host://')
    return urlparse(canonical).hostname or ""


def _canonical_key_hash(assessment_uuid: str, normalized_identifier: str) -> str:
    return hashlib.sha256(
        f"{assessment_uuid}:{normalized_identifier}".encode('utf-8')
    ).hexdigest()


class AssetCorrelationService:
    """Roll up per-scan Exposure records into canonical assessment-scoped Assets."""

    def __init__(self, assessment: Assessment):
        self.assessment = assessment
        # Per-scan cache of {subdomain_name: [severity, ...]} built once in
        # _rollup_scan and consumed by _score_asset — avoids one Vulnerability
        # query per Exposure/Asset (see r3ngine-python-backend.md N+1 guidance).
        self._vuln_severity_cache: dict[int, dict[str, list[int]]] = {}

    def correlate(self) -> AssetCorrelationResult:
        result = AssetCorrelationResult()
        scan_ids = list(
            self.assessment.scan_histories.values_list('id', flat=True)
        )
        for scan_id in scan_ids:
            self._ensure_exposures(scan_id)
            self._rollup_scan(scan_id, result)
            result.scans_processed += 1
        return result

    def _ensure_exposures(self, scan_id: int) -> None:
        """Run ExposureCorrelationEngine for a scan if no Exposure rows exist yet."""
        if Exposure.objects.filter(scan_history_id=scan_id).exists():
            return
        from startScan.models import ScanHistory
        scan = ScanHistory.objects.filter(id=scan_id).first()
        if scan is None:
            return
        try:
            ExposureCorrelationEngine(scan_history=scan).correlate_exposures()
        except Exception as exc:
            logger.error(
                "AssetCorrelationService: ExposureCorrelationEngine failed for scan %s: %s",
                scan_id, exc, exc_info=True,
            )

    def _rollup_scan(self, scan_id: int, result: AssetCorrelationResult) -> None:
        """Merge subdomains, endpoints, and exposures for this scan into Assets."""
        assessment_uuid = str(self.assessment.uuid)
        sub_ct = ContentType.objects.get_for_model(Subdomain)
        ep_ct = ContentType.objects.get_for_model(EndPoint)
        exp_ct = ContentType.objects.get_for_model(Exposure)

        # Build the per-scan vulnerability-severity cache once, so _score_asset
        # never has to hit the DB per-asset (see N+1 note in __init__).
        self._build_vuln_severity_cache(scan_id)

        touched_asset_ids: set[int] = set()

        # ------------------------------------------------------------------ #
        # Subdomains → canonical hostname assets
        # ------------------------------------------------------------------ #
        subdomains = (
            Subdomain.objects.filter(scan_history_id=scan_id)
            .select_related('target_domain')
        )
        for sub in subdomains:
            canonical = _normalize_host(sub.name) if sub.name else ""
            if not canonical:
                continue
            asset = self._upsert_asset(
                assessment_uuid, canonical, 'Unclassified Asset', result,
            )
            touched_asset_ids.add(asset.id)
            self._upsert_source(
                asset=asset, tool='subdomain_enum', scan_id=scan_id,
                content_type=sub_ct, object_id=sub.id,
                payload={'name': sub.name, 'http_url': sub.http_url},
                result=result,
            )

        # ------------------------------------------------------------------ #
        # EndPoints → canonical URL assets
        # ------------------------------------------------------------------ #
        endpoints = (
            EndPoint.objects.filter(scan_history_id=scan_id)
            .select_related('subdomain', 'target_domain')
            .prefetch_related('subdomain__ip_addresses__ports')
        )
        for ep in endpoints:
            canonical = _normalize_url(ep.http_url)
            if not canonical:
                continue
            asset = self._upsert_asset(
                assessment_uuid, canonical, 'Web Application', result,
            )
            touched_asset_ids.add(asset.id)
            self._upsert_source(
                asset=asset, tool='katana', scan_id=scan_id,
                content_type=ep_ct, object_id=ep.id,
                payload={'url': ep.http_url, 'status': ep.http_status},
                result=result,
            )

        # ------------------------------------------------------------------ #
        # Exposures → canonical hostname assets tagged with exposure type
        # ------------------------------------------------------------------ #
        exposures = (
            Exposure.objects.filter(scan_history_id=scan_id)
            .select_related('subdomain', 'target_domain')
            .prefetch_related('subdomain__ip_addresses__ports')
        )
        for exp in exposures:
            sub_name = exp.subdomain.name if exp.subdomain else ""
            canonical = _normalize_host(sub_name) if sub_name else ""
            if not canonical:
                continue
            primary_type = (exp.type or ['Unclassified Asset'])[0]
            asset = self._upsert_asset(
                assessment_uuid, canonical, primary_type, result,
            )
            touched_asset_ids.add(asset.id)
            self._upsert_source(
                asset=asset, tool='exposure_engine', scan_id=scan_id,
                content_type=exp_ct, object_id=exp.id,
                payload={'type': exp.type, 'status': exp.status, 'risk_score': exp.risk_score},
                result=result,
            )

        # ------------------------------------------------------------------ #
        # Score every Asset touched in this rollup — not just Exposure-backed
        # ones — so URL-form and hostname-only assets get a non-zero score too.
        # ------------------------------------------------------------------ #
        if touched_asset_ids:
            for asset in Asset.objects.filter(id__in=touched_asset_ids):
                asset.risk_score = self._score_asset(asset, scan_id)
                asset.save(update_fields=['risk_score', 'last_seen_at'])

    def _upsert_asset(self, assessment_uuid: str, canonical: str,
                      asset_type: str, result: AssetCorrelationResult) -> Asset:
        key_hash = _canonical_key_hash(assessment_uuid, canonical)
        asset, created = Asset.objects.get_or_create(
            assessment=self.assessment,
            canonical_key_hash=key_hash,
            defaults={
                'canonical_identifier': canonical,
                'asset_type': asset_type,
            },
        )
        if created:
            result.new_assets += 1
        else:
            # Upgrade type if we now know something more specific than Unclassified.
            if (asset.asset_type == 'Unclassified Asset'
                    and asset_type != 'Unclassified Asset'):
                asset.asset_type = asset_type
                asset.save(update_fields=['asset_type'])
                result.updated_assets += 1
        return asset

    def _upsert_source(self, *, asset: Asset, tool: str, scan_id: int,
                       content_type, object_id: int, payload: dict,
                       result: AssetCorrelationResult) -> None:
        _, created = AssetSource.objects.get_or_create(
            asset=asset,
            source_content_type=content_type,
            source_object_id=object_id,
            defaults={
                'source_tool': tool,
                'source_scan_history_id': scan_id,
                'observed_at': timezone.now(),
                'payload': payload,
            },
        )
        if created:
            result.new_sources += 1

    def _score_asset(self, asset: Asset, scan_id: int) -> float:
        """Recompute risk_score using ExposureCorrelationEngine weights.

        Gracefully handles assets with no matching Exposure (e.g. URL-form
        canonical assets derived purely from an EndPoint): max_sev and
        port_score both default to 0.0, leaving the asset-type weight as
        the sole contribution to the score.
        """
        type_base = _ASSET_TYPE_WEIGHTS.get(asset.asset_type, 3.0)

        hostname = _hostname_from_canonical(asset.canonical_identifier)
        severities = self._vuln_severity_cache.get(scan_id, {}).get(hostname, [])
        max_sev = max(
            (_SEVERITY_TO_SCORE.get(s, 0.0) for s in severities),
            default=0.0,
        )

        # Port component derived from the linked Exposures for this asset, if any.
        exposure_ids = list(
            asset.sources.filter(source_tool='exposure_engine')
                 .values_list('source_object_id', flat=True)
        )
        port_score = 0.0
        if exposure_ids:
            ports = set()
            for exp in Exposure.objects.filter(id__in=exposure_ids).select_related('subdomain'):
                if not exp.subdomain:
                    continue
                for ip in exp.subdomain.ip_addresses.all():
                    for port in ip.ports.all():
                        ports.add(port.number)
            port_score = min(len(ports & _HIGH_RISK_PORTS) * 2.0, 10.0)

        raw = 0.50 * max_sev + 0.35 * type_base + 0.15 * port_score
        return round(min(raw, 10.0), 2)

    def _build_vuln_severity_cache(self, scan_id: int) -> None:
        """Populate self._vuln_severity_cache[scan_id] with one query.

        Maps subdomain name -> list of severities, so _score_asset can look
        up severities in-memory instead of issuing one Vulnerability query
        per Asset (N+1 fix — see r3ngine-python-backend.md ORM guidance).
        """
        if scan_id in self._vuln_severity_cache:
            return
        cache: dict[str, list[int]] = {}
        rows = (
            Vulnerability.objects
            .filter(scan_history_id=scan_id)
            .exclude(subdomain__isnull=True)
            .values_list('subdomain__name', 'severity')
        )
        for name, severity in rows:
            cache.setdefault(name, []).append(severity)
        self._vuln_severity_cache[scan_id] = cache
