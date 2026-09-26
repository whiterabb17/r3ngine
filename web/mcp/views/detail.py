"""Complementary MCP detail payloads — richer than thin list/get serializers."""

from django.db.models import Count, Q

from rest_framework.response import Response

from mcp.views.base import McpDataView
from mcp.views.read import (
    serialize_endpoint,
    serialize_exposure,
    serialize_scan,
    serialize_subdomain,
    serialize_subscan,
    serialize_target,
    serialize_vulnerability,
    _dt,
)
from reNgine.definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    INITIATED_TASK,
    RUNNING_TASK,
    SUCCESS_TASK,
)
from startScan.models import (
    EndPoint,
    Exposure,
    ScanActivity,
    ScanHistory,
    Subdomain,
    SubScan,
    Vulnerability,
)
from targetApp.models import Domain

RELATED_LIST_CAP = 20
ACTIVITY_BUCKET_CAP = 100

_STATUS_BUCKETS = (
    ('initiated', INITIATED_TASK),
    ('failed', FAILED_TASK),
    ('running', RUNNING_TASK),
    ('success', SUCCESS_TASK),
    ('aborted', ABORTED_TASK),
)

_STATUS_LABELS = {
    INITIATED_TASK: 'initiated',
    FAILED_TASK: 'failed',
    RUNNING_TASK: 'running',
    SUCCESS_TASK: 'success',
    ABORTED_TASK: 'aborted',
}


def _cap(iterable, n=RELATED_LIST_CAP):
    return list(iterable[:n])


def _excluded_paths_snippet(paths):
    if not paths:
        return {'count': 0, 'paths': []}
    items = list(paths) if not isinstance(paths, list) else paths
    return {'count': len(items), 'paths': items[:RELATED_LIST_CAP]}


def serialize_activity(row):
    return {
        'id': row.id,
        'name': row.name,
        'title': row.title,
        'tier': row.tier,
        'status': row.status,
        'status_label': _STATUS_LABELS.get(row.status, 'unknown'),
        'target_host': row.target_host or None,
        'time_started': _dt(row.time_started),
        'time_ended': _dt(row.time_ended),
        'error_message': row.error_message,
        'subscan_id': row.subscan_id,
    }


def bucket_activities(queryset):
    """Group ScanActivity rows by status; cap each bucket; return full counts."""
    ordered = list(queryset.order_by('tier', 'time_started', 'id'))
    tasks = {name: [] for name, _ in _STATUS_BUCKETS}
    summary = {name: 0 for name, _ in _STATUS_BUCKETS}
    for row in ordered:
        label = _STATUS_LABELS.get(row.status)
        if not label:
            continue
        summary[label] += 1
        if len(tasks[label]) < ACTIVITY_BUCKET_CAP:
            tasks[label].append(serialize_activity(row))
    return summary, tasks


def _severity_counts(vuln_qs):
    buckets = {-1: 'unknown', 0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
    counts = {label: 0 for label in buckets.values()}
    for row in vuln_qs.values('severity').annotate(n=Count('id')):
        label = buckets.get(row['severity'])
        if label:
            counts[label] = row['n']
    return counts


def serialize_scan_detail(row):
    from reNgine.capabilities import RISK_ACTIVE, ASSET_SUBDOMAIN
    activities = ScanActivity.objects.filter(scan_of_id=row.id)
    task_summary, tasks = bucket_activities(activities)
    vulns = Vulnerability.objects.filter(scan_history_id=row.id)
    # Coverage-gap suggestions: empty failed/aborted buckets → propose retry or follow-up
    suggestions = []
    for failed in tasks.get('failed') or []:
        suggestions.append({
            'tool': failed.get('name'),
            'asset_type': ASSET_SUBDOMAIN,
            'reason': f"Retry failed task {failed.get('title') or failed.get('name')}",
            'risk': RISK_ACTIVE,
            'step_kind': 'retry_task',
            'task_id': failed.get('id'),
        })
        if len(suggestions) >= 3:
            break
    if not suggestions and (task_summary.get('success') or 0) == 0:
        suggestions.append({
            'tool': 'port_scan',
            'asset_type': ASSET_SUBDOMAIN,
            'reason': 'No successful tasks yet — consider port scan follow-up on hot hosts',
            'risk': RISK_ACTIVE,
            'step_kind': 'run_tool',
        })
    return {
        **serialize_scan(row),
        'engine_name': row.scan_type.engine_name if row.scan_type_id else None,
        'hardware_profile_id': row.hardware_profile_id,
        'error_message': row.error_message,
        'tasks_planned': list(row.tasks or []),
        'counts': {
            'subdomains': Subdomain.objects.filter(scan_history_id=row.id).count(),
            'endpoints': EndPoint.objects.filter(scan_history_id=row.id).count(),
            'vulnerabilities': vulns.count(),
            'exposures': Exposure.objects.filter(scan_history_id=row.id).count(),
            'subscans': SubScan.objects.filter(scan_history_id=row.id).count(),
        },
        'severity_counts': _severity_counts(vulns),
        'task_summary': task_summary,
        'tasks': tasks,
        'suggested_followups': suggestions[:3],
    }


def serialize_target_detail(row):
    scans = ScanHistory.objects.filter(domain_id=row.id).select_related('domain').order_by('-id')
    vulns = (
        Vulnerability.objects.filter(target_domain_id=row.id)
        .select_related('subdomain')
        .order_by('-severity', '-id')
    )
    return {
        **serialize_target(row),
        'description': row.description,
        'h1_team_handle': row.h1_team_handle,
        'ip_address_cidr': row.ip_address_cidr,
        'start_scan_date': _dt(row.start_scan_date),
        'starting_point_path': row.starting_point_path,
        'excluded_paths': _excluded_paths_snippet(row.excluded_paths),
        'counts': {
            'scans': scans.count(),
            'vulnerabilities': vulns.count(),
            'exposures': Exposure.objects.filter(target_domain_id=row.id).count(),
        },
        'recent_scans': [serialize_scan(s) for s in _cap(scans)],
        'recent_vulnerabilities': [serialize_vulnerability(v) for v in _cap(vulns)],
    }


def serialize_vulnerability_detail(row):
    from reNgine.capabilities import suggest_followups_for_vulnerability
    extracted = list(row.extracted_results or [])
    scan = None
    if row.scan_history_id:
        scan = ScanHistory.objects.select_related('domain').filter(pk=row.scan_history_id).first()
    return {
        **serialize_vulnerability(row),
        'description': row.description,
        'impact': row.impact,
        'remediation': row.remediation,
        'cvss_score': row.cvss_score,
        'cvss_metrics': row.cvss_metrics,
        'source': row.source,
        'template_id': row.template_id,
        'validation_status': row.validation_status,
        'open_status': row.open_status,
        'discovered_date': _dt(row.discovered_date),
        'cve_ids': [c.name for c in row.cve_ids.all()[:RELATED_LIST_CAP]],
        'cwe_ids': [c.name for c in row.cwe_ids.all()[:RELATED_LIST_CAP]],
        'tags': [t.name for t in row.tags.all()[:RELATED_LIST_CAP]],
        'extracted_results': extracted[:RELATED_LIST_CAP],
        'subdomain_id': row.subdomain_id,
        'endpoint_id': row.endpoint_id,
        'exposure_id': row.exposure_id,
        'target_id': row.target_domain_id,
        'target_name': row.target_domain.name if row.target_domain_id else None,
        'scan': serialize_scan(scan) if scan else None,
        'suggested_followups': suggest_followups_for_vulnerability(row),
    }


def serialize_subdomain_detail(row):
    from reNgine.capabilities import suggest_followups_for_subdomain
    vulns = (
        Vulnerability.objects.filter(subdomain_id=row.id)
        .select_related('subdomain')
        .order_by('-severity', '-id')
    )
    endpoints = EndPoint.objects.filter(subdomain_id=row.id).order_by('-id')
    return {
        **serialize_subdomain(row),
        'http_url': row.http_url,
        'cname': row.cname,
        'is_cdn': row.is_cdn,
        'cdn_name': row.cdn_name,
        'webserver': row.webserver,
        'page_title': row.page_title,
        'discovered_date': _dt(row.discovered_date),
        'ip_addresses': [
            ip.address for ip in row.ip_addresses.all()[:RELATED_LIST_CAP] if ip.address
        ],
        'technologies': [t.name for t in row.technologies.all()[:RELATED_LIST_CAP] if t.name],
        'waf': [w.name for w in row.waf.all()[:RELATED_LIST_CAP]],
        'counts': {
            'endpoints': endpoints.count(),
            'vulnerabilities': vulns.count(),
        },
        'recent_vulnerabilities': [serialize_vulnerability(v) for v in _cap(vulns)],
        'recent_endpoints': [serialize_endpoint(e) for e in _cap(endpoints)],
        'suggested_followups': suggest_followups_for_subdomain(row),
    }


def serialize_endpoint_detail(row):
    from reNgine.capabilities import suggest_followups_for_endpoint
    vulns = (
        Vulnerability.objects.filter(endpoint_id=row.id)
        .select_related('subdomain')
        .order_by('-severity', '-id')
    )
    params = row.parameters.all().order_by('-id')
    return {
        **serialize_endpoint(row),
        'page_title': row.page_title,
        'content_type': row.content_type,
        'content_length': row.content_length,
        'webserver': row.webserver,
        'response_time': row.response_time,
        'discovered_date': _dt(row.discovered_date),
        'source': row.source,
        'techs': [t.name for t in row.techs.all()[:RELATED_LIST_CAP] if t.name],
        'subdomain_id': row.subdomain_id,
        'target_id': row.target_domain_id,
        'recent_vulnerabilities': [serialize_vulnerability(v) for v in _cap(vulns)],
        'parameters': [
            {
                'id': p.id,
                'name': p.name,
                'type': p.type,
                'confidence': p.confidence,
            }
            for p in _cap(params)
        ],
        'suggested_followups': suggest_followups_for_endpoint(row),
    }


def serialize_exposure_detail(row):
    vulns = (
        Vulnerability.objects.filter(exposure_id=row.id)
        .select_related('subdomain')
        .order_by('-severity', '-id')
    )
    return {
        **serialize_exposure(row),
        'status_note': row.status_note,
        'first_seen': _dt(row.first_seen),
        'last_seen': _dt(row.last_seen),
        'type': list(row.type or []),
        'subdomain_id': row.subdomain_id,
        'subdomain_name': row.subdomain.name if row.subdomain_id else None,
        'endpoint_id': row.endpoint_id,
        'target_name': row.target_domain.name if row.target_domain_id else None,
        'vulnerabilities': [serialize_vulnerability(v) for v in _cap(vulns)],
    }


def activities_for_subscan(row):
    """Activities stamped with this subscan, or same-name parent rows in the subscan window.

    Claim/initialize historically reused parent-scan ScanActivity rows without
    always setting subscan_id; fall back to type + time window when needed.
    """
    linked = ScanActivity.objects.filter(subscan_id=row.id)
    if linked.exists() or not row.type or not row.scan_history_id:
        return linked
    qs = ScanActivity.objects.filter(
        scan_of_id=row.scan_history_id,
        name=row.type,
        subscan_id__isnull=True,
    )
    if row.start_scan_date:
        qs = qs.filter(
            Q(time_started__gte=row.start_scan_date)
            | Q(time_started__isnull=True, time__gte=row.start_scan_date)
        )
    if row.stop_scan_date:
        qs = qs.filter(
            Q(time_ended__lte=row.stop_scan_date)
            | Q(time_ended__isnull=True)
            | Q(time__lte=row.stop_scan_date)
        )
    return qs


def serialize_subscan_detail(row):
    parent = None
    if row.scan_history_id:
        parent = ScanHistory.objects.select_related('domain').filter(pk=row.scan_history_id).first()
    activities = activities_for_subscan(row)
    task_summary, tasks = bucket_activities(activities)
    return {
        **serialize_subscan(row),
        'error_message': row.error_message,
        'engine_id': row.engine_id,
        'engine_name': row.engine.engine_name if row.engine_id else None,
        'subdomain_name': row.subdomain.name if row.subdomain_id else None,
        'scan': serialize_scan(parent) if parent else None,
        'task_summary': task_summary,
        'tasks': tasks,
    }


class McpGetScanDetailView(McpDataView):
    def get(self, request, pk):
        row = (
            ScanHistory.objects
            .select_related('domain', 'scan_type')
            .filter(pk=pk)
            .first()
        )
        if not row:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_scan_detail(row))


def _query_bool(params, key: str, default: bool) -> bool:
    raw = params.get(key)
    if raw is None or raw == '':
        return default
    return str(raw).strip().lower() in ('1', 'true', 'yes', 'on')


class McpExportScanForAiView(McpDataView):
    """Same Analyst Assist AI export as the scan-detail UI, as JSON for agents.

    Returns markdown overview, triage prompt, full structured bundle, and
    manifest — equivalent to the ZIP the UI downloads, without binary packaging.
    """

    def get(self, request, pk):
        from reNgine.exporters.ai_bundle import (
            AiExportOptions,
            FORMAT_VERSION,
            build_ai_export_payload,
        )

        row = (
            ScanHistory.objects
            .select_related('domain', 'domain__project', 'scan_type')
            .filter(pk=pk)
            .first()
        )
        if not row:
            return Response({'error': 'Not found'}, status=404)

        preset = (request.query_params.get('preset') or 'analyst_assist').strip()
        if preset != 'analyst_assist':
            return Response({'error': 'Unsupported preset'}, status=400)

        options = AiExportOptions(
            preset=preset,
            include_raw_outputs=_query_bool(request.query_params, 'include_raw_outputs', False),
            include_timeline=_query_bool(request.query_params, 'include_timeline', True),
            include_sidecars=_query_bool(request.query_params, 'include_sidecars', True),
            format_version=request.query_params.get('format_version') or FORMAT_VERSION,
        )

        include_files = _query_bool(request.query_params, 'include_files', False)
        try:
            payload = build_ai_export_payload(scan=row, options=options)
        except Exception as exc:
            return Response({'error': f'Failed to build AI export: {exc}'}, status=500)

        # Omit raw file blobs by default — agents use markdown + bundle.
        if not include_files:
            payload = {k: v for k, v in payload.items() if k != 'files'}

        return Response(payload)

class McpGetTargetDetailView(McpDataView):
    def get(self, request, pk):
        row = Domain.objects.select_related('project').filter(pk=pk).first()
        if not row:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_target_detail(row))


class McpGetVulnerabilityDetailView(McpDataView):
    def get(self, request, pk):
        row = (
            Vulnerability.objects
            .select_related('subdomain', 'target_domain', 'endpoint', 'exposure')
            .prefetch_related('cve_ids', 'cwe_ids', 'tags')
            .filter(pk=pk)
            .first()
        )
        if not row:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_vulnerability_detail(row))


class McpGetSubdomainDetailView(McpDataView):
    def get(self, request, pk):
        row = (
            Subdomain.objects
            .prefetch_related('ip_addresses', 'technologies', 'waf')
            .filter(pk=pk)
            .first()
        )
        if not row:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_subdomain_detail(row))


class McpGetEndpointDetailView(McpDataView):
    def get(self, request, pk):
        row = (
            EndPoint.objects
            .prefetch_related('techs', 'parameters')
            .filter(pk=pk)
            .first()
        )
        if not row:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_endpoint_detail(row))


class McpGetExposureDetailView(McpDataView):
    def get(self, request, pk):
        row = (
            Exposure.objects
            .select_related('subdomain', 'endpoint', 'target_domain')
            .filter(pk=pk)
            .first()
        )
        if not row:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_exposure_detail(row))


class McpGetSubscanDetailView(McpDataView):
    def get(self, request, pk):
        row = (
            SubScan.objects
            .select_related('subdomain', 'engine', 'scan_history', 'scan_history__domain')
            .filter(pk=pk)
            .first()
        )
        if not row:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_subscan_detail(row))
