from django.db.models import Count, Q, F
from django.http import FileResponse
from django.utils import timezone
from datetime import timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from dashboard.models import Project
from targetApp.models import Domain
from startScan.models import (
    Subdomain, EndPoint, Vulnerability, 
    VulnerabilityTags, IpAddress, Port, Technology, 
    MonitoringDiscovery, CountryISO, CveId, CweId,
    Email, Employee, ScanHistory, SubScan, ScanActivity, SecretLeak, Command,
    Dork, MetaFinderDocument, S3Bucket
)
from recon_note.models import TodoNote
from reNgine.utilities import get_screenshot_path
from reNgine.definitions import RUNNING_TASK
from reNgine.exporters.ai_bundle import AiExportOptions, FORMAT_VERSION, build_ai_export_zip
from api.scan_task_counts import get_task_counts

from api.target_summary_serializers import TargetSummarySerializer, TacticalScanHistorySerializer
from api.serializers import (
    MonitoringDiscoverySerializer, SubScanSerializer, 
    SecretLeakSerializer, EmailSerializer, EmployeeSerializer, 
    DorkSerializer, MetafinderDocumentSerializer, S3BucketSerializer
)

class ScanSummaryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, slug, id):
        """Fetch and return summary information for a specific scan.

        Args:
            request (Request): Django REST Framework request object.
            slug (str): Project slug identifier.
            id (int): Scan history ID.

        Returns:
            Response: API Response containing scan metrics, status, timeline, vulnerabilities, and target domain details.
        """
        try:
            project = Project.objects.get(slug=slug)
            scan = ScanHistory.objects.get(id=id, domain__project=project)
            target = scan.domain
        except (Project.DoesNotExist, ScanHistory.DoesNotExist):
            return Response({'error': 'Scan not found'}, status=404)

        # Scans related to this target (for timeline/recent scans)
        all_scans = ScanHistory.objects.filter(domain=target).order_by('-start_scan_date')
        scan_count = all_scans.count()
        this_week_scan_count = all_scans.filter(start_scan_date__gte=timezone.now() - timedelta(days=7)).count()
        recent_scans = all_scans[:5]

        # Query sets for the target domain
        subdomain_qs = Subdomain.objects.filter(target_domain=target)
        alive_count = subdomain_qs.filter(http_status__gt=0, http_status__lt=500).exclude(http_status=404).count()
        subdomain_count = subdomain_qs.count()
        important_subdomains = subdomain_qs.filter(is_important=True)

        endpoint_qs = EndPoint.objects.filter(target_domain=target)
        endpoint_count = endpoint_qs.count()
        endpoint_alive_count = endpoint_qs.filter(http_status__in=[200, 301, 302, 403]).count()

        # Vulnerabilities - Cumulative for target
        vulnerabilities = Vulnerability.objects.filter(target_domain=target)
        # Auto-mark RESOLVED vulnerabilities if this scan included vuln scan and is finished
        if scan.scan_status == 2 and scan.tasks and 'vulnerability_scan' in scan.tasks:
            current_vulns = vulnerabilities.filter(scan_history=scan)
            current_vuln_keys = set((v.name, v.http_url) for v in current_vulns)
            
            # Find open vulns from previous scans that were NOT found in this scan
            previous_open_vulns = vulnerabilities.filter(
                open_status=True,
                is_suppressed=False
            ).exclude(scan_history=scan)
            
            for v in previous_open_vulns:
                if (v.name, v.http_url) not in current_vuln_keys:
                    v.open_status = False
                    v.save()

        critical_count = vulnerabilities.filter(severity=4).count()
        high_count = vulnerabilities.filter(severity=3).count()
        medium_count = vulnerabilities.filter(severity=2).count()
        low_count = vulnerabilities.filter(severity=1).count()
        info_count = vulnerabilities.filter(severity=0).count()
        unknown_count = vulnerabilities.filter(severity=-1).count()
        
        # Aggregations
        most_common_vulnerability = vulnerabilities.exclude(severity=0).values("name", "severity").annotate(count=Count('name')).order_by("-count")[:10]
        most_common_tags = VulnerabilityTags.objects.filter(vuln_tags__in=vulnerabilities).annotate(nused=Count('vuln_tags')).order_by('-nused').values('name', 'nused')[:7]
        # Filter out empty or null CVEs to prevent displaying blank items
        most_common_cve = CveId.objects.filter(cve_ids__in=vulnerabilities).exclude(name='').exclude(name__isnull=True).annotate(nused=Count('cve_ids')).order_by('-nused').values('name', 'nused')[:7]
        # Filter out empty or null CWEs to prevent displaying blank items and frontend errors on click
        most_common_cwe = CweId.objects.filter(cwe_ids__in=vulnerabilities).exclude(name='').exclude(name__isnull=True).annotate(nused=Count('cwe_ids')).order_by('-nused').values('name', 'nused')[:7]

        # Assets
        # IP Addresses and Country ISO - Target-wide
        ip_addresses = IpAddress.objects.filter(ip_addresses__target_domain=target).distinct()
        asset_countries = ip_addresses.exclude(geo_iso=None).values(name=F('geo_iso__name'), iso=F('geo_iso__iso')).annotate(count=Count('geo_iso')).order_by('-count')
        subdomain_statuses = subdomain_qs.exclude(Q(http_status=0) | Q(http_status__isnull=True)).values('http_status').annotate(count=Count('http_status'))
        endpoint_statuses = endpoint_qs.exclude(Q(http_status=0) | Q(http_status__isnull=True)).values('http_status').annotate(count=Count('http_status'))
        
        # Combine Subdomain and EndPoint status codes for a comprehensive breakdown
        status_map = {}
        for item in subdomain_statuses:
            status = item['http_status']
            status_map[status] = status_map.get(status, 0) + item['count']
        
        for item in endpoint_statuses:
            status = item['http_status']
            status_map[status] = status_map.get(status, 0) + item['count']
            
        http_status_breakdown = sorted(
            [{'http_status': k, 'count': v} for k, v in status_map.items()],
            key=lambda x: x['http_status']
        )
        
        discovered_ports = Port.objects.filter(ports__in=ip_addresses).values('number', 'service_name', 'is_uncommon').annotate(count=Count('number')).order_by('-count')[:20]
        
        endpoint_techs = Technology.objects.filter(techs__target_domain=target)
        subdomain_techs = Technology.objects.filter(technologies__target_domain=target)
        discovered_technologies = (endpoint_techs | subdomain_techs).distinct().values('name').annotate(count=Count('name')).order_by('-count')[:20]

        # Domain Information
        domain_info_data = None
        if hasattr(target, 'domain_info') and target.domain_info:
            di = target.domain_info
            domain_info_data = {
                'dnssec': di.dnssec,
                'geolocation_iso': di.geolocation_iso,
                'created': di.created,
                'updated': di.updated,
                'expires': di.expires,
                'whois_server': di.whois_server,
                'registrar': {
                    'name': di.registrar.name if di.registrar else None,
                    'phone': di.registrar.phone if di.registrar else None,
                    'email': di.registrar.email if di.registrar else None,
                },
                'dns_records': list(di.dns_records.all().values('type', 'name'))[:20],
                'name_servers': list(di.name_servers.all().values('name'))[:10],
                'nameservers': [ns.name for ns in di.name_servers.all()][:10],
                'historical_ips': list(di.historical_ips.all().values('ip', 'location', 'owner', 'last_seen'))[:10],
            }

        # Related
        related_domains = []
        related_tlds = []
        if hasattr(target, 'domain_info') and target.domain_info:
            related_domains = list(target.domain_info.related_domains.all().values_list('name', flat=True)[:20])
            related_tlds = list(target.domain_info.related_tlds.all().values_list('name', flat=True)[:20])

        # Monitoring Discoveries for THIS scan
        monitoring_discoveries = MonitoringDiscovery.objects.filter(scan_history=scan).order_by('-discovered_at')[:10]
        
        # Subscans for THIS scan
        subscans = SubScan.objects.filter(scan_history=scan).order_by('-start_scan_date')[:10]
        
        # Recent scans for the same target
        recent_scans_data = []
        for i, s in enumerate(recent_scans):
            scan_data = TacticalScanHistorySerializer(s).data
            scan_data['subdomain_count'] = s.get_subdomain_count()
            scan_data['engine_name'] = s.scan_type.engine_name if s.scan_type else "Default"
            if i + 1 < len(recent_scans):
                prev_scan = recent_scans[i+1]
                prev_count = prev_scan.get_subdomain_count()
                scan_data['subdomain_diff'] = scan_data['subdomain_count'] - prev_count
            else:
                scan_data['subdomain_diff'] = 0
            recent_scans_data.append(scan_data)

        # Timeline/Activities — ordered by tier then time_started, PENDING rows last within tier
        activities = ScanActivity.objects.filter(scan_of=scan).order_by(
            'tier', 'time_started', 'time'
        )
        timeline_data = []
        _STATUS_MAP = {
            2: 'SUCCESS',
            1: 'RUNNING',
            0: 'FAILED',
            3: 'ABORTED',
            -1: 'PENDING',
        }
        for activity in activities:
            timeline_data.append({
                'id': activity.id,
                'task_uid': str(activity.task_uid) if activity.task_uid else None,
                'title': activity.title,
                'time': activity.time,
                'time_started': activity.time_started,
                'time_ended': activity.time_ended,
                'tier': activity.tier,
                'status': _STATUS_MAP.get(activity.status, 'UNKNOWN'),
                'name': activity.name,
                'error_message': activity.error_message,
                'commands': list(Command.objects.filter(activity=activity).values('command', 'output', 'return_code'))
            })

        # OSINT - Cumulative for target
        emails = Email.objects.filter(emails__domain=target).distinct()
        exposed_count = emails.exclude(password__isnull=True).count()
        secret_leaks = SecretLeak.objects.filter(scan_history__domain=target)
        secret_leaks_count = secret_leaks.count()
        exploitable_count = vulnerabilities.exclude(exploit_url__isnull=True).exclude(exploit_url__exact='').count()
        matched_gf_count = []
        if scan.used_gf_patterns:
            for gf in scan.used_gf_patterns.split(','):
                matched_gf_count.append({
                    'matched_gf_patterns': gf,
                    'count': endpoint_qs.filter(matched_gf_patterns__icontains=gf).count()
                })

        _tc = get_task_counts(scan)
        data = {
            'subdomain_count': subdomain_count,
            'alive_count': alive_count,
            'endpoint_count': endpoint_count,
            'endpoint_alive_count': endpoint_alive_count,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'info_count': info_count,
            'unknown_count': unknown_count,
            'total_vul_ignore_info_count': sum([low_count, medium_count, high_count, critical_count]),
            'vulnerability_count': vulnerabilities.count(),
            'most_common_vulnerability': list(most_common_vulnerability),
            'most_common_tags': list(most_common_tags),
            'most_common_cve': list(most_common_cve),
            'most_common_cwe': list(most_common_cwe),
            'asset_countries': list(asset_countries),
            'http_status_breakdown': list(http_status_breakdown),
            'exposed_count': exposed_count,
            'secret_leaks_count': secret_leaks_count,
            'exploitable_count': exploitable_count,
            'matched_gf_count': matched_gf_count,
            'buckets_count': S3Bucket.objects.filter(buckets__domain=target).distinct().count(),
            'email_count': emails.count(),
            'employees_count': Employee.objects.filter(employees__domain=target).distinct().count(),
            'emails': EmailSerializer(emails, many=True).data,
            'employees': EmployeeSerializer(Employee.objects.filter(employees__domain=target).distinct(), many=True).data,
            'dorks': DorkSerializer(Dork.objects.filter(dorks__domain=target).distinct(), many=True).data,
            'documents': MetafinderDocumentSerializer(MetaFinderDocument.objects.filter(target_domain=target), many=True).data,
            'buckets': S3BucketSerializer(S3Bucket.objects.filter(buckets__domain=target).distinct(), many=True).data,
            'todo_notes': list(TodoNote.objects.filter(scan_history=scan).values('id', 'title', 'description', 'is_done', 'is_important')),
            'monitoring_discoveries_list': MonitoringDiscoverySerializer(monitoring_discoveries, many=True).data,
            'subscans': SubScanSerializer(subscans, many=True).data,
            'recent_scans': recent_scans_data,
            'important_subdomains': list(important_subdomains),
            'discovered_ports': list(discovered_ports),
            'discovered_technologies': list(discovered_technologies),
            'project_info': {'name': project.name, 'slug': project.slug},
            'target_info': {'name': target.name, 'id': target.id},
            'domain_info': domain_info_data,
            'related_domains': related_domains,
            'related_tlds': related_tlds,
            'scan_count': scan_count,
            'this_week_scan_count': this_week_scan_count,
            'vulnerability_highlights': list(vulnerabilities.order_by('-severity', '-discovered_date')[:10].values(
                'id', 'name', 'severity', 'http_url', 'discovered_date', 'description', 'impact', 'remediation', 'is_gpt_used'
            )),
            'subdomains': [
                {
                    'name': sub.name,
                    'http_status': sub.http_status,
                    'page_title': sub.page_title,
                    'http_url': sub.http_url,
                    'origin_ip': sub.origin_ip,
                    'response_time': sub.response_time,
                    'screenshot_path': get_screenshot_path(sub),
                    'critical_count': sub.get_critical_count,
                    'high_count': sub.get_high_count,
                    'medium_count': sub.get_medium_count,
                    'low_count': sub.get_low_count,
                    'info_count': sub.get_info_count,
                    'content_length': sub.content_length,
                    'ip_addresses': [
                        {
                            'address': ip.address,
                            'is_cdn': ip.is_cdn,
                            'ports': list(ip.ports.all().values('number', 'service_name', 'is_uncommon'))
                        } for ip in sub.ip_addresses.all()
                    ]
                } for sub in subdomain_qs.order_by('name')[:100]
            ],
            'endpoints': list(endpoint_qs.order_by('http_url')[:100].values('id', 'http_url', 'http_status', 'content_type', 'techs__name')),
            'vulnerabilities': [
                {
                    'id': v['id'],
                    'name': v['name'],
                    'severity': v['severity'],
                    'description': v['description'],
                    'impact': v['impact'],
                    'remediation': v['remediation'],
                    'http_url': v['http_url'],
                    'matched_at': v['discovered_date'],
                    'is_gpt_used': v['is_gpt_used'],
                    'domain_name': v['subdomain__name'] or v['target_domain__name'] or target.name
                } for v in vulnerabilities.order_by('-severity')[:100].values(
                    'id', 'name', 'severity', 'description', 'impact', 'remediation', 'http_url', 'discovered_date', 'is_gpt_used', 'subdomain__name', 'target_domain__name'
                )
            ],
            'monitoring_discoveries': list(monitoring_discoveries.values('id', 'discovery_type', 'content')),
            'secret_leaks': SecretLeakSerializer(secret_leaks[:100], many=True).data,
            # Scan specific data
            'scan_info': {
                'id': scan.id,
                'scan_status': scan.scan_status,
                'engine_name': scan.scan_type.engine_name if scan.scan_type else "Standard",
                'start_scan_date': scan.start_scan_date,
                'stop_scan_date': scan.stop_scan_date,
                'duration': int((scan.stop_scan_date - scan.start_scan_date).total_seconds()) if scan.stop_scan_date and scan.start_scan_date else int((timezone.now() - scan.start_scan_date).total_seconds()) if scan.start_scan_date else 0,
                'progress': scan.get_progress() or 0,
                'cfg_starting_point_path': scan.cfg_starting_point_path,
                'cfg_imported_subdomains': scan.cfg_imported_subdomains or [],
                'cfg_out_of_scope_subdomains': scan.cfg_out_of_scope_subdomains or [],
                'cfg_excluded_paths': scan.cfg_excluded_paths or [],
                'tasks': scan.tasks or [],
                'used_gf_patterns': scan.used_gf_patterns.split(',') if scan.used_gf_patterns else [],
                'is_spiderfoot_running': scan.scanactivity_set.filter(
                    Q(name='spiderfoot_scan') | Q(title__icontains='spiderfoot'),
                    status=RUNNING_TASK
                ).exists(),
                'successful_task_count': _tc[0],
                'failed_task_count': _tc[1],
                'total_task_count': _tc[2],
            },
            'exposed_count': exposed_count,
            'secret_leaks_count': secret_leaks_count,
            'exploitable_count': exploitable_count,
            'matched_gf_count': matched_gf_count,
            'buckets_count': scan.buckets.count(),
            'timeline': timeline_data
        }

        serializer = TargetSummarySerializer(data)
        return Response(serializer.data)


class ScanAiExportAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, slug, id):
        try:
            project = Project.objects.get(slug=slug)
            scan = ScanHistory.objects.select_related("domain", "scan_type").get(id=id, domain__project=project)
        except (Project.DoesNotExist, ScanHistory.DoesNotExist):
            return Response({"error": "Scan not found"}, status=404)

        payload = request.data or {}
        preset = payload.get("preset", "analyst_assist")
        if preset != "analyst_assist":
            return Response({"error": "Unsupported preset"}, status=400)

        options = AiExportOptions(
            preset=preset,
            include_raw_outputs=bool(payload.get("include_raw_outputs", False)),
            include_timeline=bool(payload.get("include_timeline", True)),
            include_sidecars=bool(payload.get("include_sidecars", True)),
            format_version=payload.get("format_version") or FORMAT_VERSION,
        )

        try:
            zip_buffer, filename = build_ai_export_zip(scan=scan, options=options)
        except Exception as exc:
            return Response({"error": f"Failed to build AI export: {exc}"}, status=500)

        return FileResponse(
            zip_buffer,
            as_attachment=True,
            filename=filename,
            content_type="application/zip",
        )
