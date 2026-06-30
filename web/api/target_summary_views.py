from django.db.models import Count, Q, F
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
    Email, Employee, ScanHistory, SubScan
)

from api.target_summary_serializers import TargetSummarySerializer, TacticalScanHistorySerializer
from api.serializers import MonitoringDiscoverySerializer, SubScanSerializer

class TargetSummaryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, slug, id):
        """Fetch and return summary information for a specific target domain.

        Args:
            request (Request): Django REST Framework request object.
            slug (str): Project slug identifier.
            id (int): Target domain ID.

        Returns:
            Response: API Response containing target metrics, scan history, vulnerabilities, and domain details.
        """
        try:
            project = Project.objects.get(slug=slug)
            target = Domain.objects.get(id=id, project=project)
        except (Project.DoesNotExist, Domain.DoesNotExist):
            return Response({'error': 'Target not found'}, status=404)

        # Scans
        all_scans = ScanHistory.objects.filter(domain=target).order_by('-start_scan_date')
        scan_count = all_scans.count()
        this_week_scan_count = all_scans.filter(start_scan_date__gte=timezone.now() - timedelta(days=7)).count()
        recent_scans = all_scans[:5]

        # Subdomains
        subdomain_qs = Subdomain.objects.filter(target_domain=target)
        subdomain_count = subdomain_qs.values('name').distinct().count()
        alive_count = subdomain_qs.filter(http_status__exact=200).count()
        
        # Important subdomains
        important_subdomains = subdomain_qs.filter(http_status__exact=200).values('name', 'http_status', 'page_title')[:10]

        # Endpoints
        endpoint_qs = EndPoint.objects.filter(target_domain=target)
        endpoint_count = endpoint_qs.values('http_url').distinct().count()
        endpoint_alive_count = endpoint_qs.filter(http_status__exact=200).count()

        # Vulnerabilities
        vulnerabilities = Vulnerability.objects.filter(target_domain=target)
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
        ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomain_qs)
        asset_countries = ip_addresses.exclude(geo_iso=None).values(name=F('geo_iso__name'), iso=F('geo_iso__iso')).annotate(count=Count('geo_iso')).order_by('-count')
        http_status_breakdown = subdomain_qs.exclude(http_status=0).values('http_status').annotate(count=Count('http_status'))
        
        discovered_ports = Port.objects.filter(ports__in=ip_addresses).values('number', 'service_name', 'is_uncommon').annotate(count=Count('number')).order_by('-count')[:20]
        discovered_technologies = Technology.objects.filter(technologies__in=subdomain_qs).values('name').annotate(count=Count('name')).order_by('-count')[:20]

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

        # Related domains: include both automatically discovered related domains and manually specified secondary domains
        related_domains = []
        related_tlds = []
        if hasattr(target, 'domain_info') and target.domain_info:
            related_domains = list(target.domain_info.related_domains.all().values_list('name', flat=True)[:20])
            related_tlds = list(target.domain_info.related_tlds.all().values_list('name', flat=True)[:20])

        if target.secondary_domains:
            # Split manual secondary domains and clean empty values
            manual_sec_domains = [d.strip() for d in target.secondary_domains.split('\n') if d.strip()]
            for sec_d in manual_sec_domains:
                if sec_d not in related_domains:
                    related_domains.append(sec_d)

        # Parse manual In-Scope IPs and CIDRs
        in_scope_ips_list = []
        if target.in_scope_ips:
            in_scope_ips_list = [ip.strip() for ip in target.in_scope_ips.split('\n') if ip.strip()]

        # Monitoring
        monitoring_discoveries = MonitoringDiscovery.objects.filter(domain=target).order_by('-discovered_at')[:10]
        
        # Subscans
        subscans = SubScan.objects.filter(scan_history__domain=target).order_by('-start_scan_date')[:10]
        
        # Calculate scan history diffs for timeline
        recent_scans_data = []
        for i, scan in enumerate(recent_scans):
            scan_data = TacticalScanHistorySerializer(scan).data
            scan_data['subdomain_count'] = scan.get_subdomain_count()
            scan_data['engine_name'] = scan.scan_type.engine_name if scan.scan_type else "Default"
            if i + 1 < len(recent_scans):
                prev_scan = recent_scans[i+1]
                prev_count = prev_scan.get_subdomain_count()
                scan_data['subdomain_diff'] = scan_data['subdomain_count'] - prev_count
            else:
                scan_data['subdomain_diff'] = 0
            recent_scans_data.append(scan_data)

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
            'exposed_count': 0,
            'email_count': Email.objects.filter(emails__in=all_scans).distinct().count(),
            'employees_count': Employee.objects.filter(employees__in=all_scans).distinct().count(),
            'monitoring_discoveries_list': MonitoringDiscoverySerializer(monitoring_discoveries, many=True).data,
            'subscans': SubScanSerializer(subscans, many=True).data,
            'recent_scans': recent_scans_data,
            'important_subdomains': list(important_subdomains),
            'discovered_ports': list(discovered_ports),
            'discovered_technologies': list(discovered_technologies),
            'project_info': {'name': project.name, 'slug': project.slug},
            'target_info': {
                'name': target.name,
                'id': target.id,
                'in_scope_ips': in_scope_ips_list,
                'secondary_domains': manual_sec_domains if target.secondary_domains else [],
                'manual_subdomains': target.get_manual_subdomains(),
            },
            'domain_info': domain_info_data,
            'related_domains': related_domains,
            'related_tlds': related_tlds,
            'scan_count': scan_count,
            'this_week_scan_count': this_week_scan_count,
            'vulnerability_highlights': list(vulnerabilities.order_by('-severity', '-discovered_date')[:10].values('name', 'severity', 'http_url', 'discovered_date')),
            'subdomains': list(subdomain_qs.order_by('name')[:100].values('name', 'http_status', 'page_title')),
            'endpoints': list(endpoint_qs.order_by('http_url')[:100].values('http_url', 'http_status', 'content_type')),
            'vulnerabilities': list(vulnerabilities.order_by('-severity')[:100].values('name', 'severity', 'description')),
            'monitoring_discoveries': list(monitoring_discoveries.values('id', 'discovery_type', 'content')),
        }

        serializer = TargetSummarySerializer(data)
        return Response(serializer.data)
