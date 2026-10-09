import json
import logging
from datetime import timedelta
from django.db.models import Count, Q
from django.db.models.functions import TruncDay
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

logger = logging.getLogger(__name__)

from dashboard.models import Project, SearchHistory
from targetApp.models import Domain
from startScan.models import (
    Subdomain, EndPoint, ScanHistory, Vulnerability, 
    ScanActivity, SecretLeak, CveId, CweId, 
    VulnerabilityTags, IpAddress, Port, Technology, 
    MonitoringDiscovery, CountryISO
)


from api.dashboard_serializers import DashboardDataSerializer
from api.serializers import VulnerabilitySerializer, ScanHistorySerializer, ScanActivitySerializer

from django.conf import settings
from reNgine.definitions import INTERNAL_ERROR_MESSAGE

class DashboardAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, slug):
        try:
            project = Project.objects.get(slug=slug)
        except Project.DoesNotExist:
            return Response({'error': 'Project not found'}, status=404)

        # Basic Queries
        domains = Domain.objects.filter(project=project)
        subdomains = Subdomain.objects.filter(scan_history__domain__project=project)
        endpoints = EndPoint.objects.filter(scan_history__domain__project=project)
        scan_histories = ScanHistory.objects.filter(domain__project=project)
        vulnerabilities = Vulnerability.objects.filter(scan_history__domain__project=project)
        scan_activities = ScanActivity.objects.filter(scan_of__in=scan_histories)
        secret_leaks = SecretLeak.objects.filter(scan_history__domain__project=project)

        # KPI Calculations
        info_count = vulnerabilities.filter(severity=0).count()
        low_count = vulnerabilities.filter(severity=1).count()
        medium_count = vulnerabilities.filter(severity=2).count()
        high_count = vulnerabilities.filter(severity=3).count()
        critical_count = vulnerabilities.filter(severity=4).count()
        unknown_count = vulnerabilities.filter(severity=-1).count()
        
        kpis = {
            'domain_count': domains.count(),
            'subdomain_count': subdomains.count(),
            'endpoint_count': endpoints.count(),
            'vulnerability_count': vulnerabilities.count(),
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'info_count': info_count,
            'unknown_count': unknown_count,
            'secret_leak_count': secret_leaks.count(),
            'alive_count': subdomains.exclude(http_status__exact=0).count(),
            'endpoint_alive_count': endpoints.filter(http_status__exact=200).count(),
            'total_vul_count': vulnerabilities.count(),
        }

        # Trend Calculations (Last 7 Days)
        last_week = timezone.now() - timedelta(days=7)
        last_7_dates = [(timezone.now() - timedelta(days=i)).date() for i in range(0, 7)]
        
        trends = {
            'targets_in_last_week': self._get_trend_data(domains, 'insert_date', last_week, last_7_dates),
            'subdomains_in_last_week': self._get_trend_data(subdomains, 'discovered_date', last_week, last_7_dates),
            'endpoints_in_last_week': self._get_trend_data(endpoints, 'discovered_date', last_week, last_7_dates),
            'vulns_in_last_week': self._get_trend_data(vulnerabilities, 'discovered_date', last_week, last_7_dates),
            'leaks_in_last_week': self._get_trend_data(secret_leaks, 'discovered_date', last_week, last_7_dates),
            'last_7_dates': last_7_dates[::-1]
        }

        # Distributions
        ip_addresses = IpAddress.objects.filter(ip_addresses__in=subdomains)


        
        data = {
            'project_info': {
                'name': project.name,
                'slug': project.slug
            },
            'rengine_version': getattr(settings, 'RENGINE_CURRENT_VERSION', '3.0.0'),
            'kpis': kpis,

            'trends': trends,
            'most_used_port': Port.objects.filter(ports__in=ip_addresses).annotate(count=Count('ports')).order_by('-count')[:7].values('number', 'service_name', 'count'),
            'most_used_ip': ip_addresses.annotate(count=Count('ip_addresses')).order_by('-count').exclude(address__isnull=True)[:7].values('address', 'count'),
            'most_used_tech': Technology.objects.filter(technologies__in=subdomains).annotate(count=Count('technologies')).order_by('-count')[:7].values('name', 'count'),
            # Filter out empty or null CVEs to prevent displaying blank items
            'most_common_cve': CveId.objects.filter(cve_ids__in=vulnerabilities).exclude(name='').exclude(name__isnull=True).annotate(count=Count('cve_ids')).order_by('-count')[:7].values('name', 'count'),
            # Filter out empty or null CWEs to prevent displaying blank items and frontend errors on click
            'most_common_cwe': CweId.objects.filter(cwe_ids__in=vulnerabilities).exclude(name='').exclude(name__isnull=True).annotate(count=Count('cwe_ids')).order_by('-count')[:7].values('name', 'count'),
            'most_common_tags': VulnerabilityTags.objects.filter(vuln_tags__in=vulnerabilities).annotate(count=Count('vuln_tags')).order_by('-count')[:7].values('name', 'count'),
            'asset_countries': CountryISO.objects.filter(ipaddress__in=ip_addresses).annotate(count=Count('ipaddress')).order_by('-count').values('name', 'iso', 'count'),
            'most_vulnerable_targets': domains.annotate(
                vuln_count=Count('scanhistory__vulnerability'),
                critical_count=Count('scanhistory__vulnerability', filter=Q(scanhistory__vulnerability__severity=4)),
                high_count=Count('scanhistory__vulnerability', filter=Q(scanhistory__vulnerability__severity=3)),
                medium_count=Count('scanhistory__vulnerability', filter=Q(scanhistory__vulnerability__severity=2)),
                low_count=Count('scanhistory__vulnerability', filter=Q(scanhistory__vulnerability__severity=1)),
                info_count=Count('scanhistory__vulnerability', filter=Q(scanhistory__vulnerability__severity=0)),
                unknown_count=Count('scanhistory__vulnerability', filter=Q(scanhistory__vulnerability__severity=-1)),
            ).order_by('-vuln_count')[:7].values('id', 'name', 'vuln_count', 'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count', 'unknown_count'),
            'most_common_vulnerabilities': vulnerabilities.values('name', 'severity').annotate(count=Count('id')).order_by('-count')[:7],
            'activity_feed': ScanActivitySerializer(ScanActivity.objects.filter(scan_of__domain__project=project).order_by('-time')[:10], many=True).data,
            'vulnerability_feed': VulnerabilitySerializer(vulnerabilities.order_by('-discovered_date')[:10], many=True).data,
        }

        serializer = DashboardDataSerializer(data)
        return Response(serializer.data)

    def _get_trend_data(self, queryset, date_field, start_date, dates):
        trend_raw = queryset.filter(**{f"{date_field}__gte": start_date}).annotate(
            date=TruncDay(date_field)).values("date").annotate(count=Count('id')).order_by("-date")

        trend_map = {item['date'].date() if hasattr(item['date'], 'date') else item['date']: item['count'] for item in trend_raw}
        return [trend_map.get(date, 0) for date in dates][::-1]


class CWEInfoAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        cwe_name = request.query_params.get('name', '').strip()
        if not cwe_name:
            return Response({'error': 'Missing required parameter: name'}, status=400)

        try:
            from reNgine.llm import LLMBaseGenerator
            from reNgine.definitions import CWE_INFO_SYSTEM_PROMPT

            generator = LLMBaseGenerator(logger)
            raw = generator._call_llm(CWE_INFO_SYSTEM_PROMPT, f"Provide security information for: {cwe_name}")

            if raw.startswith('Error:'):
                return Response({'error': raw}, status=502)

            # Strip markdown code fences if present
            cleaned = raw.strip()
            if cleaned.startswith('```'):
                cleaned = cleaned.split('\n', 1)[-1]
                if cleaned.endswith('```'):
                    cleaned = cleaned.rsplit('```', 1)[0]
            cleaned = cleaned.strip()

            info = json.loads(cleaned)
            return Response({'status': True, 'cwe': cwe_name, **info})

        except json.JSONDecodeError:
            return Response({'status': False, 'error': 'LLM returned non-JSON response', 'raw': raw}, status=502)
        except Exception:
            logger.exception("CWEInfoAPIView error")
            return Response({'status': False, 'error': INTERNAL_ERROR_MESSAGE}, status=500)
