from rest_framework import serializers
from api.serializers import MonitoringDiscoverySerializer
from startScan.models import ScanHistory
from django.contrib.humanize.templatetags.humanize import naturaltime
import datetime
from django.utils import timezone

class TacticalScanHistorySerializer(serializers.ModelSerializer):
    completed_ago = serializers.SerializerMethodField('get_completed_ago')
    highest_severity = serializers.SerializerMethodField('get_highest_severity')

    class Meta:
        model = ScanHistory
        fields = [
            'id',
            'start_scan_date',
            'stop_scan_date',
            'scan_status',
            'highest_severity',
            'completed_ago'
        ]

    def get_highest_severity(self, scan_history):
        from startScan.models import Vulnerability
        max_vuln = Vulnerability.objects.filter(scan_history=scan_history).order_by('-severity').first()
        if max_vuln:
            severity_map = {
                4: 'critical',
                3: 'high',
                2: 'medium',
                1: 'low',
                0: 'info',
                -1: 'unknown'
            }
            return severity_map.get(max_vuln.severity, 'unknown')
        return 'none'

    def get_completed_ago(self, scan_history):
        if scan_history.stop_scan_date:
            return naturaltime(scan_history.stop_scan_date)
        return ""

class TargetSummarySerializer(serializers.Serializer):
    subdomain_count = serializers.IntegerField()
    alive_count = serializers.IntegerField()
    endpoint_count = serializers.IntegerField()
    endpoint_alive_count = serializers.IntegerField()
    
    # Vulnerabilities
    critical_count = serializers.IntegerField()
    high_count = serializers.IntegerField()
    medium_count = serializers.IntegerField()
    low_count = serializers.IntegerField()
    info_count = serializers.IntegerField()
    unknown_count = serializers.IntegerField()
    total_vul_ignore_info_count = serializers.IntegerField()
    vulnerability_count = serializers.IntegerField()
    
    # Aggregations
    most_common_vulnerability = serializers.ListField()
    most_common_tags = serializers.ListField()
    most_common_cve = serializers.ListField()
    most_common_cwe = serializers.ListField()
    
    # Assets
    asset_countries = serializers.ListField()
    http_status_breakdown = serializers.ListField()
    
    # Others
    exposed_count = serializers.IntegerField()
    email_count = serializers.IntegerField()
    employees_count = serializers.IntegerField()
    secret_leaks_count = serializers.IntegerField(required=False)
    exploitable_count = serializers.IntegerField(required=False)
    buckets_count = serializers.IntegerField(required=False)
    matched_gf_count = serializers.ListField(required=False)
    
    # Discovery
    monitoring_discoveries = serializers.ListField()
    recent_scans = serializers.ListField()
    subscans = serializers.ListField()
    
    # New Data Points
    important_subdomains = serializers.ListField()
    discovered_ports = serializers.ListField()
    discovered_technologies = serializers.ListField()
    
    # Information
    project_info = serializers.DictField()
    target_info = serializers.DictField()
    domain_info = serializers.DictField(allow_null=True)
    
    # Related
    related_domains = serializers.ListField()
    related_tlds = serializers.ListField()
    
    scan_count = serializers.IntegerField()
    this_week_scan_count = serializers.IntegerField()
    vulnerability_highlights = serializers.ListField(required=False)
    
    # Tab Data
    subdomains = serializers.ListField(required=False)
    endpoints = serializers.ListField(required=False)
    vulnerabilities = serializers.ListField(required=False)
    monitoring_discoveries_list = serializers.ListField(required=False)
    secret_leaks = serializers.ListField(required=False)
    
    # OSINT Data
    osint_staging = serializers.ListField(required=False)
    emails = serializers.ListField(required=False)
    employees = serializers.ListField(required=False)
    dorks = serializers.ListField(required=False)
    documents = serializers.ListField(required=False)
    buckets = serializers.ListField(required=False)
    
    # Scan specific
    scan_info = serializers.DictField(required=False)
    timeline = serializers.ListField(required=False)
