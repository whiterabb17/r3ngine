import os
import re
import markdown
from datetime import datetime
from django.core.files.base import ContentFile
from django.template.loader import get_template
from collections import defaultdict
from django.db.models import Count, Case, When, IntegerField
from weasyprint import HTML, CSS
from django.utils import timezone
from reNgine.utilities import secure_url_fetcher

from reNgine.definitions import *
from reNgine.llm import LLMReportGenerator
from reNgine.charts import (
    generate_subdomain_chart_by_http_status,
    generate_vulnerability_chart_by_severity,
    generate_attack_surface_map
)
from reNgine.utils.graph import Neo4jManager
from reNgine.utils.logger import get_module_logger, format_exception_for_log
from reNgine.common_func import get_interesting_subdomains, clean_semgrep_check_id, categorize_secret_type
from reNgine.stress.report_builder import StressReportBuilder
from startScan.models import ScanHistory, Subdomain, Vulnerability, IpAddress, ScanReport, StressTestResult, Parameter, EmailBreach, SecretLeak, EndPoint, DirectoryScan, DirectoryFile, S3Bucket, Waf, Technology, IdentityInfraDiscovery, APIIntelligenceProfile, Exposure, MetaFinderDocument, Dork, CertificateIntelligence, Employee
from scanEngine.models import VulnerabilityReportSetting

logger = get_module_logger(__name__)


def build_vuln_context(scan, ignore_info=False):
    """
    Splits scan vulnerabilities into:
    - all_vulnerabilities: non-vulners findings (for existing template {% regroup %} tag)
    - grouped_vulners_findings: list of product groups from vulners NSE
    - unique_vulnerabilities: summary for report index table (both sources combined)
    - all_vulnerabilities_count: total count including vulners
    """
    base_qs = Vulnerability.objects.filter(scan_history=scan)
    if ignore_info:
        base_qs = base_qs.exclude(severity=0)

    # Must order by (name, -severity) so that {% regroup by name %} in the
    # template receives consecutive runs of the same name — without 'name' in
    # the ORDER BY, the same vuln name can appear non-contiguously at the same
    # severity level (DB ordering), causing {% regroup %} to emit duplicate
    # groups and WeasyPrint to flag duplicate anchor IDs.
    non_vulners = base_qs.exclude(source='VULNERS').order_by('-severity', 'name')
    vulners = base_qs.filter(source='VULNERS').order_by('group_key', '-cvss_score')

    bucket = defaultdict(list)
    for v in vulners:
        bucket[v.group_key or v.name].append(v)

    grouped_vulners_findings = sorted(
        [
            {
                'group_key': gk,
                'items': items,
                'count': len(items),
                'max_severity': max(i.severity for i in items),
                'max_cvss': max((i.cvss_score or 0) for i in items),
            }
            for gk, items in bucket.items()
        ],
        key=lambda x: (-x['max_severity'], -x['max_cvss'])
    )

    non_vulners_unique = (
        non_vulners
        .values('name', 'severity')
        .annotate(count=Count('name'))
        .order_by('-severity', '-count')
    )
    vulners_unique = [
        {'name': g['group_key'], 'severity': g['max_severity'], 'count': g['count']}
        for g in grouped_vulners_findings
    ]

    return {
        'all_vulnerabilities': non_vulners,
        'all_vulnerabilities_count': non_vulners.count() + vulners.count(),
        'grouped_vulners_findings': grouped_vulners_findings,
        'unique_vulnerabilities': list(non_vulners_unique) + vulners_unique,
    }


def _normalize_llm_markdown(text: str) -> str:
    """
    LLMs sometimes output bulleted items inline on a single line:
        **Key Risks include:** - Item 1. - Item 2. - Item 3.
    The Markdown parser only recognises list markers at the start of a line,
    so this collapses to a plain paragraph.  This function detects the pattern
    "<label ending with :> - item - item …" on a single line and expands it
    into proper Markdown list lines so the parser can render <ul><li> elements.
    """
    def _expand_line(line):
        # Allow optional Markdown bold/italic markers (** or *) after the colon
        # e.g. "**Key Risks include:** - Item 1 - Item 2"
        m = re.match(r'^(.+?:[\*_]*)\s+-\s+(.+)$', line)
        if not m:
            return [line]
        prefix = m.group(1)
        items = [i.strip() for i in re.split(r'\s+-\s+', m.group(2)) if i.strip()]
        if len(items) < 2:
            return [line]
        return [prefix, ''] + ['- ' + item for item in items] + ['']

    result = []
    for line in text.split('\n'):
        result.extend(_expand_line(line))
    return '\n'.join(result)


def generate_report_task(report_id):
    logger.log_line("[REPORT]", "START", "beginning report generation for report_id=%s" % report_id)
    try:
        report_obj = ScanReport.objects.get(id=report_id)
        report_obj.status = 1  # Running
        report_obj.save()

        scan = report_obj.scan_history
        report_type = report_obj.report_type
        report_template = report_obj.report_template
        params = report_obj.params

        logger.log_line("[REPORT]", "CONFIG", "scan=%s domain=%s type=%s template=%s" % (
            scan.id, scan.domain.name, report_type, report_template
        ))

        is_ignore_info_vuln = params.get('ignore_info_vuln') in [True, 'True', 'true']
        include_attack_surface_map = params.get('include_attack_surface_map') in [True, 'True', 'true']
        include_attack_paths = params.get('include_attack_paths') in [True, 'True', 'true']

        include_found_parameters = params.get('include_found_parameters', True)
        if isinstance(include_found_parameters, str):
            include_found_parameters = include_found_parameters.lower() == 'true'

        include_endpoints = params.get('include_endpoints') in [True, 'True', 'true']
        include_directories = params.get('include_directories') in [True, 'True', 'true']
        include_s3_buckets = params.get('include_s3_buckets') in [True, 'True', 'true']
        include_waf = params.get('include_waf') in [True, 'True', 'true']
        include_technologies = params.get('include_technologies') in [True, 'True', 'true']
        include_api_intelligence = params.get('include_api_intelligence') in [True, 'True', 'true']
        include_identity = params.get('include_identity') in [True, 'True', 'true']
        include_exposures = params.get('include_exposures') in [True, 'True', 'true']
        include_dorks_metadata = params.get('include_dorks_metadata') in [True, 'True', 'true']
        include_certificates = params.get('include_certificates') in [True, 'True', 'true']
        include_employees = params.get('include_employees') in [True, 'True', 'true']

        comments = params.get('comments', '')

        show_recon = True
        show_vuln = True
        report_name = 'Full Scan Report'

        if report_type == 'vulnerability':
            show_recon = False
            report_name = 'Vulnerability Report'
        elif report_type == 'stress_test':
            show_recon = False
            show_vuln = False
            report_name = 'Stress Test Report'

        # Fetch stress results if needed
        stress_results = StressTestResult.objects.none()
        if report_type == 'stress_test' or report_template in ['stress_cyber_pro', 'stress_modern']:
            logger.log_line("[REPORT]", "FETCH", "loading stress test results")
            stress_results = StressTestResult.objects.filter(scan_history=scan).order_by('-timestamp')
            logger.log_line("[REPORT]", "FETCH", "stress results: %d" % stress_results.count())

        logger.log_line("[REPORT]", "FETCH", "building vulnerability context ignore_info=%s" % is_ignore_info_vuln)
        vuln_ctx = build_vuln_context(scan, ignore_info=is_ignore_info_vuln)
        logger.log_line("[REPORT]", "FETCH", "vulnerabilities: total=%d non_vulners=%d" % (
            vuln_ctx['all_vulnerabilities_count'],
            vuln_ctx['all_vulnerabilities'].count(),
        ))

        # All-source queryset used for description template substitution and LLM context
        vulns = (
            Vulnerability.objects
            .filter(scan_history=scan)
            .order_by('-severity')
        ) if not is_ignore_info_vuln else (
            Vulnerability.objects
            .filter(scan_history=scan)
            .exclude(severity=0)
            .order_by('-severity')
        )
        unique_vulns = vuln_ctx['unique_vulnerabilities']

        logger.log_line("[REPORT]", "FETCH", "loading subdomains")
        subdomains = (
            Subdomain.objects
            .filter(scan_history=scan)
            .order_by('-content_length')
        )
        subdomain_alive_count = (
            Subdomain.objects
            .filter(scan_history=scan)
            .values('name')
            .distinct()
            .filter(http_status__exact=200)
            .count()
        )

        interesting_subdomains = get_interesting_subdomains(scan_history=scan.id)
        interesting_subdomains = interesting_subdomains.annotate(
            sort_order=Case(
                When(http_status__gte=200, http_status__lt=300, then=1),
                When(http_status__gte=300, http_status__lt=400, then=2),
                When(http_status__gte=400, http_status__lt=500, then=3),
                default=4,
                output_field=IntegerField(),
            )
        ).order_by('sort_order', 'http_status')

        subdomains = subdomains.annotate(
            sort_order=Case(
                When(http_status__gte=200, http_status__lt=300, then=1),
                When(http_status__gte=300, http_status__lt=400, then=2),
                When(http_status__gte=400, http_status__lt=500, then=3),
                default=4,
                output_field=IntegerField(),
            )
        ).order_by('sort_order', 'http_status')

        logger.log_line("[REPORT]", "FETCH", "subdomains: total=%d alive=%d interesting=%d" % (
            subdomains.count(), subdomain_alive_count, interesting_subdomains.count()
        ))

        logger.log_line("[REPORT]", "FETCH", "loading IP addresses")
        ip_addresses = (
            IpAddress.objects
            .filter(ip_addresses__in=subdomains)
            .distinct()
        )
        logger.log_line("[REPORT]", "FETCH", "IP addresses: %d" % ip_addresses.count())

        # CPDE parameters
        parameters = Parameter.objects.none()
        if report_type != 'stress_test' and include_found_parameters:
            logger.log_line("[REPORT]", "FETCH", "loading parameters")
            parameters = (
                Parameter.objects
                .filter(scan_history=scan)
                .select_related('endpoint')
                .order_by('-confidence', 'name')
            )
            logger.log_line("[REPORT]", "FETCH", "parameters: %d" % parameters.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "parameters (include_found_parameters=%s)" % include_found_parameters)

        attack_surface_map_image = None
        if report_template == 'enterprise' and include_attack_surface_map:
            logger.log_line("[REPORT]", "FETCH", "generating attack surface map from Neo4j")
            try:
                neo4j_manager = Neo4jManager()
                graph_data = neo4j_manager.get_cytoscape_json(scan.id)
                if graph_data and graph_data.get('nodes'):
                    attack_surface_map_image = generate_attack_surface_map(graph_data)
                    logger.log_line("[REPORT]", "FETCH", "attack surface map generated (%d nodes)" % len(graph_data.get('nodes', [])))
                else:
                    logger.log_line("[REPORT]", "FETCH", "attack surface map: no graph data available")
                neo4j_manager.close()
            except Exception as e:
                logger.log_line("[REPORT]", "ERROR", "attack surface map failed: %s" % format_exception_for_log(e), level="error")
        else:
            logger.log_line("[REPORT]", "SKIP", "attack surface map (template=%s include=%s)" % (report_template, include_attack_surface_map))

        attack_paths = []
        if report_template in ['enterprise', 'cyber_pro'] and include_attack_paths:
            logger.log_line("[REPORT]", "FETCH", "loading attack paths from ImpactAssessment")
            from startScan.models import ImpactAssessment
            assessments = (
                ImpactAssessment.objects.filter(scan_history_id=scan.id)
                .exclude(potential_attack_chain__isnull=True)
                .exclude(potential_attack_chain={})
                .select_related('vulnerability')
                .order_by('-remediation_priority')
            )
            for a in assessments:
                chain = a.potential_attack_chain or {}
                if not chain.get('apme_path_id'):
                    continue
                attack_paths.append({
                    'path_id': chain.get('apme_path_id'),
                    'risk': chain.get('risk', 'unknown'),
                    'score': chain.get('score', 0.0),
                    'steps': chain.get('steps', []),
                    'explanation': chain.get('explanation', ''),
                    'potential_impact': a.potential_impact,
                    'remediation_priority': a.remediation_priority,
                    'vuln_remediation': (a.vulnerability.remediation or '') if a.vulnerability_id and a.vulnerability else '',
                    'remediation': '',
                })
            logger.log_line("[REPORT]", "FETCH", "attack paths: %d" % len(attack_paths))
        else:
            logger.log_line("[REPORT]", "SKIP", "attack paths (template=%s include=%s)" % (report_template, include_attack_paths))

        logger.log_line("[REPORT]", "FETCH", "loading email breaches")
        email_breaches = EmailBreach.objects.filter(scan_history=scan).order_by('email_address', '-discovered_date')
        logger.log_line("[REPORT]", "FETCH", "email breaches: %d" % email_breaches.count())

        include_secret_findings = params.get('include_secret_findings', True)
        if isinstance(include_secret_findings, str):
            include_secret_findings = include_secret_findings.lower() == 'true'

        secret_leaks = SecretLeak.objects.none()
        secret_findings_by_type = {}
        if include_secret_findings:
            logger.log_line("[REPORT]", "FETCH", "loading secret leaks")
            secret_leaks = SecretLeak.objects.filter(scan_history=scan).order_by('secret_type', 'source_url')
            bucket = defaultdict(list)
            for leak in secret_leaks:
                bucket[leak.secret_type].append(leak)
            secret_findings_by_type = {
                k: {
                    'display_name': clean_semgrep_check_id(k),
                    'category': categorize_secret_type(clean_semgrep_check_id(k)),
                    'leaks': v,
                }
                for k, v in sorted(bucket.items())
            }
            logger.log_line("[REPORT]", "FETCH", "secret leaks: %d across %d types" % (secret_leaks.count(), len(secret_findings_by_type)))
        else:
            logger.log_line("[REPORT]", "SKIP", "secret leaks (disabled by user)")

        endpoints_data = EndPoint.objects.none()
        if include_endpoints:
            logger.log_line("[REPORT]", "FETCH", "loading endpoints")
            endpoints_data = EndPoint.objects.filter(scan_history=scan).order_by('http_url')
            logger.log_line("[REPORT]", "FETCH", "endpoints: %d" % endpoints_data.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "endpoints")

        directories_data = DirectoryFile.objects.none()
        if include_directories:
            logger.log_line("[REPORT]", "FETCH", "loading directories")
            directories_data = DirectoryFile.objects.filter(directory_files__directories__in=subdomains).distinct().order_by('url')
            logger.log_line("[REPORT]", "FETCH", "directory files: %d" % directories_data.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "directories")

        s3_buckets_data = S3Bucket.objects.none()
        if include_s3_buckets:
            logger.log_line("[REPORT]", "FETCH", "loading S3 buckets")
            s3_buckets_data = scan.buckets.all().order_by('name')
            logger.log_line("[REPORT]", "FETCH", "S3 buckets: %d" % s3_buckets_data.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "S3 buckets")

        waf_data = Waf.objects.none()
        if include_waf:
            logger.log_line("[REPORT]", "FETCH", "loading WAF data")
            waf_data = Waf.objects.filter(waf__in=subdomains).distinct().order_by('manufacturer')
            logger.log_line("[REPORT]", "FETCH", "WAF entries: %d" % waf_data.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "WAF data")

        technologies_data = Technology.objects.none()
        if include_technologies:
            logger.log_line("[REPORT]", "FETCH", "loading technologies")
            technologies_data = Technology.objects.filter(technologies__in=subdomains).distinct().order_by('name')
            logger.log_line("[REPORT]", "FETCH", "technologies: %d" % technologies_data.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "technologies")

        api_intel = APIIntelligenceProfile.objects.none()
        if include_api_intelligence:
            logger.log_line("[REPORT]", "FETCH", "loading API intelligence profiles")
            api_intel = APIIntelligenceProfile.objects.filter(scan_history=scan)
            logger.log_line("[REPORT]", "FETCH", "API intel profiles: %d" % api_intel.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "API intelligence")

        identity_intel = IdentityInfraDiscovery.objects.none()
        if include_identity:
            logger.log_line("[REPORT]", "FETCH", "loading identity infrastructure discoveries")
            identity_intel = IdentityInfraDiscovery.objects.filter(scan_history=scan)
            logger.log_line("[REPORT]", "FETCH", "identity intel entries: %d" % identity_intel.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "identity intelligence")

        exposures_data = Exposure.objects.none()
        if include_exposures:
            logger.log_line("[REPORT]", "FETCH", "loading exposures")
            exposures_data = Exposure.objects.filter(scan_history=scan)
            logger.log_line("[REPORT]", "FETCH", "exposures: %d" % exposures_data.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "exposures")

        metadata_docs = MetaFinderDocument.objects.none()
        dorks_data = Dork.objects.none()
        if include_dorks_metadata:
            logger.log_line("[REPORT]", "FETCH", "loading dorks and metadata documents")
            metadata_docs = MetaFinderDocument.objects.filter(scan_history=scan)
            dorks_data = scan.dorks.all()
            logger.log_line("[REPORT]", "FETCH", "metadata docs: %d  dorks: %d" % (metadata_docs.count(), dorks_data.count()))
        else:
            logger.log_line("[REPORT]", "SKIP", "dorks and metadata")

        certificates_data = CertificateIntelligence.objects.none()
        if include_certificates:
            logger.log_line("[REPORT]", "FETCH", "loading certificate intelligence")
            certificates_data = CertificateIntelligence.objects.filter(scan_history=scan)
            logger.log_line("[REPORT]", "FETCH", "certificates: %d" % certificates_data.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "certificates")

        employees_data = Employee.objects.none()
        if include_employees:
            logger.log_line("[REPORT]", "FETCH", "loading employees")
            employees_data = scan.employees.all()
            logger.log_line("[REPORT]", "FETCH", "employees: %d" % employees_data.count())
        else:
            logger.log_line("[REPORT]", "SKIP", "employees")

        data = {
            'scan_object': scan,
            **vuln_ctx,
            'subdomain_alive_count': subdomain_alive_count,
            'interesting_subdomains': interesting_subdomains,
            'subdomains': subdomains,
            'ip_addresses': ip_addresses,
            'show_recon': show_recon,
            'show_vuln': show_vuln,
            'report_name': report_name,
            'is_ignore_info_vuln': is_ignore_info_vuln,
            'attack_surface_map_image': attack_surface_map_image,
            'attack_paths': attack_paths,
            'stress_results': stress_results,
            'parameters': parameters,
            'parameters_count': parameters.count(),
            'email_breaches': email_breaches,
            'email_breaches_count': email_breaches.count(),
            'secret_leaks': secret_leaks,
            'secret_leaks_count': secret_leaks.count() if include_secret_findings else 0,
            'secret_findings_by_type': secret_findings_by_type,
            'endpoints_data': endpoints_data,
            'endpoints_count': endpoints_data.count() if include_endpoints else 0,
            'directories_data': directories_data,
            'directories_count': directories_data.count() if include_directories else 0,
            's3_buckets_data': s3_buckets_data,
            's3_buckets_count': s3_buckets_data.count() if include_s3_buckets else 0,
            'waf_data': waf_data,
            'waf_count': waf_data.count() if include_waf else 0,
            'technologies_data': technologies_data,
            'technologies_count': technologies_data.count() if include_technologies else 0,
            'api_intel': api_intel,
            'api_intel_count': api_intel.count() if include_api_intelligence else 0,
            'identity_intel': identity_intel,
            'identity_intel_count': identity_intel.count() if include_identity else 0,
            'exposures_data': exposures_data,
            'exposures_count': exposures_data.count() if include_exposures else 0,
            'metadata_docs': metadata_docs,
            'metadata_docs_count': metadata_docs.count() if include_dorks_metadata else 0,
            'dorks_data': dorks_data,
            'dorks_count': dorks_data.count() if include_dorks_metadata else 0,
            'certificates_data': certificates_data,
            'certificates_count': certificates_data.count() if include_certificates else 0,
            'employees_data': employees_data,
            'employees_count': employees_data.count() if include_employees else 0,
        }

        # Stress Test Aggregation for context
        if stress_results.exists():
            logger.log_line("[REPORT]", "AGGREGATE", "computing stress test summary")
            total_reqs = sum(r.total_requests for r in stress_results)
            total_success = sum(r.successful_requests for r in stress_results)
            total_failed = sum(r.failed_requests for r in stress_results)
            avg_p95 = sum(r.p95_latency_ms for r in stress_results) / stress_results.count()
            avg_p99 = sum(r.p99_latency_ms for r in stress_results) / stress_results.count()
            data['stress_total_requests'] = total_reqs
            data['stress_total_success'] = total_success
            data['stress_total_failed'] = total_failed
            data['stress_avg_p95'] = avg_p95
            data['stress_avg_p99'] = avg_p99
            data['stress_max_rps'] = max(r.max_requests_per_second for r in stress_results)
            logger.log_line("[REPORT]", "AGGREGATE", "stress summary: reqs=%d success=%d failed=%d p95=%.1fms" % (
                total_reqs, total_success, total_failed, avg_p95
            ))

        # Get report related config
        logger.log_line("[REPORT]", "FETCH", "loading report settings")
        primary_color = '#00f3ff'
        secondary_color = '#0d0c14'

        vuln_report_query = VulnerabilityReportSetting.objects.all()
        if vuln_report_query.exists():
            report_setting = vuln_report_query[0]
            data['company_name'] = report_setting.company_name
            data['company_address'] = report_setting.company_address
            data['company_email'] = report_setting.company_email
            data['company_website'] = report_setting.company_website
            data['show_rengine_banner'] = report_setting.show_rengine_banner
            data['show_footer'] = report_setting.show_footer
            data['footer_text'] = report_setting.footer_text
            data['show_executive_summary'] = report_setting.show_executive_summary
            logger.log_line("[REPORT]", "FETCH", "report settings loaded (company=%s llm=%s)" % (
                report_setting.company_name, report_setting.enable_llm_report_generation
            ))

            # Replace executive_summary_description with template syntax
            description = report_setting.executive_summary_description or ''
            description = description.replace('{scan_date}', scan.start_scan_date.strftime('%d %B, %Y'))
            description = description.replace('{company_name}', str(report_setting.company_name or ''))
            description = description.replace('{target_name}', str(scan.domain.name or ''))
            description = description.replace('{subdomain_count}', str(subdomains.count()))
            description = description.replace('{vulnerability_count}', str(vulns.count()))
            description = description.replace('{critical_count}', str(vulns.filter(severity=4).count()))
            description = description.replace('{high_count}', str(vulns.filter(severity=3).count()))
            description = description.replace('{medium_count}', str(vulns.filter(severity=2).count()))
            description = description.replace('{low_count}', str(vulns.filter(severity=1).count()))
            description = description.replace('{info_count}', str(vulns.filter(severity=0).count()))
            description = description.replace('{unknown_count}', str(vulns.filter(severity=-1).count()))
            description = description.replace('{comments}', str(comments or ''))

            if report_type == 'stress_test' and stress_results.exists():
                description += f"\n\n**Stress Test Performance Summary:**\n"
                description += f"- Total Requests: {data.get('stress_total_requests', 0)}\n"
                description += f"- Success Rate: {(data.get('stress_total_success', 0)/data.get('stress_total_requests', 1))*100:.1f}%\n"
                description += f"- Peak RPS: {data.get('stress_max_rps', 0):.2f}\n"
                description += f"- Avg P95 Latency: {data.get('stress_avg_p95', 0):.2f}ms\n"

            if scan.domain.description:
                description = description.replace('{target_description}', str(scan.domain.description or ''))

            data['executive_summary_description'] = markdown.markdown(description, extensions=['extra', 'nl2br', 'sane_lists'])

            # LLM Generated Sections
            if report_setting.enable_llm_report_generation:
                logger.log_line("[REPORT]", "LLM", "starting LLM report section generation")
                llm_gen = LLMReportGenerator(logger=logger)

                llm_context = f"Target: {scan.domain.name}\n"
                if scan.domain.description:
                    llm_context += f"Target Description: {scan.domain.description}\n"
                llm_context += f"Scan Date: {scan.start_scan_date.strftime('%d %B, %Y')}\n"

                if report_type == 'stress_test':
                    llm_context += "Stress Test Metrics:\n"
                    for res in stress_results:
                        llm_context += f"- Tool: {res.tool_used}, Concurrency: {res.concurrency_used}, Duration: {res.duration}\n"
                        llm_context += f"  Requests: {res.total_requests} (Success: {res.successful_requests}, Failed: {res.failed_requests})\n"
                        llm_context += f"  Latency: Avg {res.avg_latency_ms}ms, P95 {res.p95_latency_ms}ms, P99 {res.p99_latency_ms}ms\n"
                        llm_context += f"  Max RPS: {res.max_requests_per_second}\n"
                    if data.get('stress_total_failed', 0) > 0:
                        llm_context += f"Warning: {data['stress_total_failed']} requests failed during the test.\n"
                else:
                    llm_context += f"Subdomains discovered: {subdomains.count()}\n"
                    llm_context += f"Vulnerabilities identified: {vulns.count()}\n"
                    llm_context += f"- Critical: {vulns.filter(severity=4).count()}\n"
                    llm_context += f"- High: {vulns.filter(severity=3).count()}\n"
                    llm_context += f"- Medium: {vulns.filter(severity=2).count()}\n"
                    llm_context += f"- Low: {vulns.filter(severity=1).count()}\n"
                    llm_context += f"- Info: {vulns.filter(severity=0).count()}\n"

                    if vulns.exists():
                        llm_context += "Top Vulnerabilities:\n"
                        for v in unique_vulns[:10]:
                            llm_context += f"- {v['name']} ({v['count']})\n"

                logger.log_line("[REPORT]", "LLM", "generating overview section")
                data['llm_overview'] = markdown.markdown(
                    _normalize_llm_markdown(llm_gen.generate_overview(llm_context)),
                    extensions=['extra', 'nl2br', 'sane_lists'],
                )
                logger.log_line("[REPORT]", "LLM", "overview done (%d chars)" % len(data['llm_overview']))

                logger.log_line("[REPORT]", "LLM", "generating executive brief section")
                data['llm_executive_brief'] = markdown.markdown(
                    _normalize_llm_markdown(llm_gen.generate_executive_brief(llm_context)),
                    extensions=['extra', 'nl2br', 'sane_lists'],
                )
                logger.log_line("[REPORT]", "LLM", "executive brief done (%d chars)" % len(data['llm_executive_brief']))

                logger.log_line("[REPORT]", "LLM", "generating conclusion section")
                data['llm_conclusion'] = markdown.markdown(
                    _normalize_llm_markdown(llm_gen.generate_conclusion(llm_context)),
                    extensions=['extra', 'nl2br', 'sane_lists'],
                )
                logger.log_line("[REPORT]", "LLM", "conclusion done (%d chars)" % len(data['llm_conclusion']))

                if attack_paths:
                    logger.log_line("[REPORT]", "LLM", "generating attack path remediation (%d paths)" % len(attack_paths))
                    for path in attack_paths:
                        path_ctx = "Risk Level: %s (Score: %s)\n" % (path['risk'].upper(), path['score'])
                        path_ctx += "Potential Impact: %s\n" % (path['potential_impact'] or 'Not specified')
                        path_ctx += "Attack Steps:\n"
                        for i, step in enumerate(path['steps'], 1):
                            action = step.get('action', 'Unknown action')
                            edge = step.get('edge_type', '')
                            mitre = step.get('mitre_technique', '')
                            line = "  %d. %s" % (i, action)
                            if edge:
                                line += " (via %s)" % edge
                            if mitre:
                                line += " [MITRE %s]" % mitre
                            path_ctx += line + "\n"
                        try:
                            raw = llm_gen.generate_path_remediation(path['path_id'], path_ctx)
                            path['remediation'] = markdown.markdown(
                                _normalize_llm_markdown(raw or ''),
                                extensions=['extra', 'nl2br', 'sane_lists'],
                            )
                            logger.log_line("[REPORT]", "LLM", "remediation done for path %s (%d chars)" % (path['path_id'], len(path['remediation'])))
                        except Exception as e:
                            logger.log_line("[REPORT]", "ERROR", "remediation failed for path %s: %s" % (path['path_id'], format_exception_for_log(e)), level="error")

                data['enable_llm_report_generation'] = True
                logger.log_line("[REPORT]", "LLM", "all LLM sections complete")
            else:
                logger.log_line("[REPORT]", "SKIP", "LLM generation (disabled in settings)")

            primary_color = report_setting.primary_color
            secondary_color = report_setting.secondary_color
        else:
            logger.log_line("[REPORT]", "FETCH", "no report settings found, using defaults")

        data['primary_color'] = primary_color
        data['secondary_color'] = secondary_color

        # Charts
        logger.log_line("[REPORT]", "CHART", "generating subdomain HTTP status chart")
        from reNgine.charts import (
            generate_subdomain_chart_by_http_status,
            generate_vulnerability_chart_by_severity,
            generate_attack_surface_map,
            generate_stress_latency_chart,
            generate_stress_success_rate_chart,
            generate_stress_latency_distribution_chart,
            generate_stress_response_code_chart,
            generate_stress_error_breakdown_chart,
            generate_stress_endpoint_heatmap
        )

        data['subdomain_http_status_chart'] = generate_subdomain_chart_by_http_status(subdomains)
        logger.log_line("[REPORT]", "CHART", "generating vulnerability severity chart")
        data['vulns_severity_chart'] = generate_vulnerability_chart_by_severity(vulns) if vulns else ''
        logger.log_line("[REPORT]", "CHART", "base charts complete")

        # Enhanced stress test charts for detailed reports
        if stress_results.exists():
            logger.log_line("[REPORT]", "CHART", "generating stress test charts")
            data['stress_latency_chart'] = generate_stress_latency_chart(stress_results)
            data['stress_success_rate_chart'] = generate_stress_success_rate_chart(stress_results)

            stress_report_contexts = []
            for idx, stress_result in enumerate(stress_results, start=1):
                logger.log_line("[REPORT]", "CHART", "building stress result context %d/%d" % (idx, stress_results.count()))
                builder = StressReportBuilder(stress_result)
                report_context = builder.build()

                report_context['latency_distribution_chart'] = generate_stress_latency_distribution_chart(stress_result)
                report_context['response_code_chart'] = generate_stress_response_code_chart(stress_result.response_code_distribution)
                report_context['error_breakdown_chart'] = generate_stress_error_breakdown_chart(stress_result.error_breakdown)
                report_context['endpoint_heatmap_chart'] = generate_stress_endpoint_heatmap(
                    stress_result.endpoints_tested,
                    stress_result.response_code_distribution
                )
                stress_report_contexts.append(report_context)

            data['stress_report_contexts'] = stress_report_contexts
            logger.log_line("[REPORT]", "CHART", "stress charts complete")

        # Template selection
        if report_template == 'enterprise':
            template = get_template('report/enterprise.html')
        elif report_template == 'modern' or report_template == 'stress_modern':
            template = get_template('report/modern.html') if report_template == 'modern' else get_template('report/stress_modern.html')
        elif report_template == 'cyber_pro' or report_template == 'stress_cyber_pro':
            template = get_template('report/cyber_pro.html') if report_template == 'cyber_pro' else get_template('report/stress_cyber_pro.html')
        else:
            template = get_template('report/default.html')

        logger.log_line("[REPORT]", "RENDER", "rendering HTML template: %s" % report_template)
        html = template.render(data)
        logger.log_line("[REPORT]", "RENDER", "HTML rendered (%d bytes), starting WeasyPrint PDF generation" % len(html))

        pdf = HTML(string=html, url_fetcher=secure_url_fetcher).write_pdf()
        logger.log_line("[REPORT]", "RENDER", "PDF generated (%d bytes), saving file" % len(pdf))

        target_name = scan.domain.name
        date_str = datetime.now().strftime('%Y-%m-%d')
        filename = f"{target_name}_Stress_Report_{date_str}.pdf" if report_type == 'stress_test' else f"{target_name}_Report_{date_str}.pdf"

        report_obj.report_file.save(filename, ContentFile(pdf))
        report_obj.status = 2  # Success
        report_obj.completed_at = timezone.now()
        report_obj.save()

        logger.log_line("[REPORT]", "COMPLETE", "report saved as %s (report_id=%s)" % (filename, report_id))

    except Exception as e:
        logger.log_line("[REPORT]", "ERROR", format_exception_for_log(e), level="error", exc_info=True)
        try:
            report_obj = ScanReport.objects.get(id=report_id)
            report_obj.status = 0  # Failed
            report_obj.error_message = str(e)
            report_obj.save()
        except ScanReport.DoesNotExist:
            logger.log_line("[REPORT]", "ERROR", "ScanReport id=%s not found, cannot save failed status" % report_id, level="error")
    finally:
        from django.db import close_old_connections
        close_old_connections()
        logger.log_line("[REPORT]", "CLEANUP", "database connections closed for report_id=%s" % report_id)
