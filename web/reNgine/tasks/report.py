import os
import markdown
import logging
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
from reNgine.common_func import get_interesting_subdomains, clean_semgrep_check_id, categorize_secret_type
from reNgine.stress.report_builder import StressReportBuilder
from startScan.models import ScanHistory, Subdomain, Vulnerability, IpAddress, ScanReport, StressTestResult, Parameter, EmailBreach, SecretLeak
from scanEngine.models import VulnerabilityReportSetting

logger = logging.getLogger('reNgine.tasks')


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

    non_vulners = base_qs.exclude(source='VULNERS').order_by('-severity')
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


def generate_report_task(report_id):
    try:
        report_obj = ScanReport.objects.get(id=report_id)
        report_obj.status = 1 # Running
        report_obj.save()

        scan = report_obj.scan_history
        report_type = report_obj.report_type
        report_template = report_obj.report_template
        params = report_obj.params
        is_ignore_info_vuln = params.get('ignore_info_vuln', False)
        include_attack_surface_map = params.get('include_attack_surface_map', False)
        include_attack_paths = params.get('include_attack_paths', False)
        # Default True for backward-compat with reports created before this flag was stored.
        include_found_parameters = params.get('include_found_parameters', True)
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
            stress_results = StressTestResult.objects.filter(scan_history=scan).order_by('-timestamp')

        vuln_ctx = build_vuln_context(scan, ignore_info=is_ignore_info_vuln)

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

        ip_addresses = (
            IpAddress.objects
            .filter(ip_addresses__in=subdomains)
            .distinct()
        )

        # CPDE parameters — omit for stress-test-only reports or when the user
        # explicitly unchecked 'Include Found Parameters' in the report modal.
        parameters = Parameter.objects.none()
        if report_type != 'stress_test' and include_found_parameters:
            parameters = (
                Parameter.objects
                .filter(scan_history=scan)
                .select_related('endpoint')
                .order_by('-confidence', 'name')
            )

        attack_surface_map_image = None
        if report_template == 'enterprise' and include_attack_surface_map:
            try:
                neo4j_manager = Neo4jManager()
                graph_data = neo4j_manager.get_cytoscape_json(scan.id)
                if graph_data and graph_data.get('nodes'):
                    attack_surface_map_image = generate_attack_surface_map(graph_data)
                neo4j_manager.close()
            except Exception as e:
                logger.error("Error generating Attack Surface Map for report: %s", e)

        attack_paths = []
        if report_template in ['enterprise', 'cyber_pro'] and include_attack_paths:
            from startScan.models import ImpactAssessment
            assessments = (
                ImpactAssessment.objects.filter(scan_history_id=scan.id)
                .exclude(potential_attack_chain__isnull=True)
                .exclude(potential_attack_chain={})
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
                })

        email_breaches = EmailBreach.objects.filter(scan_history=scan).order_by('email_address', '-discovered_date')

        include_secret_findings = params.get('include_secret_findings', True)

        secret_leaks = SecretLeak.objects.none()
        secret_findings_by_type = {}
        if include_secret_findings:
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
        }

        # Stress Test Aggregation for context
        if stress_results.exists():
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

        # Get report related config
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

                data['llm_overview'] = markdown.markdown(llm_gen.generate_overview(llm_context))
                data['llm_executive_brief'] = markdown.markdown(llm_gen.generate_executive_brief(llm_context))
                data['llm_conclusion'] = markdown.markdown(llm_gen.generate_conclusion(llm_context))
                data['enable_llm_report_generation'] = True

            primary_color = report_setting.primary_color
            secondary_color = report_setting.secondary_color

        data['primary_color'] = primary_color
        data['secondary_color'] = secondary_color

        # Charts
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
        data['vulns_severity_chart'] = generate_vulnerability_chart_by_severity(vulns) if vulns else ''

        # Enhanced stress test charts for detailed reports
        if stress_results.exists():
            data['stress_latency_chart'] = generate_stress_latency_chart(stress_results)
            data['stress_success_rate_chart'] = generate_stress_success_rate_chart(stress_results)

            # Generate per-stress-result detailed charts and context
            stress_report_contexts = []
            for stress_result in stress_results:
                builder = StressReportBuilder(stress_result)
                report_context = builder.build()

                # Generate charts specific to this result
                report_context['latency_distribution_chart'] = generate_stress_latency_distribution_chart(stress_result)
                report_context['response_code_chart'] = generate_stress_response_code_chart(stress_result.response_code_distribution)
                report_context['error_breakdown_chart'] = generate_stress_error_breakdown_chart(stress_result.error_breakdown)
                report_context['endpoint_heatmap_chart'] = generate_stress_endpoint_heatmap(
                    stress_result.endpoints_tested,
                    stress_result.response_code_distribution
                )

                stress_report_contexts.append(report_context)

            data['stress_report_contexts'] = stress_report_contexts

        if report_template == 'enterprise':
            template = get_template('report/enterprise.html')
        elif report_template == 'modern' or report_template == 'stress_modern':
            template = get_template('report/modern.html') if report_template == 'modern' else get_template('report/stress_modern.html')
        elif report_template == 'cyber_pro' or report_template == 'stress_cyber_pro':
            template = get_template('report/cyber_pro.html') if report_template == 'cyber_pro' else get_template('report/stress_cyber_pro.html')
        else:
            template = get_template('report/default.html')

        html = template.render(data)
        pdf = HTML(string=html, url_fetcher=secure_url_fetcher).write_pdf()

        target_name = scan.domain.name
        date_str = datetime.now().strftime('%Y-%m-%d')
        filename = f"{target_name}_Stress_Report_{date_str}.pdf" if report_type == 'stress_test' else f"{target_name}_Report_{date_str}.pdf"

        # Save to FileField
        report_obj.report_file.save(filename, ContentFile(pdf))
        report_obj.status = 2 # Success
        report_obj.completed_at = timezone.now()
        report_obj.save()

    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        try:
            report_obj = ScanReport.objects.get(id=report_id)
            report_obj.status = 0 # Failed
            report_obj.error_message = str(e)
            report_obj.save()
        except ScanReport.DoesNotExist:
            logger.error(f"ScanReport with id {report_id} does not exist. Cannot save failed status.")
    finally:
        from django.db import close_old_connections
        close_old_connections()

