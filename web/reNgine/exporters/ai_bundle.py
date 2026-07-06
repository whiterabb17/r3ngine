from __future__ import annotations

import io
import json
import math
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from typing import Any

from django.utils import timezone

from startScan.models import (
    Command,
    DirectoryFile,
    DirectoryScan,
    Email,
    Employee,
    EndPoint,
    ImpactAssessment,
    MetaFinderDocument,
    Parameter,
    S3Bucket,
    ScanActivity,
    ScanHistory,
    SecretLeak,
    SubScan,
    Subdomain,
    Vulnerability,
)


FORMAT_VERSION = "ai-export.v1"
MARKDOWN_SECTION_CAPS = {
    "critical_vulnerabilities": 25,
    "other_vulnerability_groups": 20,
    "secret_leaks": 15,
    "attack_chains": 10,
    "interesting_endpoints": 25,
    "directory_findings": 25,
    "important_subdomains": 20,
    "technologies": 20,
    "ports": 20,
    "timeline": 20,
}
MAX_TEXT_PREVIEW = 1200
MAX_REQUEST_RESPONSE_PREVIEW = 2500
MAX_RAW_OUTPUT_PREVIEW = 4000
MAX_RAW_OUTPUT_FULL = 50000
SUSPICIOUS_KEYWORDS = (
    "admin", "login", "auth", "token", "oauth", "debug", "backup", "internal",
    "swagger", "openapi", "graphql", "jenkins", "grafana", "prometheus", "actuator",
)
INTERESTING_FILE_EXTENSIONS = (
    ".env", ".bak", ".sql", ".zip", ".tar", ".gz", ".7z", ".conf", ".config",
    ".yml", ".yaml", ".json", ".xml", ".pem", ".key", ".crt", ".log", ".old",
)


@dataclass(frozen=True)
class AiExportOptions:
    preset: str = "analyst_assist"
    include_raw_outputs: bool = False
    include_timeline: bool = True
    include_sidecars: bool = True
    format_version: str = FORMAT_VERSION


def build_ai_export_zip(scan: ScanHistory, options: AiExportOptions) -> tuple[io.BytesIO, str]:
    builder = AiBundleBuilder(scan=scan, options=options)
    return builder.build_zip()


class AiBundleBuilder:
    def __init__(self, scan: ScanHistory, options: AiExportOptions):
        self.scan = scan
        self.options = options
        self.generated_at = timezone.now()

    def build_zip(self) -> tuple[io.BytesIO, str]:
        bundle = self._build_bundle()
        markdown_text = self._render_markdown(bundle)
        prompt_text = self._render_prompt(bundle)
        findings_ndjson = self._render_ndjson(bundle["findings"])
        assets_ndjson = self._render_ndjson(bundle["assets"]) if self.options.include_sidecars else ""
        commands_ndjson = (
            self._render_ndjson(bundle["commands"])
            if self.options.include_raw_outputs and bundle["commands"]
            else ""
        )

        files: dict[str, str] = {
            "ai_bundle.md": markdown_text,
            "ai_bundle.json": self._render_json(bundle),
            "findings.ndjson": findings_ndjson,
            "prompt.txt": prompt_text,
        }
        if self.options.include_sidecars:
            files["assets.ndjson"] = assets_ndjson
        if self.options.include_raw_outputs and commands_ndjson:
            files["commands.ndjson"] = commands_ndjson

        manifest = self._build_manifest(bundle=bundle, files=files)
        files["manifest.json"] = self._render_json(manifest)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for name, content in files.items():
                zip_file.writestr(name, content)
        zip_buffer.seek(0)
        return zip_buffer, self._download_filename()

    def _build_bundle(self) -> dict[str, Any]:
        scan = (
            ScanHistory.objects
            .select_related("domain", "domain__project", "scan_type")
            .prefetch_related("buckets", "emails", "employees", "dorks")
            .get(pk=self.scan.pk)
        )
        subdomains = list(
            Subdomain.objects.filter(scan_history=scan)
            .prefetch_related("technologies", "ip_addresses__ports", "directories__directory_files", "waf")
            .order_by("name")
        )
        endpoints = list(
            EndPoint.objects.filter(scan_history=scan)
            .select_related("subdomain")
            .prefetch_related("techs")
            .order_by("http_url")
        )
        parameters = list(
            Parameter.objects.filter(scan_history=scan)
            .select_related("endpoint")
            .order_by("endpoint__http_url", "name")
        )
        vulnerabilities = list(
            Vulnerability.objects.filter(scan_history=scan, validation_status='verified')
            .select_related("subdomain", "endpoint", "target_domain")
            .prefetch_related("tags", "references", "cve_ids", "cwe_ids")
            .order_by("-severity", "-correlation_score", "-discovered_date", "name")
        )
        secret_leaks = list(
            SecretLeak.objects.filter(scan_history=scan)
            .select_related("subdomain")
            .order_by("-discovered_date", "tool_name")
        )
        subscans = list(
            SubScan.objects.filter(scan_history=scan)
            .select_related("subdomain", "engine")
            .order_by("-start_scan_date")
        )
        activities = list(
            ScanActivity.objects.filter(scan_of=scan)
            .order_by("tier", "time_started", "time")
        )
        commands = list(
            Command.objects.filter(scan_history=scan)
            .select_related("activity")
            .order_by("time")
        )
        documents = list(
            MetaFinderDocument.objects.filter(scan_history=scan)
            .select_related("subdomain")
            .order_by("doc_name", "url")
        )
        impact_assessments = list(
            ImpactAssessment.objects.filter(scan_history=scan)
            .select_related("vulnerability", "subdomain")
            .order_by("-updated_at")
        )
        directory_scans = list(
            DirectoryScan.objects.filter(directories__scan_history=scan)
            .prefetch_related("directory_files", "directories")
            .distinct()
        )

        unique_directory_files = self._collect_directory_files(directory_scans)
        unique_ips = self._collect_unique_ips(subdomains)
        discovered_ports = self._collect_ports(unique_ips)
        discovered_technologies = self._collect_technologies(subdomains, endpoints)
        vulnerability_groups = self._group_vulnerabilities(vulnerabilities)
        critical_vulns = [v for v in vulnerabilities if v.severity >= 3]
        attack_chain_hints = self._collect_attack_chain_hints(impact_assessments, vulnerability_groups)

        params_by_endpoint: dict[int, list[Parameter]] = {}
        for parameter in parameters:
            params_by_endpoint.setdefault(parameter.endpoint_id, []).append(parameter)

        serialized_vulnerabilities = [self._serialize_vulnerability(v) for v in vulnerabilities]
        serialized_secret_leaks = [self._serialize_secret_leak(leak) for leak in secret_leaks]
        serialized_endpoints = [
            self._serialize_endpoint(endpoint, params_by_endpoint.get(endpoint.id, []))
            for endpoint in endpoints
        ]
        serialized_subdomains = [self._serialize_subdomain(subdomain) for subdomain in subdomains]
        serialized_directory_files = [self._serialize_directory_file(df) for df in unique_directory_files]
        serialized_documents = [self._serialize_document(doc) for doc in documents]
        serialized_subscans = [self._serialize_subscan(subscan) for subscan in subscans]
        serialized_timeline = [self._serialize_timeline_item(activity) for activity in activities]
        serialized_commands = [self._serialize_command(command) for command in commands]

        ranked_endpoints = self._rank_endpoints(serialized_endpoints)
        ranked_directory_files = self._rank_directory_files(serialized_directory_files)
        ranked_subdomains = self._rank_subdomains(serialized_subdomains)

        scan_payload = {
            "metadata": self._serialize_scan(scan),
            "executive_counts": self._build_executive_counts(vulnerabilities, secret_leaks, ranked_endpoints, ranked_directory_files, subdomains),
            "vulnerability_groups": vulnerability_groups,
            "critical_vulnerabilities": [self._serialize_vulnerability(v) for v in critical_vulns],
            "secret_leaks": serialized_secret_leaks,
            "attack_chain_hints": attack_chain_hints,
            "interesting_endpoints": ranked_endpoints,
            "directory_findings": ranked_directory_files,
            "important_subdomains": ranked_subdomains,
            "documents": serialized_documents,
            "ports": discovered_ports,
            "technologies": discovered_technologies,
            "ips": unique_ips,
            "subscans": serialized_subscans,
            "timeline": serialized_timeline if self.options.include_timeline else [],
            "commands": serialized_commands if self.options.include_raw_outputs else [],
            "parameters": [self._serialize_parameter(p) for p in parameters],
            "buckets": [self._serialize_bucket(bucket) for bucket in scan.buckets.all()],
            "emails": [self._serialize_email(email) for email in scan.emails.all()],
            "employees": [self._serialize_employee(employee) for employee in scan.employees.all()],
            "dorks": [self._serialize_dork(dork) for dork in scan.dorks.all()],
            "subdomains": serialized_subdomains,
            "endpoints": serialized_endpoints,
            "directory_files": serialized_directory_files,
            "vulnerabilities": serialized_vulnerabilities,
        }

        return {
            "metadata": {
                "format_version": self.options.format_version,
                "preset": self.options.preset,
                "goal": "analyst_assist",
                "generated_at": self.generated_at.isoformat(),
                "scan_id": scan.id,
                "project_slug": scan.domain.project.slug if scan.domain and scan.domain.project else None,
                "target": scan.domain.name if scan.domain else None,
                "engine": scan.scan_type.engine_name if scan.scan_type else None,
                "status": scan.scan_status,
                "status_label": self._status_label(scan.scan_status),
                "start_scan_date": self._iso(scan.start_scan_date),
                "stop_scan_date": self._iso(scan.stop_scan_date),
                "tasks": list(scan.tasks or []),
                "options": {
                    "include_raw_outputs": self.options.include_raw_outputs,
                    "include_timeline": self.options.include_timeline,
                    "include_sidecars": self.options.include_sidecars,
                },
            },
            "counts": {
                "subdomains": len(subdomains),
                "endpoints": len(endpoints),
                "parameters": len(parameters),
                "vulnerabilities": len(vulnerabilities),
                "critical_high_vulnerabilities": len(critical_vulns),
                "secret_leaks": len(secret_leaks),
                "directory_files": len(unique_directory_files),
                "subscans": len(subscans),
                "timeline_items": len(serialized_timeline),
                "commands": len(serialized_commands),
                "documents": len(documents),
                "buckets": scan.buckets.count(),
                "emails": scan.emails.count(),
                "employees": scan.employees.count(),
                "dorks": scan.dorks.count(),
                "impact_assessments": len(impact_assessments),
            },
            "scan": scan_payload,
            "findings": serialized_vulnerabilities + serialized_secret_leaks,
            "assets": ranked_endpoints + ranked_directory_files + ranked_subdomains + [self._serialize_parameter(p) for p in parameters],
            "commands": serialized_commands if self.options.include_raw_outputs else [],
        }

    def _serialize_scan(self, scan: ScanHistory) -> dict[str, Any]:
        duration = None
        if scan.start_scan_date and scan.stop_scan_date:
            duration = int((scan.stop_scan_date - scan.start_scan_date).total_seconds())
        return {
            "id": scan.id,
            "target": scan.domain.name if scan.domain else None,
            "project_slug": scan.domain.project.slug if scan.domain and scan.domain.project else None,
            "engine": scan.scan_type.engine_name if scan.scan_type else None,
            "status": scan.scan_status,
            "status_label": self._status_label(scan.scan_status),
            "start_scan_date": self._iso(scan.start_scan_date),
            "stop_scan_date": self._iso(scan.stop_scan_date),
            "duration_seconds": duration,
            "progress": scan.get_progress(),
            "tasks": list(scan.tasks or []),
            "starting_point_path": scan.cfg_starting_point_path,
            "imported_subdomains": list(scan.cfg_imported_subdomains or []),
            "out_of_scope_subdomains": list(scan.cfg_out_of_scope_subdomains or []),
            "excluded_paths": list(scan.cfg_excluded_paths or []),
            "used_gf_patterns": scan.used_gf_patterns.split(",") if scan.used_gf_patterns else [],
        }

    def _build_executive_counts(self, vulnerabilities, secret_leaks, ranked_endpoints, ranked_directory_files, subdomains) -> dict[str, Any]:
        severity_counts = Counter(v.severity for v in vulnerabilities)
        alive_subdomains = sum(1 for subdomain in subdomains if subdomain.http_status and 0 < subdomain.http_status < 500 and subdomain.http_status != 404)
        return {
            "critical": severity_counts.get(4, 0),
            "high": severity_counts.get(3, 0),
            "medium": severity_counts.get(2, 0),
            "low": severity_counts.get(1, 0),
            "info": severity_counts.get(0, 0),
            "unknown": severity_counts.get(-1, 0),
            "total_vulnerabilities": len(vulnerabilities),
            "total_secret_leaks": len(secret_leaks),
            "interesting_endpoints": len(ranked_endpoints),
            "interesting_directory_findings": len(ranked_directory_files),
            "subdomains": len(subdomains),
            "alive_subdomains": alive_subdomains,
        }

    def _group_vulnerabilities(self, vulnerabilities: list[Vulnerability]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for vulnerability in vulnerabilities:
            asset = vulnerability.subdomain.name if vulnerability.subdomain else (vulnerability.http_url or (vulnerability.target_domain.name if vulnerability.target_domain else "unknown"))
            key = vulnerability.group_key or f"{vulnerability.name}|{asset}|{vulnerability.severity}"
            if key not in grouped:
                grouped[key] = {
                    "group_key": key,
                    "name": vulnerability.name,
                    "severity": vulnerability.severity,
                    "asset": asset,
                    "count": 0,
                    "correlation_score": vulnerability.correlation_score or 0.0,
                    "validation_status": vulnerability.validation_status,
                    "sample_ids": [],
                    "sources": set(),
                    "cves": set(),
                    "tags": set(),
                }
            entry = grouped[key]
            entry["count"] += 1
            entry["sample_ids"].append(vulnerability.id)
            if vulnerability.source:
                entry["sources"].add(vulnerability.source)
            entry["cves"].update(cve.name for cve in vulnerability.cve_ids.all())
            entry["tags"].update(tag.name for tag in vulnerability.tags.all())

        groups = []
        for entry in grouped.values():
            groups.append({
                **entry,
                "sources": sorted(entry["sources"]),
                "cves": sorted(entry["cves"]),
                "tags": sorted(entry["tags"]),
                "sample_ids": entry["sample_ids"][:10],
            })
        groups.sort(key=lambda item: (-item["severity"], -item["count"], -item["correlation_score"], item["name"]))
        return groups

    def _collect_attack_chain_hints(self, impact_assessments: list[ImpactAssessment], vulnerability_groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        hints: list[dict[str, Any]] = []
        for impact in impact_assessments:
            vuln = impact.vulnerability
            if not vuln:
                continue
            hints.append({
                "type": "impact_assessment",
                "vulnerability": vuln.name,
                "severity": vuln.severity,
                "asset": vuln.subdomain.name if vuln.subdomain else vuln.http_url,
                "potential_impact": self._truncate_text(impact.potential_impact, MAX_TEXT_PREVIEW),
                "potential_attack_chain": impact.potential_attack_chain,
                "simulated_path": impact.simulated_path,
                "remediation_priority": impact.remediation_priority,
            })
        if not hints:
            for group in vulnerability_groups[:MARKDOWN_SECTION_CAPS["attack_chains"]]:
                if group["severity"] >= 3 and group["count"] >= 2:
                    hints.append({
                        "type": "correlation_cluster",
                        "vulnerability": group["name"],
                        "severity": group["severity"],
                        "asset": group["asset"],
                        "potential_impact": f"Repeated finding cluster confirmed {group['count']} time(s) on {group['asset']}.",
                        "potential_attack_chain": None,
                        "simulated_path": None,
                        "remediation_priority": 1,
                    })
        return hints[:MARKDOWN_SECTION_CAPS["attack_chains"]]

    def _collect_directory_files(self, directory_scans: list[DirectoryScan]) -> list[DirectoryFile]:
        deduped: dict[str, DirectoryFile] = {}
        for directory_scan in directory_scans:
            for directory_file in directory_scan.directory_files.all():
                key = directory_file.url or directory_file.name or str(directory_file.id)
                deduped.setdefault(key, directory_file)
        return sorted(deduped.values(), key=lambda item: ((item.url or item.name or "").lower(), item.id))

    def _collect_unique_ips(self, subdomains: list[Subdomain]) -> list[dict[str, Any]]:
        ip_map: dict[str, dict[str, Any]] = {}
        for subdomain in subdomains:
            for ip in subdomain.ip_addresses.all():
                if ip.address not in ip_map:
                    ip_map[ip.address] = {
                        "address": ip.address,
                        "is_cdn": ip.is_cdn,
                        "asn": ip.asn,
                        "asn_org": ip.asn_org,
                        "geo_iso": ip.geo_iso.iso if ip.geo_iso else None,
                        "ports": set(),
                    }
                ip_map[ip.address]["ports"].update(
                    f"{port.number}/{port.service_name or 'unknown'}" for port in ip.ports.all()
                )
        rows = []
        for value in ip_map.values():
            rows.append({
                **value,
                "ports": sorted(value["ports"]),
            })
        rows.sort(key=lambda item: item["address"] or "")
        return rows

    def _collect_ports(self, unique_ips: list[dict[str, Any]]) -> list[dict[str, Any]]:
        counter: Counter[str] = Counter()
        for ip in unique_ips:
            counter.update(ip["ports"])
        return [{"port": port, "count": count} for port, count in counter.most_common(MARKDOWN_SECTION_CAPS["ports"])]

    def _collect_technologies(self, subdomains: list[Subdomain], endpoints: list[EndPoint]) -> list[dict[str, Any]]:
        counter: Counter[str] = Counter()
        for subdomain in subdomains:
            counter.update(tech.name for tech in subdomain.technologies.all() if tech.name)
        for endpoint in endpoints:
            counter.update(tech.name for tech in endpoint.techs.all() if tech.name)
        return [{"name": name, "count": count} for name, count in counter.most_common(MARKDOWN_SECTION_CAPS["technologies"])]

    def _serialize_vulnerability(self, vulnerability: Vulnerability) -> dict[str, Any]:
        request_preview, request_truncated = self._truncate_with_flag(vulnerability.request, MAX_REQUEST_RESPONSE_PREVIEW)
        response_preview, response_truncated = self._truncate_with_flag(vulnerability.response, MAX_REQUEST_RESPONSE_PREVIEW)
        return {
            "record_type": "vulnerability",
            "id": vulnerability.id,
            "name": vulnerability.name,
            "severity": vulnerability.severity,
            "severity_label": self._severity_label(vulnerability.severity),
            "source": vulnerability.source,
            "asset": vulnerability.subdomain.name if vulnerability.subdomain else (vulnerability.http_url or (vulnerability.target_domain.name if vulnerability.target_domain else None)),
            "subdomain": vulnerability.subdomain.name if vulnerability.subdomain else None,
            "endpoint": vulnerability.endpoint.http_url if vulnerability.endpoint else None,
            "http_url": vulnerability.http_url,
            "template_id": vulnerability.template_id,
            "matcher_name": vulnerability.matcher_name,
            "description": vulnerability.description,
            "impact": vulnerability.impact,
            "remediation": vulnerability.remediation,
            "validation_status": vulnerability.validation_status,
            "open_status": vulnerability.open_status,
            "correlation_score": vulnerability.correlation_score,
            "validation_confidence": vulnerability.validation_confidence,
            "is_suppressed": vulnerability.is_suppressed,
            "group_key": vulnerability.group_key,
            "cvss_score": vulnerability.cvss_score,
            "cvss_metrics": vulnerability.cvss_metrics,
            "exploit_url": vulnerability.exploit_url,
            "discovered_date": self._iso(vulnerability.discovered_date),
            "tags": [tag.name for tag in vulnerability.tags.all()],
            "references": [ref.url for ref in vulnerability.references.all()],
            "cves": [self._serialize_cve(cve) for cve in vulnerability.cve_ids.all()],
            "cwes": [cwe.name for cwe in vulnerability.cwe_ids.all()],
            "extracted_results": list(vulnerability.extracted_results or []),
            "curl_command": self._truncate_text(vulnerability.curl_command, MAX_TEXT_PREVIEW),
            "request_preview": request_preview,
            "request_truncated": request_truncated,
            "response_preview": response_preview,
            "response_truncated": response_truncated,
        }

    def _serialize_cve(self, cve) -> dict[str, Any]:
        return {
            "name": cve.name,
            "cvss_v31_base_score": cve.cvss_v31_base_score,
            "epss_score": cve.epss_score,
            "epss_percentile": cve.epss_percentile,
            "is_cisa_kev": cve.is_cisa_kev,
            "patching_priority": cve.patching_priority,
            "is_poc": cve.is_poc,
        }

    def _serialize_secret_leak(self, leak: SecretLeak) -> dict[str, Any]:
        match_preview, match_truncated = self._truncate_with_flag(leak.match_content, MAX_TEXT_PREVIEW)
        return {
            "record_type": "secret_leak",
            "id": leak.id,
            "tool_name": leak.tool_name,
            "secret_type": leak.secret_type,
            "status": leak.status,
            "source_url": leak.source_url,
            "subdomain": leak.subdomain.name if leak.subdomain else None,
            "match_content": match_preview,
            "match_content_truncated": match_truncated,
            "discovered_date": self._iso(leak.discovered_date),
        }

    def _serialize_endpoint(self, endpoint: EndPoint, params_for_endpoint: list[Parameter]) -> dict[str, Any]:
        techs = sorted({tech.name for tech in endpoint.techs.all() if tech.name})
        matched_patterns = sorted(set(filter(None, (endpoint.matched_gf_patterns or "").split(",")))) if endpoint.matched_gf_patterns else []
        return {
            "record_type": "endpoint",
            "id": endpoint.id,
            "http_url": endpoint.http_url,
            "subdomain": endpoint.subdomain.name if endpoint.subdomain else None,
            "http_status": endpoint.http_status,
            "content_type": endpoint.content_type,
            "page_title": endpoint.page_title,
            "content_length": endpoint.content_length,
            "response_time": endpoint.response_time,
            "webserver": endpoint.webserver,
            "source": endpoint.source,
            "is_redirect": endpoint.is_redirect,
            "matched_gf_patterns": matched_patterns,
            "technologies": techs,
            "parameters": [self._serialize_parameter(param) for param in params_for_endpoint],
            "rank_score": self._endpoint_rank_score(endpoint, params_for_endpoint),
        }

    def _serialize_parameter(self, parameter: Parameter) -> dict[str, Any]:
        return {
            "record_type": "parameter",
            "id": parameter.id,
            "endpoint": parameter.endpoint.http_url if parameter.endpoint else None,
            "name": parameter.name,
            "value": parameter.value,
            "type": parameter.type,
            "impact": parameter.impact,
            "confidence": parameter.confidence,
            "sources": list(parameter.sources or []),
            "param_location": parameter.param_location,
            "data_type": parameter.data_type,
            "is_auth_related": parameter.is_auth_related,
            "observed_in_js": parameter.observed_in_js,
            "observed_in_openapi": parameter.observed_in_openapi,
            "observed_in_graphql": parameter.observed_in_graphql,
            "discovered_date": self._iso(parameter.discovered_date),
        }

    def _serialize_subdomain(self, subdomain: Subdomain) -> dict[str, Any]:
        return {
            "record_type": "subdomain",
            "id": subdomain.id,
            "name": subdomain.name,
            "http_url": subdomain.http_url,
            "http_status": subdomain.http_status,
            "is_important": subdomain.is_important,
            "page_title": subdomain.page_title,
            "content_type": subdomain.content_type,
            "response_time": subdomain.response_time,
            "content_length": subdomain.content_length,
            "origin_ip": subdomain.origin_ip,
            "is_cdn": subdomain.is_cdn,
            "cdn_name": subdomain.cdn_name,
            "criticality_level": subdomain.criticality_level,
            "criticality_reason": self._truncate_text(subdomain.criticality_reason, MAX_TEXT_PREVIEW),
            "technologies": sorted({tech.name for tech in subdomain.technologies.all() if tech.name}),
            "waf": sorted({waf.name for waf in subdomain.waf.all() if waf.name}),
            "ip_addresses": [ip.address for ip in subdomain.ip_addresses.all() if ip.address],
            "rank_score": self._subdomain_rank_score(subdomain),
        }

    def _serialize_directory_file(self, directory_file: DirectoryFile) -> dict[str, Any]:
        return {
            "record_type": "directory_file",
            "id": directory_file.id,
            "name": directory_file.name,
            "url": directory_file.url,
            "http_status": directory_file.http_status,
            "content_type": directory_file.content_type,
            "length": directory_file.length,
            "words": directory_file.words,
            "lines": directory_file.lines,
            "rank_score": self._directory_rank_score(directory_file),
        }

    def _serialize_document(self, document: MetaFinderDocument) -> dict[str, Any]:
        return {
            "record_type": "document",
            "id": document.id,
            "doc_name": document.doc_name,
            "url": document.url,
            "title": document.title,
            "author": document.author,
            "producer": document.producer,
            "creator": document.creator,
            "os": document.os,
            "http_status": document.http_status,
            "subdomain": document.subdomain.name if document.subdomain else None,
        }

    def _serialize_subscan(self, subscan: SubScan) -> dict[str, Any]:
        return {
            "record_type": "subscan",
            "id": subscan.id,
            "type": subscan.type,
            "status": subscan.status,
            "status_label": self._status_label(subscan.status),
            "subdomain": subscan.subdomain.name if subscan.subdomain else None,
            "engine": subscan.engine.engine_name if subscan.engine else None,
            "start_scan_date": self._iso(subscan.start_scan_date),
            "stop_scan_date": self._iso(subscan.stop_scan_date),
            "error_message": subscan.error_message,
        }

    def _serialize_timeline_item(self, activity: ScanActivity) -> dict[str, Any]:
        return {
            "record_type": "timeline",
            "id": activity.id,
            "title": activity.title,
            "name": activity.name,
            "status": activity.status,
            "status_label": self._status_label(activity.status),
            "tier": activity.tier,
            "time_started": self._iso(activity.time_started),
            "time_ended": self._iso(activity.time_ended),
            "time": self._iso(activity.time),
            "error_message": activity.error_message,
        }

    def _serialize_command(self, command: Command) -> dict[str, Any]:
        limit = MAX_RAW_OUTPUT_FULL if self.options.include_raw_outputs else MAX_RAW_OUTPUT_PREVIEW
        output, truncated = self._truncate_with_flag(command.output, limit)
        return {
            "record_type": "command",
            "id": command.id,
            "activity_id": command.activity_id,
            "activity_title": command.activity.title if command.activity else None,
            "time": self._iso(command.time),
            "command": command.command,
            "return_code": command.return_code,
            "output": output,
            "output_truncated": truncated,
            "raw": self.options.include_raw_outputs,
        }

    def _serialize_bucket(self, bucket: S3Bucket) -> dict[str, Any]:
        return {
            "name": bucket.name,
            "region": bucket.region,
            "provider": bucket.provider,
            "num_objects": bucket.num_objects,
            "size": bucket.size,
            "public_read": bool(bucket.perm_all_users_read),
            "public_write": bool(bucket.perm_all_users_write),
        }

    def _serialize_email(self, email: Email) -> dict[str, Any]:
        return {
            "address": email.address,
            "password": email.password,
            "metadata": email.metadata,
        }

    def _serialize_employee(self, employee: Employee) -> dict[str, Any]:
        return {
            "name": employee.name,
            "designation": employee.designation,
            "metadata": employee.metadata,
        }

    def _serialize_dork(self, dork) -> dict[str, Any]:
        return {
            "type": dork.type,
            "url": dork.url,
        }

    def _rank_endpoints(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped = {endpoint["http_url"]: endpoint for endpoint in endpoints}
        return sorted(deduped.values(), key=lambda item: (-item["rank_score"], item["http_url"] or ""))

    def _rank_directory_files(self, directory_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped = {
            directory_file.get("url") or directory_file.get("name") or str(directory_file["id"]): directory_file
            for directory_file in directory_files
        }
        return sorted(deduped.values(), key=lambda item: (-item["rank_score"], item.get("url") or item.get("name") or ""))

    def _rank_subdomains(self, subdomains: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(subdomains, key=lambda item: (-item["rank_score"], item["name"]))

    def _endpoint_rank_score(self, endpoint: EndPoint, params_for_endpoint: list[Parameter]) -> int:
        url = (endpoint.http_url or "").lower()
        score = 0
        if endpoint.http_status in {200, 401, 403, 500}:
            score += 12
        if any(keyword in url for keyword in SUSPICIOUS_KEYWORDS):
            score += 15
        if params_for_endpoint:
            score += min(10, len(params_for_endpoint) * 2)
        if endpoint.matched_gf_patterns:
            score += 8
        if any(param.is_auth_related for param in params_for_endpoint):
            score += 10
        if any(param.observed_in_openapi or param.observed_in_graphql for param in params_for_endpoint):
            score += 6
        if endpoint.techs.exists():
            score += min(6, endpoint.techs.count())
        return score

    def _directory_rank_score(self, directory_file: DirectoryFile) -> int:
        target = (directory_file.url or directory_file.name or "").lower()
        score = 0
        if directory_file.http_status in {200, 206, 401, 403, 500}:
            score += 10
        if any(keyword in target for keyword in SUSPICIOUS_KEYWORDS):
            score += 15
        if any(target.endswith(ext) for ext in INTERESTING_FILE_EXTENSIONS):
            score += 18
        if directory_file.content_type and any(marker in directory_file.content_type.lower() for marker in ("json", "xml", "yaml", "text")):
            score += 5
        return score

    def _subdomain_rank_score(self, subdomain: Subdomain) -> int:
        name = (subdomain.name or "").lower()
        score = 0
        if subdomain.is_important:
            score += 20
        if subdomain.http_status in {200, 401, 403, 500}:
            score += 10
        if any(keyword in name for keyword in SUSPICIOUS_KEYWORDS):
            score += 15
        if subdomain.criticality_level:
            score += int(subdomain.criticality_level) * 2
        if subdomain.origin_ip:
            score += 2
        return score

    def _render_markdown(self, bundle: dict[str, Any]) -> str:
        scan = bundle["scan"]
        executive = scan["executive_counts"]
        lines = [
            "# AI Export Bundle",
            "",
            f"- Target: `{bundle['metadata']['target']}`",
            f"- Scan ID: `{bundle['metadata']['scan_id']}`",
            f"- Engine: `{bundle['metadata']['engine']}`",
            f"- Status: `{bundle['metadata']['status_label']}`",
            f"- Generated At: `{bundle['metadata']['generated_at']}`",
            f"- Goal: `analyst_assist`",
            "",
            "## Executive Counts",
            "",
            f"- Vulnerabilities: `{executive['total_vulnerabilities']}`",
            f"- Critical: `{executive['critical']}`",
            f"- High: `{executive['high']}`",
            f"- Secret Leaks: `{executive['total_secret_leaks']}`",
            f"- Interesting Endpoints: `{executive['interesting_endpoints']}`",
            f"- Interesting Directory Findings: `{executive['interesting_directory_findings']}`",
            f"- Subdomains: `{executive['subdomains']}` (`{executive['alive_subdomains']}` alive)",
            "",
            "## Analyst Guidance",
            "",
            "- Use this bundle as an analyst-assist artifact, not as a replacement for manual validation.",
            "- Main markdown is intentionally compact; fuller records live in `ai_bundle.json` and sidecar NDJSON files.",
            "",
        ]
        lines.extend(self._render_vulnerability_section(scan["critical_vulnerabilities"], scan["vulnerability_groups"]))
        lines.extend(self._render_secret_leaks_section(scan["secret_leaks"]))
        lines.extend(self._render_attack_chain_section(scan["attack_chain_hints"]))
        lines.extend(self._render_endpoint_section(scan["interesting_endpoints"]))
        lines.extend(self._render_directory_section(scan["directory_findings"]))
        lines.extend(self._render_subdomain_section(scan["important_subdomains"]))
        lines.extend(self._render_supporting_assets_section(scan))
        if self.options.include_timeline:
            lines.extend(self._render_timeline_section(scan["timeline"]))
        if self.options.include_raw_outputs and bundle["commands"]:
            lines.extend(self._render_command_summary_section(bundle["commands"]))
        return "\n".join(lines).strip() + "\n"

    def _render_vulnerability_section(self, critical_vulnerabilities: list[dict[str, Any]], groups: list[dict[str, Any]]) -> list[str]:
        lines = ["## Critical And High Findings", ""]
        top_vulns = critical_vulnerabilities[:MARKDOWN_SECTION_CAPS["critical_vulnerabilities"]]
        if not top_vulns:
            lines.append("- No critical or high-severity findings in this scan.")
        else:
            for vuln in top_vulns:
                lines.append(f"- `{vuln['severity_label']}` {vuln['name']} on `{vuln['asset'] or 'unknown'}`")
                if vuln.get("http_url"):
                    lines.append(f"  URL: `{vuln['http_url']}`")
                if vuln.get("description"):
                    lines.append(f"  Description: {self._truncate_text(vuln['description'], 240)}")
                if vuln.get("cves"):
                    lines.append(f"  CVEs: `{', '.join(cve['name'] for cve in vuln['cves'][:5])}`")
                lines.append(f"  Validation: `{vuln['validation_status']}` | Correlation: `{round(vuln.get('correlation_score') or 0, 2)}`")

        lines.extend(["", "## Correlated Finding Groups", ""])
        top_groups = groups[:MARKDOWN_SECTION_CAPS["other_vulnerability_groups"]]
        if not top_groups:
            lines.append("- No correlated finding groups available.")
        else:
            for group in top_groups:
                lines.append(
                    f"- `{self._severity_label(group['severity'])}` {group['name']} on `{group['asset']}`"
                    f" | occurrences `{group['count']}` | correlation `{round(group['correlation_score'] or 0, 2)}`"
                )
        lines.append("")
        return lines

    def _render_secret_leaks_section(self, secret_leaks: list[dict[str, Any]]) -> list[str]:
        lines = ["## Secrets And Exposures", ""]
        if not secret_leaks:
            lines.append("- No secret leaks captured for this scan.")
            lines.append("")
            return lines
        for leak in secret_leaks[:MARKDOWN_SECTION_CAPS["secret_leaks"]]:
            lines.append(f"- `{leak['secret_type']}` via `{leak['tool_name']}` on `{leak.get('subdomain') or leak.get('source_url') or 'unknown'}`")
            if leak.get("source_url"):
                lines.append(f"  Source: `{leak['source_url']}`")
            if leak.get("match_content"):
                lines.append(f"  Evidence: {self._truncate_text(leak['match_content'], 240)}")
        lines.append("")
        return lines

    def _render_attack_chain_section(self, attack_chains: list[dict[str, Any]]) -> list[str]:
        lines = ["## Attack Chain Hints", ""]
        if not attack_chains:
            lines.append("- No attack-chain hints available.")
            lines.append("")
            return lines
        for hint in attack_chains[:MARKDOWN_SECTION_CAPS["attack_chains"]]:
            lines.append(f"- `{self._severity_label(hint['severity'])}` {hint['vulnerability']} on `{hint.get('asset') or 'unknown'}`")
            if hint.get("potential_impact"):
                lines.append(f"  Impact: {self._truncate_text(hint['potential_impact'], 260)}")
            if hint.get("potential_attack_chain"):
                lines.append(f"  Chain Data: `{self._truncate_text(json.dumps(hint['potential_attack_chain'], ensure_ascii=False), 220)}`")
        lines.append("")
        return lines

    def _render_endpoint_section(self, endpoints: list[dict[str, Any]]) -> list[str]:
        lines = ["## Interesting Endpoints", ""]
        if not endpoints:
            lines.append("- No ranked endpoints available.")
            lines.append("")
            return lines
        for endpoint in endpoints[:MARKDOWN_SECTION_CAPS["interesting_endpoints"]]:
            lines.append(f"- `{endpoint['http_status']}` `{endpoint['http_url']}` | score `{endpoint['rank_score']}`")
            if endpoint.get("matched_gf_patterns"):
                lines.append(f"  GF: `{', '.join(endpoint['matched_gf_patterns'][:5])}`")
            if endpoint.get("parameters"):
                lines.append(f"  Params: `{', '.join(param['name'] for param in endpoint['parameters'][:6])}`")
            if endpoint.get("technologies"):
                lines.append(f"  Tech: `{', '.join(endpoint['technologies'][:6])}`")
        lines.append("")
        return lines

    def _render_directory_section(self, directory_files: list[dict[str, Any]]) -> list[str]:
        lines = ["## Interesting Directory And File Findings", ""]
        if not directory_files:
            lines.append("- No directory or file findings ranked as interesting.")
            lines.append("")
            return lines
        for directory_file in directory_files[:MARKDOWN_SECTION_CAPS["directory_findings"]]:
            target = directory_file.get("url") or directory_file.get("name") or "unknown"
            lines.append(f"- `{directory_file['http_status']}` `{target}` | score `{directory_file['rank_score']}`")
            if directory_file.get("content_type"):
                lines.append(f"  Content-Type: `{directory_file['content_type']}`")
        lines.append("")
        return lines

    def _render_subdomain_section(self, subdomains: list[dict[str, Any]]) -> list[str]:
        lines = ["## Important Subdomains", ""]
        if not subdomains:
            lines.append("- No subdomains available.")
            lines.append("")
            return lines
        for subdomain in subdomains[:MARKDOWN_SECTION_CAPS["important_subdomains"]]:
            lines.append(f"- `{subdomain['http_status']}` `{subdomain['name']}` | score `{subdomain['rank_score']}`")
            if subdomain.get("technologies"):
                lines.append(f"  Tech: `{', '.join(subdomain['technologies'][:6])}`")
            if subdomain.get("waf"):
                lines.append(f"  WAF: `{', '.join(subdomain['waf'][:4])}`")
        lines.append("")
        return lines

    def _render_supporting_assets_section(self, scan: dict[str, Any]) -> list[str]:
        lines = ["## Supporting Asset Context", ""]
        if scan["technologies"]:
            lines.append("- Technologies: " + ", ".join(f"{item['name']} ({item['count']})" for item in scan["technologies"][:MARKDOWN_SECTION_CAPS["technologies"]]))
        if scan["ports"]:
            lines.append("- Ports: " + ", ".join(f"{item['port']} ({item['count']})" for item in scan["ports"][:MARKDOWN_SECTION_CAPS["ports"]]))
        if scan["documents"]:
            lines.append(f"- Documents: `{len(scan['documents'])}` total")
        if scan["buckets"]:
            lines.append(f"- Buckets: `{len(scan['buckets'])}` total")
        if scan["emails"]:
            lines.append(f"- Emails: `{len(scan['emails'])}` total")
        if scan["employees"]:
            lines.append(f"- Employees: `{len(scan['employees'])}` total")
        lines.append("")
        return lines

    def _render_timeline_section(self, timeline: list[dict[str, Any]]) -> list[str]:
        lines = ["## Timeline Summary", ""]
        if not timeline:
            lines.append("- Timeline omitted or empty.")
            lines.append("")
            return lines
        for item in timeline[:MARKDOWN_SECTION_CAPS["timeline"]]:
            lines.append(f"- Tier `{item.get('tier')}` `{item['title']}` -> `{item['status_label']}`")
            if item.get("error_message"):
                lines.append(f"  Error: {self._truncate_text(item['error_message'], 180)}")
        lines.append("")
        return lines

    def _render_command_summary_section(self, commands: list[dict[str, Any]]) -> list[str]:
        lines = ["## Raw Command Output Summary", ""]
        for command in commands[:10]:
            lines.append(f"- `{command.get('activity_title') or 'Command'}` return_code `{command.get('return_code')}`")
            if command.get("command"):
                lines.append(f"  Command: `{self._truncate_text(command['command'], 220)}`")
            if command.get("output"):
                lines.append(f"  Output Preview: {self._truncate_text(command['output'], 280)}")
        lines.append("")
        return lines

    def _render_prompt(self, bundle: dict[str, Any]) -> str:
        return (
            "You are assisting with security triage for a scan artifact exported from r3ngine.\n\n"
            f"Target: {bundle['metadata']['target']}\n"
            f"Scan ID: {bundle['metadata']['scan_id']}\n"
            "Primary goal: analyst assist, not blind auto-triage.\n\n"
            "Tasks:\n"
            "1. Prioritize the highest-risk findings and explain why.\n"
            "2. Identify likely attack paths or escalation chains.\n"
            "3. Point out which findings need manual verification first.\n"
            "4. Suggest follow-up checks that would reduce uncertainty quickly.\n"
            "5. Flag low-signal noise that should not dominate analyst time.\n\n"
            "Use `ai_bundle.md` for the compact overview.\n"
            "Use `ai_bundle.json`, `findings.ndjson`, and sidecar files for deeper evidence.\n"
            "Do not assume all findings are valid without manual confirmation.\n"
        )

    def _build_manifest(self, bundle: dict[str, Any], files: dict[str, str]) -> dict[str, Any]:
        file_estimates = {
            name: {
                "bytes": len(content.encode("utf-8")),
                "rough_tokens": self._rough_tokens(content),
            }
            for name, content in files.items()
        }
        markdown_sections = {
            "critical_vulnerabilities": min(len(bundle["scan"]["critical_vulnerabilities"]), MARKDOWN_SECTION_CAPS["critical_vulnerabilities"]),
            "secret_leaks": min(len(bundle["scan"]["secret_leaks"]), MARKDOWN_SECTION_CAPS["secret_leaks"]),
            "attack_chains": min(len(bundle["scan"]["attack_chain_hints"]), MARKDOWN_SECTION_CAPS["attack_chains"]),
            "interesting_endpoints": min(len(bundle["scan"]["interesting_endpoints"]), MARKDOWN_SECTION_CAPS["interesting_endpoints"]),
            "directory_findings": min(len(bundle["scan"]["directory_findings"]), MARKDOWN_SECTION_CAPS["directory_findings"]),
            "important_subdomains": min(len(bundle["scan"]["important_subdomains"]), MARKDOWN_SECTION_CAPS["important_subdomains"]),
            "timeline": min(len(bundle["scan"]["timeline"]), MARKDOWN_SECTION_CAPS["timeline"]) if self.options.include_timeline else 0,
        }
        return {
            "format_version": self.options.format_version,
            "generated_at": self.generated_at.isoformat(),
            "scan_id": bundle["metadata"]["scan_id"],
            "target": bundle["metadata"]["target"],
            "preset": self.options.preset,
            "goal": "analyst_assist",
            "options": bundle["metadata"]["options"],
            "counts": bundle["counts"],
            "markdown_caps": MARKDOWN_SECTION_CAPS,
            "markdown_exported_counts": markdown_sections,
            "files": file_estimates,
            "included_files": sorted(files.keys()),
            "notes": [
                "Main markdown is compact and prioritized.",
                "Fuller records live in ai_bundle.json and NDJSON sidecars.",
                "Large raw outputs stay out of the main markdown even when raw output export is enabled.",
            ],
        }

    def _render_ndjson(self, records: list[dict[str, Any]]) -> str:
        return "\n".join(json.dumps(record, ensure_ascii=False, default=str) for record in records) + ("\n" if records else "")

    def _render_json(self, payload: dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=False, indent=2, default=str)

    def _download_filename(self) -> str:
        target = re.sub(r"[^a-zA-Z0-9._-]+", "_", self.scan.domain.name if self.scan.domain else f"scan_{self.scan.id}").strip("_")
        return f"ai_bundle_{target}_{self.scan.id}_{self.generated_at.strftime('%Y%m%d_%H%M%S')}.zip"

    def _truncate_text(self, value: Any, limit: int) -> str | None:
        if value is None:
            return None
        text = str(value)
        if len(text) <= limit:
            return text
        return f"{text[:limit].rstrip()}... [truncated]"

    def _truncate_with_flag(self, value: Any, limit: int) -> tuple[str | None, bool]:
        if value is None:
            return None, False
        text = str(value)
        if len(text) <= limit:
            return text, False
        return f"{text[:limit].rstrip()}... [truncated]", True

    def _iso(self, value) -> str | None:
        return value.isoformat() if value else None

    def _rough_tokens(self, value: str) -> int:
        return max(1, math.ceil(len(value) / 4)) if value else 0

    def _severity_label(self, severity: int | None) -> str:
        return {
            4: "CRITICAL",
            3: "HIGH",
            2: "MEDIUM",
            1: "LOW",
            0: "INFO",
            -1: "UNKNOWN",
        }.get(severity, "UNKNOWN")

    def _status_label(self, status: int | None) -> str:
        return {
            2: "SUCCESS",
            1: "RUNNING",
            0: "FAILED",
            3: "ABORTED",
            4: "PAUSED",
            -1: "PENDING",
        }.get(status, "UNKNOWN")
