"""Index completed scan findings into the Assessment Copilot memory store."""
from __future__ import annotations

import logging
from typing import Any

from temporalio import activity

from copilot.client import CopilotClientError, copilot_index
from startScan.models import Vulnerability

logger = logging.getLogger(__name__)


def _vuln_chunk(vuln: Vulnerability, project_slug: str) -> dict[str, Any]:
    enrichment = vuln.agent_enrichment or {}
    poc = enrichment.get('poc') or {}
    text_parts = [
        f"Finding: {vuln.name}",
        f"Severity: {vuln.get_severity_display() if hasattr(vuln, 'get_severity_display') else vuln.severity}",
        f"URL: {vuln.http_url or ''}",
        f"Description: {(vuln.description or '')[:1500]}",
        f"Remediation: {(vuln.remediation or '')[:1000]}",
        f"Validation: {vuln.validation_status or ''} {vuln.validation_reason or ''}",
    ]
    tags = ['vulnerability', f'severity:{vuln.severity}']
    cve_names: list[str] = []
    try:
        for cve in vuln.cve_ids.all()[:8]:
            name = getattr(cve, 'name', None) or str(cve)
            if name:
                cve_names.append(name)
                text_parts.append(f"CVE: {name}")
                tags.append(name)
            pe = getattr(cve, 'public_exploits', None) or []
            if pe:
                text_parts.append(f"public_exploits: {len(pe)}")
                tags.extend(['public_exploit', 'has_metasploit', 'msf_aux'])
    except Exception:
        pass
    if enrichment.get('has_metasploit') or (enrichment.get('apme') or {}).get('has_metasploit'):
        text_parts.append('has_metasploit: true')
        tags.extend(['has_metasploit', 'msf_aux', 'metasploit'])
    if poc:
        text_parts.append(f"SAFE PoC: {poc}")
    if enrichment.get('remediation'):
        text_parts.append(f"Agent remediation: {enrichment.get('remediation')}")
    if enrichment.get('msf_aux'):
        text_parts.append(f"MSF aux: {enrichment.get('msf_aux')}")
        tags.append('msf_aux')
    return {
        'id': f'vuln:{vuln.id}:scan:{vuln.scan_history_id}',
        'text': '\n'.join(text_parts),
        'scope': 'project',
        'project_id': project_slug,
        'tags': tags,
        'meta': {
            'vulnerability_id': vuln.id,
            'scan_id': vuln.scan_history_id,
            'template_id': getattr(vuln, 'template_id', None),
            'cve_ids': cve_names,
        },
    }


@activity.defn(name="IndexScanForCopilotActivity")
def index_scan_for_copilot_activity(scan_history_id: int) -> dict[str, Any]:
    """Best-effort index of scan vulns into assessment-copilot. Never raises to fail scans."""
    from startScan.models import ScanHistory

    try:
        scan = (
            ScanHistory.objects
            .select_related('domain', 'domain__project')
            .filter(pk=scan_history_id)
            .first()
        )
        if not scan or not scan.domain or not scan.domain.project:
            return {'ok': False, 'reason': 'scan_or_project_missing'}

        project_slug = scan.domain.project.slug
        vulns = Vulnerability.objects.filter(scan_history_id=scan_history_id).order_by('-severity')[:500]
        documents = [_vuln_chunk(v, project_slug) for v in vulns]
        if not documents:
            return {'ok': True, 'indexed': 0, 'reason': 'no_vulnerabilities'}

        result = copilot_index(documents)
        activity.logger.info(
            'IndexScanForCopilotActivity scan_id=%s indexed=%s',
            scan_history_id,
            result.get('indexed_documents'),
        )
        return {'ok': True, 'indexed': result.get('indexed_documents', 0), 'scan_id': scan_history_id}
    except CopilotClientError as exc:
        activity.logger.warning(
            'IndexScanForCopilotActivity skipped (copilot down) scan_id=%s: %s',
            scan_history_id,
            exc,
        )
        return {'ok': False, 'reason': 'copilot_unreachable', 'detail': str(exc)}
    except Exception as exc:
        activity.logger.exception(
            'IndexScanForCopilotActivity failed scan_id=%s: %s',
            scan_history_id,
            exc,
        )
        return {'ok': False, 'reason': 'error', 'detail': str(exc)}
