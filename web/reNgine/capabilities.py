"""Server-side capability registry for agent/UI tool discovery and singular runs.

Maps pipeline tasks and standalone workflows to asset kinds and risk classes.
Does not execute tools — callers validate then dispatch Temporal work.
"""
from __future__ import annotations

from typing import Any, Optional

# Asset kinds a tool may target.
ASSET_SUBDOMAIN = 'subdomain'
ASSET_ENDPOINT = 'endpoint'
ASSET_URL = 'url'
ASSET_HOST = 'host'

RISK_RECON = 'recon'
RISK_ACTIVE = 'active'
RISK_VULN = 'vuln'

# Pipeline tasks agents may propose for singular / subscan follow-ups.
# Keep in sync with _PERMITTED_GENERIC_TASKS / RETRYABLE_TASK_NAMES where possible.
_PIPELINE_TOOLS: dict[str, dict[str, Any]] = {
    'subdomain_discovery': {
        'title': 'Subdomain Discovery',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_HOST],
        'risk': RISK_RECON,
    },
    'port_scan': {
        'title': 'Port Scan',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_HOST],
        'risk': RISK_ACTIVE,
    },
    'http_crawl': {
        'title': 'HTTP Crawl',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_ACTIVE,
    },
    'fetch_url': {
        'title': 'Fetch URL',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_ACTIVE,
    },
    'screenshot': {
        'title': 'Screenshot',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_ACTIVE,
    },
    'dir_file_fuzz': {
        'title': 'Directory & File Fuzzing',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_ACTIVE,
    },
    'waf_detection': {
        'title': 'WAF Detection',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_ACTIVE,
    },
    'osint': {
        'title': 'OSINT',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_HOST],
        'risk': RISK_RECON,
    },
    'nuclei_scan': {
        'title': 'Nuclei Vulnerability Scan',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_VULN,
        # Dispatched via SingleTaskRetryWorkflow as vulnerability_scan child path.
        'retry_task_name': 'vulnerability_scan',
    },
    'vulnerability_scan': {
        'title': 'Vulnerability Scan',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_VULN,
    },
    'dalfox_xss_scan': {
        'title': 'Dalfox XSS Scan',
        'asset_kinds': [ASSET_ENDPOINT, ASSET_URL, ASSET_SUBDOMAIN],
        'risk': RISK_VULN,
    },
    'secret_scanning': {
        'title': 'Secret Scanning',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_VULN,
    },
    'waf_bypass': {
        'title': 'WAF Bypass',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_VULN,
    },
    'web_api_discovery': {
        'title': 'Web API Discovery',
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL],
        'risk': RISK_ACTIVE,
    },
    'param_discovery': {
        'title': 'Parameter Discovery',
        'asset_kinds': [ASSET_ENDPOINT, ASSET_URL, ASSET_SUBDOMAIN],
        'risk': RISK_ACTIVE,
    },
}

_WORKFLOW_TOOLS: dict[str, dict[str, Any]] = {
    'url-vuln': {
        'title': 'URL Vulnerability Workflow',
        'asset_kinds': [ASSET_URL, ASSET_ENDPOINT],
        'risk': RISK_VULN,
        'required_fields': ['urls'],
    },
    'url-crawl': {
        'title': 'URL Crawl Workflow',
        'asset_kinds': [ASSET_URL, ASSET_ENDPOINT],
        'risk': RISK_ACTIVE,
        'required_fields': ['urls'],
    },
    'url-fuzz': {
        'title': 'URL Fuzz Workflow',
        'asset_kinds': [ASSET_URL, ASSET_ENDPOINT],
        'risk': RISK_ACTIVE,
        'required_fields': ['urls'],
    },
    'url-dirsearch': {
        'title': 'URL DirSearch Workflow',
        'asset_kinds': [ASSET_URL, ASSET_ENDPOINT],
        'risk': RISK_ACTIVE,
        'required_fields': ['urls'],
    },
    'host-recon': {
        'title': 'Host Recon Workflow',
        'asset_kinds': [ASSET_HOST, ASSET_SUBDOMAIN],
        'risk': RISK_RECON,
        'required_fields': ['target', 'target_type'],
    },
    'domain-recon': {
        'title': 'Domain Recon Workflow',
        'asset_kinds': [ASSET_HOST],
        'risk': RISK_RECON,
        'required_fields': ['domain'],
    },
    'subdomain-recon': {
        'title': 'Subdomain Recon Workflow',
        'asset_kinds': [ASSET_HOST, ASSET_SUBDOMAIN],
        'risk': RISK_RECON,
        'required_fields': ['domain'],
    },
}


def list_pipeline_tools() -> list[dict[str, Any]]:
    out = []
    for name, meta in sorted(_PIPELINE_TOOLS.items()):
        out.append({
            'kind': 'pipeline_task',
            'name': name,
            'title': meta['title'],
            'asset_kinds': list(meta['asset_kinds']),
            'risk': meta['risk'],
        })
    return out


def list_workflow_tools() -> list[dict[str, Any]]:
    out = []
    for name, meta in sorted(_WORKFLOW_TOOLS.items()):
        out.append({
            'kind': 'workflow',
            'name': name,
            'title': meta['title'],
            'asset_kinds': list(meta['asset_kinds']),
            'risk': meta['risk'],
            'required_fields': list(meta.get('required_fields') or []),
        })
    return out


def list_capabilities() -> dict[str, Any]:
    return {
        'pipeline_tasks': list_pipeline_tools(),
        'workflows': list_workflow_tools(),
        'asset_kinds': [ASSET_SUBDOMAIN, ASSET_ENDPOINT, ASSET_URL, ASSET_HOST],
        'risk_classes': [RISK_RECON, RISK_ACTIVE, RISK_VULN],
        'max_followup_steps': 5,
    }


def get_pipeline_tool(name: str) -> Optional[dict[str, Any]]:
    meta = _PIPELINE_TOOLS.get(name)
    if not meta:
        return None
    return {'name': name, **meta}


def get_workflow_tool(name: str) -> Optional[dict[str, Any]]:
    meta = _WORKFLOW_TOOLS.get(name)
    if not meta:
        return None
    return {'name': name, **meta}


def resolve_retry_task_name(tool: str) -> str:
    """Map capability name to SingleTaskRetryWorkflow task_name."""
    meta = _PIPELINE_TOOLS.get(tool) or {}
    return meta.get('retry_task_name') or tool


def engine_enabled_tasks(engine) -> list[str]:
    """Return task names enabled on an EngineType (YAML top-level keys)."""
    try:
        return list(engine.tasks or [])
    except Exception:
        return []


def serialize_engine_detail(engine) -> dict[str, Any]:
    tasks = engine_enabled_tasks(engine)
    known = set(_PIPELINE_TOOLS)
    return {
        'id': engine.id,
        'engine_name': engine.engine_name,
        'default_engine': bool(engine.default_engine),
        'tasks': tasks,
        'known_followup_tasks': [t for t in tasks if t in known],
    }


# Heuristic suggestions for detail payloads (capped by caller).
_SEVERITY_TOOL = {
    4: 'vulnerability_scan',
    3: 'vulnerability_scan',
    2: 'nuclei_scan',
}


def suggest_followups_for_vulnerability(vuln) -> list[dict[str, Any]]:
    suggestions = []
    tool = _SEVERITY_TOOL.get(vuln.severity, 'nuclei_scan')
    if vuln.endpoint_id:
        suggestions.append({
            'tool': tool,
            'asset_type': ASSET_ENDPOINT,
            'asset_id': vuln.endpoint_id,
            'reason': 'Retarget vulnerability scanner on the affected endpoint',
            'risk': RISK_VULN,
            'step_kind': 'run_tool',
        })
    elif vuln.subdomain_id:
        suggestions.append({
            'tool': tool,
            'asset_type': ASSET_SUBDOMAIN,
            'asset_id': vuln.subdomain_id,
            'reason': 'Retarget vulnerability scanner on the affected host',
            'risk': RISK_VULN,
            'step_kind': 'run_tool',
        })
    if vuln.http_url:
        suggestions.append({
            'tool': 'url-vuln',
            'asset_type': ASSET_URL,
            'url': vuln.http_url,
            'reason': 'Run URL vulnerability workflow on the finding URL',
            'risk': RISK_VULN,
            'step_kind': 'start_workflow',
        })
    return suggestions[:3]


def suggest_followups_for_subdomain(subdomain) -> list[dict[str, Any]]:
    return [
        {
            'tool': 'port_scan',
            'asset_type': ASSET_SUBDOMAIN,
            'asset_id': subdomain.id,
            'reason': 'Enumerate open ports on this host',
            'risk': RISK_ACTIVE,
            'step_kind': 'run_tool',
        },
        {
            'tool': 'vulnerability_scan',
            'asset_type': ASSET_SUBDOMAIN,
            'asset_id': subdomain.id,
            'reason': 'Run vulnerability scan on this host',
            'risk': RISK_VULN,
            'step_kind': 'run_tool',
        },
    ]


def suggest_followups_for_endpoint(endpoint) -> list[dict[str, Any]]:
    return [
        {
            'tool': 'dir_file_fuzz',
            'asset_type': ASSET_ENDPOINT,
            'asset_id': endpoint.id,
            'reason': 'Fuzz directories on this endpoint',
            'risk': RISK_ACTIVE,
            'step_kind': 'run_tool',
        },
        {
            'tool': 'nuclei_scan',
            'asset_type': ASSET_ENDPOINT,
            'asset_id': endpoint.id,
            'reason': 'Nuclei templates against this URL',
            'risk': RISK_VULN,
            'step_kind': 'run_tool',
        },
    ]
