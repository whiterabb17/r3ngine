"""Singular tool execution — build context and start SingleTaskRetryWorkflow."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional, Tuple

import yaml
from django.utils import timezone

from reNgine.capabilities import (
    ASSET_ENDPOINT,
    ASSET_HOST,
    ASSET_SUBDOMAIN,
    ASSET_URL,
    get_pipeline_tool,
    get_workflow_tool,
    resolve_retry_task_name,
)
from reNgine.definitions import INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK
from reNgine.temporal_client import TemporalClientProvider, run_and_close
from startScan.models import EndPoint, ScanActivity, ScanHistory, Subdomain

logger = logging.getLogger(__name__)


class ToolRunError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _load_yaml(scan: ScanHistory) -> dict:
    try:
        return yaml.safe_load(scan.scan_type.yaml_configuration or '') or {}
    except Exception:
        return {}


def _resolve_asset(
    *,
    asset_type: str,
    asset_id: Optional[int],
    url: Optional[str],
    scan: ScanHistory,
) -> Tuple[Optional[Subdomain], Optional[str], Optional[str]]:
    """Return (subdomain, subdomain_name, http_url)."""
    subdomain = None
    subdomain_name = None
    http_url = None

    if asset_type == ASSET_SUBDOMAIN:
        if not asset_id:
            raise ToolRunError('asset_id is required for subdomain')
        subdomain = Subdomain.objects.filter(pk=asset_id, scan_history=scan).first()
        if not subdomain:
            # Allow target-domain scoped subdomain from any scan of same domain
            subdomain = Subdomain.objects.filter(pk=asset_id, target_domain_id=scan.domain_id).first()
        if not subdomain:
            raise ToolRunError('Subdomain not found for this scan/target', 404)
        subdomain_name = subdomain.name
        http_url = subdomain.http_url or f'https://{subdomain.name}/'

    elif asset_type == ASSET_ENDPOINT:
        if not asset_id:
            raise ToolRunError('asset_id is required for endpoint')
        endpoint = EndPoint.objects.filter(pk=asset_id).first()
        if not endpoint:
            raise ToolRunError('Endpoint not found', 404)
        http_url = endpoint.http_url
        if endpoint.subdomain_id:
            subdomain = endpoint.subdomain
            subdomain_name = subdomain.name
        elif endpoint.scan_history_id == scan.id:
            subdomain_name = scan.domain.name

    elif asset_type in (ASSET_URL, ASSET_HOST):
        if not url and not asset_id:
            raise ToolRunError('url or asset_id is required')
        if asset_type == ASSET_HOST and asset_id:
            subdomain = Subdomain.objects.filter(pk=asset_id).first()
            if subdomain:
                if subdomain.target_domain_id and subdomain.target_domain_id != scan.domain_id:
                    raise ToolRunError('Host/subdomain is outside this scan domain', 400)
                subdomain_name = subdomain.name
                http_url = subdomain.http_url or f'https://{subdomain.name}/'
            else:
                raise ToolRunError('Host/subdomain not found', 404)
        else:
            http_url = url
            subdomain_name = url
            if url and '://' in url:
                from urllib.parse import urlparse
                subdomain_name = urlparse(url).hostname or url
            elif url:
                from urllib.parse import urlparse
                subdomain_name = urlparse(f'https://{url}').hostname or url
            # Free-form url/host must stay under the scan target domain.
            domain_name = scan.domain.name if scan.domain_id else ''
            host = (subdomain_name or '').lower().rstrip('.')
            base = (domain_name or '').lower().rstrip('.')
            if not base or not (host == base or host.endswith('.' + base)):
                raise ToolRunError(
                    f'url host {host or url} is outside scan domain {domain_name}',
                    400,
                )
    else:
        raise ToolRunError(f'Unsupported asset_type: {asset_type}')

    return subdomain, subdomain_name, http_url


def start_pipeline_tool_run(
    *,
    tool: str,
    asset_type: str,
    scan_id: int,
    asset_id: Optional[int] = None,
    url: Optional[str] = None,
    tool_args: Optional[dict] = None,
    user=None,
) -> dict[str, Any]:
    meta = get_pipeline_tool(tool)
    if not meta:
        raise ToolRunError(f'Unknown pipeline tool: {tool}')
    if asset_type not in meta['asset_kinds']:
        raise ToolRunError(
            f'Tool {tool} does not support asset_type={asset_type}; '
            f'allowed={meta["asset_kinds"]}'
        )

    scan = ScanHistory.objects.select_related('domain', 'scan_type').filter(pk=scan_id).first()
    if not scan:
        raise ToolRunError('Scan not found', 404)

    from reNgine.definitions import PAUSED_TASK
    if scan.scan_status in (RUNNING_TASK, PAUSED_TASK):
        raise ToolRunError('Cannot run a singular tool while the scan is running or paused')

    subdomain, subdomain_name, http_url = _resolve_asset(
        asset_type=asset_type,
        asset_id=asset_id,
        url=url,
        scan=scan,
    )

    from reNgine.tool_args import ToolArgsError, merge_yaml_overlay, validate_tool_args
    try:
        validated = validate_tool_args(tool, tool_args)
    except ToolArgsError as exc:
        raise ToolRunError(str(exc), exc.status) from exc

    yaml_cfg = merge_yaml_overlay(_load_yaml(scan), tool, validated.get('yaml_overlay') or {})
    arg_keys = sorted((validated.get('sanitized') or {}).keys())

    retry_name = resolve_retry_task_name(tool)
    from reNgine.task_plan import singular_activity_name
    activity_name = singular_activity_name(retry_name)
    title = meta['title']
    now = timezone.now()
    title_suffix = f' [{", ".join(arg_keys)}]' if arg_keys else ''
    activity = ScanActivity.objects.create(
        scan_of=scan,
        name=activity_name,
        title=f'{title} (singular){title_suffix}'[:500],
        # RUNNING: workflow is started immediately below. For tools like
        # nuclei_scan→vulnerability_scan the child activities track as
        # single_tool_nuclei_scan and never claim this parent row, so leaving
        # it INITIATED would look stuck for the whole run.
        status=RUNNING_TASK,
        time=now,
        time_started=now,
        tier=None,
        target_host=subdomain_name or http_url or '',
    )

    # Persist singular args so timeline retry can restore overlays / extras.
    try:
        import json
        import os
        meta_dir = scan.results_dir or ''
        if meta_dir:
            os.makedirs(meta_dir, exist_ok=True)
            meta_path = os.path.join(meta_dir, f'singular_meta_{activity.id}.json')
            with open(meta_path, 'w', encoding='utf-8') as fh:
                json.dump({
                    'tool': tool,
                    'retry_task_name': retry_name,
                    'sanitized': validated.get('sanitized') or {},
                    'extra_cli_args': validated.get('extra_cli_args') or [],
                    'yaml_overlay': validated.get('yaml_overlay') or {},
                    'subdomain_id': subdomain.id if subdomain else None,
                    'subdomain_name': subdomain_name,
                    'http_url': http_url,
                }, fh)
    except Exception:
        logger.exception('Failed to write singular_meta for activity %s', activity.id)

    original_scan_status = scan.scan_status
    scan.scan_status = RUNNING_TASK
    scan.error_message = None
    scan.save(update_fields=['scan_status', 'error_message'])

    from reNgine.utils.scan_cancellation import set_scan_stop_kill_switch
    set_scan_stop_kill_switch(scan.id, enabled=False)

    ctx = {
        'scan_history_id': scan.id,
        'engine_id': scan.scan_type_id,
        'domain_id': scan.domain_id,
        'results_dir': scan.results_dir,
        'yaml_configuration': yaml_cfg,
        'tasks': [retry_name],
        'original_scan_status': original_scan_status if original_scan_status is not None else SUCCESS_TASK,
        'subdomain_id': subdomain.id if subdomain else None,
        'subdomain_name': subdomain_name,
        'subdomain_http_url': http_url,
        'urls': [http_url] if http_url else [],
        'hosts': [subdomain_name] if subdomain_name else [],
        'singular_tool_run': True,
        'singular_tool_args': validated.get('sanitized') or {},
        'extra_cli_args': validated.get('extra_cli_args') or [],
        'activity_id': activity.id,
        'initiated_by_user_id': getattr(user, 'id', None),
    }

    workflow_id = f"tool-{retry_name}-{scan.id}-{activity.id}-{int(now.timestamp())}"

    async def _start():
        client = await TemporalClientProvider.get_client()
        await client.start_workflow(
            'SingleTaskRetryWorkflow',
            args=[ctx, retry_name],
            id=workflow_id,
            task_queue='python-orchestrator-queue',
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    run_and_close(loop, _start())

    return {
        'status': 'started',
        'workflow_id': workflow_id,
        'activity_id': activity.id,
        'tool': tool,
        'retry_task_name': retry_name,
        'activity_name': activity_name,
        'scan_id': scan.id,
        'asset_type': asset_type,
        'target_host': subdomain_name,
        'http_url': http_url,
        'tool_args': validated.get('sanitized') or {},
    }


def start_workflow_tool_run(
    *,
    workflow_slug: str,
    scan_id: Optional[int],
    url: Optional[str] = None,
    asset_id: Optional[int] = None,
    user=None,
) -> dict[str, Any]:
    from api.views.tools import _WORKFLOW_REGISTRY

    meta = get_workflow_tool(workflow_slug)
    if not meta:
        raise ToolRunError(f'Unknown workflow: {workflow_slug}')
    if workflow_slug not in _WORKFLOW_REGISTRY:
        raise ToolRunError(f'Workflow not registered: {workflow_slug}', 404)

    workflow_name, required_fields = _WORKFLOW_REGISTRY[workflow_slug]
    data: dict[str, Any] = {
        'yaml_configuration': {},
        'scan_history_id': scan_id,
    }

    if 'urls' in required_fields:
        http_url = url
        if not http_url and asset_id:
            ep = EndPoint.objects.filter(pk=asset_id).first()
            if ep:
                http_url = ep.http_url
        if not http_url:
            raise ToolRunError('url is required for this workflow')
        data['urls'] = [http_url]

    if 'domain' in required_fields and scan_id:
        scan = ScanHistory.objects.select_related('domain').filter(pk=scan_id).first()
        if not scan:
            raise ToolRunError('Scan not found', 404)
        data['domain'] = scan.domain.name

    if 'target' in required_fields:
        data['target'] = url or ''
        data['target_type'] = 'host'

    for field in required_fields:
        if field not in data:
            raise ToolRunError(f'Missing required field for workflow: {field}')

    wf_id = f"{workflow_slug}-tool-{getattr(user, 'id', 0)}-{int(timezone.now().timestamp())}"

    async def _start():
        client = await TemporalClientProvider.get_client()
        handle = await client.start_workflow(
            workflow_name,
            data,
            id=wf_id,
            task_queue='python-orchestrator-queue',
        )
        return handle.id

    loop = asyncio.new_event_loop()
    started = run_and_close(loop, _start())
    return {
        'status': 'started',
        'workflow_id': started or wf_id,
        'tool': workflow_slug,
        'kind': 'workflow',
    }
