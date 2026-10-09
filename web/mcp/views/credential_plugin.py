"""MCP wrappers for Credential Intelligence (gated)."""
from __future__ import annotations

import logging

from rest_framework import status
from rest_framework.response import Response

from mcp.plugins_gate import gate_plugin
from mcp.views.base import McpDataView
from mcp.views.dispatch import McpIntelDispatchView

logger = logging.getLogger(__name__)

SLUG = 'credential_intelligence'
BACKEND = 'plugins_data.credential_intelligence.backend'


def _redact_credential(data: dict) -> dict:
    out = dict(data)
    if out.get('password'):
        out['password'] = '[redacted]'
        out['has_password'] = True
    else:
        out['has_password'] = False
    if out.get('hash_value'):
        out['hash_value'] = '[redacted]'
        out['has_hash'] = True
    else:
        out['has_hash'] = False
    return out


def _redact_cracked(data: dict) -> dict:
    out = dict(data)
    if out.get('plaintext'):
        out['plaintext'] = '[redacted]'
        out['has_plaintext'] = True
    else:
        out['has_plaintext'] = False
    return out


def _paginate(qs, request, limit_default=50):
    try:
        limit = min(int(request.query_params.get('limit', limit_default)), 200)
    except (TypeError, ValueError):
        limit = limit_default
    try:
        offset = max(int(request.query_params.get('offset', 0)), 0)
    except (TypeError, ValueError):
        offset = 0
    total = qs.count()
    return total, qs[offset:offset + limit]


class McpCredListTasksView(McpDataView):
    def get(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.credential_intelligence.backend.models import CredentialTask
        from plugins_data.credential_intelligence.backend.serializers import (
            CredentialTaskSerializer,
        )

        qs = CredentialTask.objects.all().order_by('-created_at')
        status_f = request.query_params.get('status')
        tool = request.query_params.get('tool')
        if status_f:
            qs = qs.filter(status=status_f)
        if tool:
            qs = qs.filter(tool=tool)
        total, page = _paginate(qs, request)
        data = CredentialTaskSerializer(page, many=True).data
        # Nested credentials may include secrets — redact
        for item in data:
            creds = item.get('discovered_credentials') or []
            item['discovered_credentials'] = [_redact_credential(c) for c in creds]
        return Response({'count': total, 'results': data})


class McpCredGetTaskView(McpDataView):
    def get(self, request, pk):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.credential_intelligence.backend.models import CredentialTask
        from plugins_data.credential_intelligence.backend.serializers import (
            CredentialTaskSerializer,
        )

        try:
            task = CredentialTask.objects.get(pk=pk)
        except CredentialTask.DoesNotExist:
            return Response({'error': f'Credential task {pk} not found.'}, status=404)
        data = CredentialTaskSerializer(task).data
        creds = data.get('discovered_credentials') or []
        data['discovered_credentials'] = [_redact_credential(c) for c in creds]
        return Response(data)


class McpCredStartTaskView(McpIntelDispatchView):
    """Create a credential task and optionally execute it."""

    def post(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.credential_intelligence.backend.api import CredentialTaskViewSet
        from plugins_data.credential_intelligence.backend.models import CredentialTask
        from plugins_data.credential_intelligence.backend.serializers import (
            CredentialTaskSerializer,
        )

        name = request.data.get('name')
        tool = request.data.get('tool')
        target = request.data.get('target')
        if not name or not tool or not target:
            return Response(
                {'error': 'name, tool, and target are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        allowed_tools = {'brutus', 'netexec', 'kerbrute', 'hashcat'}
        if tool not in allowed_tools:
            return Response(
                {'error': f'tool must be one of {sorted(allowed_tools)}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        payload = {
            'name': name,
            'tool': tool,
            'target': target,
            'protocol': request.data.get('protocol'),
            'wordlist_user': request.data.get('wordlist_user'),
            'wordlist_pass': request.data.get('wordlist_pass'),
            'threads': request.data.get('threads', 5),
            'additional_flags': request.data.get('additional_flags'),
            'scan_history': request.data.get('scan_id') or request.data.get('scan_history'),
            'target_domain': request.data.get('domain_id') or request.data.get('target_domain'),
        }
        serializer = CredentialTaskSerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        task = serializer.save()

        auto_start = request.data.get('auto_start', True)
        if isinstance(auto_start, str):
            auto_start = auto_start.lower() not in ('0', 'false', 'no')

        started = None
        if auto_start:
            viewset = CredentialTaskViewSet()
            viewset.request = request
            viewset.format_kwarg = None
            viewset.kwargs = {'pk': task.pk}
            start_response = viewset.execute(request, pk=task.pk)
            started = start_response.data
            task.refresh_from_db()
            if start_response.status_code >= 400:
                return Response({
                    'task': CredentialTaskSerializer(task).data,
                    'start_error': started,
                }, status=start_response.status_code)

        data = CredentialTaskSerializer(task).data
        data['discovered_credentials'] = []
        return Response({
            'task': data,
            'started': started,
        }, status=status.HTTP_201_CREATED)


class McpCredListCredentialsView(McpDataView):
    def get(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.credential_intelligence.backend.models import DiscoveredCredential
        from plugins_data.credential_intelligence.backend.serializers import (
            DiscoveredCredentialSerializer,
        )

        qs = DiscoveredCredential.objects.all().order_by('-discovered_at')
        task_id = request.query_params.get('task_id')
        service = request.query_params.get('service')
        if task_id:
            qs = qs.filter(task_id=task_id)
        if service:
            qs = qs.filter(service=service)
        total, page = _paginate(qs, request)
        data = [_redact_credential(c) for c in DiscoveredCredentialSerializer(page, many=True).data]
        return Response({
            'count': total,
            'results': data,
            'note': 'password/hash_value values are redacted for MCP; use the UI for secrets.',
        })


class McpCredListCrackingView(McpDataView):
    def get(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.credential_intelligence.backend.models import HashCrackingTask
        from plugins_data.credential_intelligence.backend.serializers import (
            HashCrackingTaskSerializer,
        )

        qs = HashCrackingTask.objects.all().order_by('-created_at')
        status_f = request.query_params.get('status')
        if status_f:
            qs = qs.filter(status=status_f)
        total, page = _paginate(qs, request)
        data = HashCrackingTaskSerializer(page, many=True).data
        for item in data:
            cracked = item.get('cracked_hashes') or []
            item['cracked_hashes'] = [_redact_cracked(c) for c in cracked]
            # Don't dump huge hash lists into MCP by default
            if item.get('hashes_txt') and len(item['hashes_txt']) > 500:
                item['hashes_txt'] = item['hashes_txt'][:500] + '…'
                item['hashes_truncated'] = True
        return Response({'count': total, 'results': data})


class McpCredGetCrackingView(McpDataView):
    def get(self, request, pk):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.credential_intelligence.backend.models import HashCrackingTask
        from plugins_data.credential_intelligence.backend.serializers import (
            HashCrackingTaskSerializer,
        )

        try:
            task = HashCrackingTask.objects.get(pk=pk)
        except HashCrackingTask.DoesNotExist:
            return Response({'error': f'Hash cracking task {pk} not found.'}, status=404)
        data = HashCrackingTaskSerializer(task).data
        data['cracked_hashes'] = [_redact_cracked(c) for c in (data.get('cracked_hashes') or [])]
        return Response(data)


class McpCredStartCrackingView(McpIntelDispatchView):
    def post(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.credential_intelligence.backend.cracking_views import (
            HashCrackingTaskViewSet,
        )
        from plugins_data.credential_intelligence.backend.serializers import (
            HashCrackingTaskSerializer,
        )

        name = request.data.get('name')
        hashes_txt = request.data.get('hashes_txt')
        if not name or not hashes_txt:
            return Response(
                {'error': 'name and hashes_txt are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        payload = {
            'name': name,
            'hashes_txt': hashes_txt,
            'hash_type': request.data.get('hash_type', 1000),
            'attack_mode': request.data.get('attack_mode', 0),
            'wordlist': request.data.get('wordlist'),
            'mask': request.data.get('mask'),
            'custom_rules': request.data.get('custom_rules'),
            'workload_profile': request.data.get('workload_profile', 2),
            'force': request.data.get('force', True),
        }
        serializer = HashCrackingTaskSerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        task = serializer.save()

        auto_start = request.data.get('auto_start', True)
        if isinstance(auto_start, str):
            auto_start = auto_start.lower() not in ('0', 'false', 'no')

        started = None
        if auto_start:
            viewset = HashCrackingTaskViewSet()
            viewset.request = request
            viewset.format_kwarg = None
            viewset.kwargs = {'pk': task.pk}
            start_response = viewset.execute(request, pk=task.pk)
            started = start_response.data
            task.refresh_from_db()
            if start_response.status_code >= 400:
                return Response({
                    'task': HashCrackingTaskSerializer(task).data,
                    'start_error': started,
                }, status=start_response.status_code)

        data = HashCrackingTaskSerializer(task).data
        data['cracked_hashes'] = []
        return Response({'task': data, 'started': started}, status=status.HTTP_201_CREATED)
