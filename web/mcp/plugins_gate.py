"""Gate MCP plugin tools on installed + enabled Plugin rows and backend import."""
from __future__ import annotations

import importlib
from typing import Any, Optional

from rest_framework.exceptions import NotFound
from rest_framework.response import Response

from plugins.models import Plugin


class McpPluginUnavailable(NotFound):
    """Raised when a plugin is missing, disabled, or its backend cannot be imported."""

    default_code = 'plugin_unavailable'

    def __init__(
        self,
        slug: str,
        *,
        reason: str = 'plugin_not_installed',
        detail: Optional[str] = None,
    ):
        self.slug = slug
        self.reason = reason
        message = detail or {
            'plugin_not_installed': f'Plugin "{slug}" is not installed.',
            'plugin_disabled': f'Plugin "{slug}" is installed but disabled.',
            'plugin_backend_missing': (
                f'Plugin "{slug}" is enabled but its backend is not importable.'
            ),
        }.get(reason, f'Plugin "{slug}" is unavailable.')
        super().__init__(detail={
            'error': message,
            'reason': reason,
            'slug': slug,
        })


def mcp_tools_from_manifest(manifest: Any) -> list[str]:
    if not isinstance(manifest, dict):
        return []
    mcp = manifest.get('mcp') or {}
    if not isinstance(mcp, dict):
        return []
    tools = mcp.get('tools') or []
    if not isinstance(tools, list):
        return []
    return [str(t) for t in tools if t]


def serialize_plugin(plugin: Plugin) -> dict[str, Any]:
    return {
        'slug': plugin.slug,
        'name': plugin.name,
        'version': plugin.version,
        'description': plugin.description or '',
        'is_enabled': plugin.is_enabled,
        'author': plugin.author or '',
        'mcp_tools': mcp_tools_from_manifest(plugin.manifest),
    }


def list_enabled_plugins() -> list[dict[str, Any]]:
    return [
        serialize_plugin(p)
        for p in Plugin.objects.filter(is_enabled=True).order_by('slug')
    ]


def get_enabled_plugin(slug: str) -> Plugin:
    try:
        plugin = Plugin.objects.get(slug=slug)
    except Plugin.DoesNotExist as exc:
        raise McpPluginUnavailable(slug, reason='plugin_not_installed') from exc
    if not plugin.is_enabled:
        raise McpPluginUnavailable(slug, reason='plugin_disabled')
    return plugin


def require_plugin(slug: str, *, backend_module: Optional[str] = None) -> Plugin:
    """Return the enabled Plugin row, optionally verifying backend importability."""
    plugin = get_enabled_plugin(slug)
    module_name = backend_module or f'plugins_data.{slug}.backend'
    try:
        importlib.import_module(module_name)
    except ImportError as exc:
        raise McpPluginUnavailable(slug, reason='plugin_backend_missing') from exc
    return plugin


def gate_plugin(slug: str, *, backend_module: Optional[str] = None) -> Optional[Response]:
    """Return a 404 Response if the plugin is unavailable, else None."""
    try:
        require_plugin(slug, backend_module=backend_module)
        return None
    except McpPluginUnavailable as exc:
        return plugin_unavailable_response(exc)


def plugin_unavailable_response(exc: McpPluginUnavailable) -> Response:
    return Response(exc.detail, status=404)
