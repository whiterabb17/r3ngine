import logging
import mimetypes
import os
import threading
import uuid

from django.core.cache import cache
from django.http import Http404
from django.views import View
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response

from .models import Plugin
from .serializers import PluginSerializer
from .utils import AtomicInstaller, PluginManager, MarketplaceManager

logger = logging.getLogger(__name__)

class PluginViewSet(viewsets.ModelViewSet):
    queryset = Plugin.objects.all()
    serializer_class = PluginSerializer
    lookup_field = 'slug'
    pagination_class = None

    def get_permissions(self):
        # Read-only actions (list, retrieve, registry, install-status) require only authentication.
        # All mutating or privileged actions require admin/staff.
        read_only_actions = {'list', 'retrieve', 'registry', 'install_status', 'get_icon', 'get_docs'}
        if self.action in read_only_actions:
            return [IsAuthenticated()]
        return [IsAdminUser()]
    
    MAX_PLUGIN_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

    @action(detail=False, methods=['post'], url_path='upload')
    def upload_plugin(self, request):
        if 'file' not in request.FILES:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        zip_file = request.FILES['file']

        if zip_file.size > self.MAX_PLUGIN_UPLOAD_BYTES:
            return Response({'error': 'File too large (max 50 MB)'}, status=status.HTTP_400_BAD_REQUEST)

        header = zip_file.read(4)
        zip_file.seek(0)
        if header[:2] != b'PK':
            return Response({'error': 'File must be a valid ZIP archive'}, status=status.HTTP_400_BAD_REQUEST)

        PluginManager.ensure_dirs()
        original_name = zip_file.name
        ext = '.r3n' if original_name.endswith('.r3n') else '.zip'
        temp_zip_path = os.path.join(PluginManager.BASE_PLUGINS_DIR, f'upload_{uuid.uuid4().hex[:8]}{ext}')

        with open(temp_zip_path, 'wb+') as destination:
            for chunk in zip_file.chunks():
                destination.write(chunk)

        install_id = uuid.uuid4().hex[:12]
        cache.set(f'plugin:install:{install_id}', {
            'steps': [{'key': 'upload', 'label': 'Saving plugin archive', 'status': 'completed', 'message': ''}],
            'status': 'running',
            'plugin_name': None,
        }, timeout=300)

        def _run_install(path, iid):
            import django.db
            django.db.close_old_connections()
            try:
                AtomicInstaller.install(path, install_id=iid)
            except Exception:
                pass  # AtomicInstaller already writes 'failed' state to cache
            finally:
                if os.path.exists(path):
                    os.remove(path)
                django.db.close_old_connections()

        threading.Thread(target=_run_install, args=(temp_zip_path, install_id), daemon=True).start()

        return Response({'install_id': install_id}, status=status.HTTP_202_ACCEPTED)

    @action(detail=False, methods=['get'], url_path='install-status')
    def install_status(self, request):
        install_id = request.GET.get('id', '')
        if not install_id:
            return Response({'error': 'id parameter required'}, status=status.HTTP_400_BAD_REQUEST)
        data = cache.get(f'plugin:install:{install_id}')
        if data is None:
            return Response({'error': 'install session not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(data)

    def perform_update(self, serializer):
        instance = serializer.save()
        from django.core.cache import cache
        cache.set(f"plugin_{instance.slug}_needs_restart", True, timeout=None)

    @action(detail=False, methods=['post'], url_path='restart-orchestrator')
    def restart_orchestrator(self, request):
        import redis
        from django.conf import settings
        try:
            rdb = redis.StrictRedis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD,
                db=0
            )
            rdb.publish('orchestrator_control', 'restart')
            return Response({'success': True, 'message': 'Restart command sent to orchestrator.'})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'], url_path='restart-server')
    def restart_server(self, request):
        """
        User-triggered restart of the orchestrator and web container after plugin install.
        The web container restart is delayed 3 s so this HTTP response can reach the client
        before the connection is severed.
        """
        import redis
        from django.conf import settings

        try:
            rdb = redis.StrictRedis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD,
                db=0
            )
            rdb.publish('orchestrator_control', 'restart')
        except Exception as e:
            logger.warning("Could not send orchestrator restart signal: %s", e)

        def _restart_web():
            import time
            time.sleep(3)
            try:
                import docker
                client = docker.from_env()
                web_container = client.containers.get('r3ngine-web-1')
                logger.info("User-triggered web container restart.")
                web_container.restart()
            except Exception as _e:
                logger.error("Failed to restart web container: %s", _e)

        threading.Thread(target=_restart_web, daemon=True).start()
        return Response({'success': True, 'message': 'Server restart initiated.'})

    @action(detail=False, methods=['get'], url_path='registry')
    def registry(self, request):
        """Returns the UI component registry for the frontend."""
        active_plugins = Plugin.objects.filter(is_enabled=True)
        registry_data = []
        for plugin in active_plugins:
            # Check for UI components in manifest
            ui_config = plugin.manifest.get('ui', {})
            if ui_config:
                registry_data.append({
                    'slug': plugin.slug,
                    'name': plugin.name,
                    'components': ui_config # Should contain list of {name, file, type}
                })
        return Response(registry_data)

    @action(detail=True, methods=['get'], url_path='docs')
    def get_docs(self, request, slug=None):
        """
        GET /api/plugins/{slug}/docs/
        Reads the markdown files in plugins_data/{slug}/docs/ and returns them.
        """
        plugin = self.get_object()
        docs_dir = os.path.join(PluginManager.BASE_PLUGINS_DIR, plugin.slug, 'docs')
        if not os.path.exists(docs_dir):
            return Response({'error': 'Documentation not found'}, status=status.HTTP_404_NOT_FOUND)

        docs = {}
        for file in os.listdir(docs_dir):
            if file.endswith('.md'):
                try:
                    with open(os.path.join(docs_dir, file), 'r', encoding='utf-8') as f:
                        docs[file] = f.read()
                except Exception as e:
                    logger.error(f"Failed to read doc file {file}: {e}")

        if not docs:
            return Response({'error': 'No markdown files found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(docs)

    @action(detail=True, methods=['get'], url_path='icon')
    def get_icon(self, request, slug=None):
        """Serves the plugin's bundled icon."""
        plugin = self.get_object()
        if not plugin.icon_path:
            return Response({'error': 'No icon configured'}, status=status.HTTP_404_NOT_FOUND)
            
        icon_file_path = os.path.join(PluginManager.BASE_PLUGINS_DIR, plugin.slug, plugin.icon_path)
        
        # Guard against path traversal
        safe_dir = os.path.join(PluginManager.BASE_PLUGINS_DIR, plugin.slug)
        if not os.path.abspath(icon_file_path).startswith(os.path.abspath(safe_dir)):
            raise Http404

        if not os.path.exists(icon_file_path):
            return Response({'error': 'Icon file not found'}, status=status.HTTP_404_NOT_FOUND)
            
        content_type, _ = mimetypes.guess_type(icon_file_path)
        from django.http import HttpResponse
        with open(icon_file_path, 'rb') as f:
            return HttpResponse(f.read(), content_type=content_type or 'application/octet-stream')

    @action(detail=False, methods=['get'], url_path='marketplace')
    def marketplace(self, request):
        """Returns available plugins from the marketplace."""
        force_refresh = request.query_params.get('refresh', 'false').lower() == 'true'
        plugins = MarketplaceManager.get_available_plugins(force_refresh=force_refresh)
        return Response(plugins)

    @action(detail=False, methods=['post'], url_path='marketplace/install')
    def marketplace_install(self, request):
        """
        Installs a plugin from the marketplace using an async background thread,
        identical to the upload flow. Returns an install_id immediately (HTTP 202)
        so the frontend InstallProgressOverlay can poll for real-time progress.
        """
        slug = request.data.get('slug')
        if not slug:
            return Response({'error': 'No slug provided'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a tracking ID and seed the cache entry
        install_id = uuid.uuid4().hex[:12]
        cache.set(f'plugin:install:{install_id}', {
            'steps': [{'key': 'upload', 'label': 'Downloading plugin archive', 'status': 'in_progress', 'message': ''}],
            'status': 'running',
            'plugin_name': None,
        }, timeout=300)

        def _run_marketplace_install(slug, iid):
            """
            Background thread: downloads the .r3n archive from the marketplace
            and hands off to AtomicInstaller (which handles all further progress
            emissions, DB backup, migrations, and asset installation).
            """
            import django.db
            django.db.close_old_connections()
            temp_zip_path = None
            try:
                # Step 1: Download from marketplace
                temp_zip_path = MarketplaceManager.download_plugin(slug)

                # Mark the download step complete before handing to installer
                data = cache.get(f'plugin:install:{iid}') or {}
                steps = data.get('steps', [])
                for s in steps:
                    if s['key'] == 'upload':
                        s['status'] = 'completed'
                        s['message'] = 'Archive downloaded successfully'
                data['steps'] = steps
                cache.set(f'plugin:install:{iid}', data, timeout=300)

                # Step 2: Full atomic install with progress tracking
                AtomicInstaller.install(temp_zip_path, install_id=iid)
            except Exception:
                # AtomicInstaller writes failed state; handle download failures here
                data = cache.get(f'plugin:install:{iid}') or {'steps': [], 'status': 'running'}
                for s in data.get('steps', []):
                    if s.get('status') == 'in_progress':
                        s['status'] = 'failed'
                import traceback
                data['status'] = 'failed'
                data['error'] = traceback.format_exc().splitlines()[-1]
                cache.set(f'plugin:install:{iid}', data, timeout=300)
            finally:
                if temp_zip_path and os.path.exists(temp_zip_path):
                    os.remove(temp_zip_path)
                django.db.close_old_connections()

        threading.Thread(target=_run_marketplace_install, args=(slug, install_id), daemon=True).start()

        return Response({'install_id': install_id}, status=status.HTTP_202_ACCEPTED)

    @action(detail=False, methods=['post'], url_path='marketplace/refresh')
    def marketplace_refresh(self, request):
        """Force refreshes the marketplace cache."""
        plugins = MarketplaceManager.get_available_plugins(force_refresh=True)
        return Response(plugins)


class PluginUIView(View):
    """Serves built plugin UI assets from plugins_data/{slug}/ui/dist/."""

    def get(self, request, slug, path):
        ui_dir = os.path.join(PluginManager.BASE_PLUGINS_DIR, slug, 'ui')
        file_path = os.path.normpath(os.path.join(ui_dir, path))

        # Guard against path traversal
        if not file_path.startswith(os.path.abspath(ui_dir)):
            raise Http404

        if not os.path.isfile(file_path):
            raise Http404

        content_type, _ = mimetypes.guess_type(file_path)
        from django.http import HttpResponse
        with open(file_path, 'rb') as f:
            return HttpResponse(f.read(), content_type=content_type or 'application/octet-stream')
