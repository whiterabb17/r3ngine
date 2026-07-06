import os
from django.core.asgi import get_asgi_application

# Initialize Django ASGI application early to ensure that all apps and
# settings are fully loaded before importing custom routing modules,
# middleware, or consumers that might reference models or settings.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
django_asgi_app = get_asgi_application()

from django.urls import re_path
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from reNgine.consumers import StressTelemetryConsumer, ScanLogConsumer, AssessmentEventConsumer
from reNgine.middleware import JWTAuthMiddleware


websocket_urlpatterns = [
    re_path(r'ws/stress/(?P<scan_id>\d+)/$', StressTelemetryConsumer.as_asgi()),
    re_path(r'ws/logs/(?P<scan_id>\d+)/$', ScanLogConsumer.as_asgi()),
    re_path(r'ws/assessments/(?P<assessment_id>[\w-]+)/$', AssessmentEventConsumer.as_asgi()),
]

# Dynamic plugin WebSocket consumer discovery
# Plugin consumers.py must declare WEBSOCKET_URLPATTERNS = [(pattern, ClassName), ...]
import importlib
import os as _os
from django.conf import settings as _settings

_plugins_data_dir = _os.path.join(_settings.BASE_DIR, 'plugins_data')
if _os.path.exists(_plugins_data_dir):
    for _plugin_slug in _os.listdir(_plugins_data_dir):
        _consumers_module_path = f"plugins_data.{_plugin_slug}.backend.consumers"
        try:
            _mod = importlib.import_module(_consumers_module_path)
            for _pattern, _cls_name in getattr(_mod, 'WEBSOCKET_URLPATTERNS', []):
                _consumer_cls = getattr(_mod, _cls_name)
                websocket_urlpatterns.append(
                    re_path(_pattern, _consumer_cls.as_asgi()))
        except ImportError:
            pass
        except Exception as _e:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                f"Failed to load plugin WebSocket consumers for {_plugin_slug}: {_e}")

application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        JWTAuthMiddleware(
            URLRouter(
                websocket_urlpatterns
            )
        )
    ),
    "lifespan": "auto",
})

