import os
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path, re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from reNgine import views as rengine_views
from reNgine.stress import views as stress_views
from dashboard import views as dashboard_views
from plugins.views import PluginUIView
from .openapi_info import info

schema_view = get_schema_view(
   info,
   public=False,
   permission_classes=[permissions.IsAuthenticated],
)

urlpatterns = [
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path(
        os.environ.get('DJANGO_ADMIN_URL', 'admin') + '/',
        admin.site.urls),
    path(
        'api/',
        include(
            'api.urls',
            'api')),
    path(
        'mapi/',
        include(
            'api.urls',
            'mapi')),
    path(
        'api/engagements/',
        include('engagements.urls')),
    path(
        'target/',
        include('targetApp.urls')),
    path(
        'scanEngine/',
        include('scanEngine.urls')),
    path(
        'scan/',
        include('startScan.urls')),
    path(
        'recon_note/',
        include('recon_note.urls')),
    path(
        'login/',
        dashboard_views.login_v3,
        name='login'),
    path(
        'logout/',
        dashboard_views.logout_v3,
        name='logout'),
    path(
        'api/stress/<int:scan_id>/control/',
        stress_views.StressTestControlAPI.as_view(),
        name='stress_test_control'
    ),
    path(
        'api/stress/<int:scan_id>/status/',
        stress_views.StressTestStatusAPI.as_view(),
        name='stress_test_status'
    ),
    path(
        'api/stress/<int:scan_id>/report/',
        stress_views.StressReportGenerationAPI.as_view(),
        name='stress_report_generation'
    ),
    path(
        'media/<path:path>',
        rengine_views.serve_protected_media,
        name='serve_protected_media'
    ),
    path(
        'plugins-ui/<slug:slug>/<path:path>',
        PluginUIView.as_view(),
        name='plugin_ui'
    ),
    # Dashboard include last — contains the SPA catch-all as its final pattern,
    # so all more-specific routes above are matched first.
    path(
        '',
        include('dashboard.urls')),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
