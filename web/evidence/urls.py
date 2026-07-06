"""Evidence app URL routing."""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import EvidenceCollectionViewSet, EvidenceViewSet, EvidenceUploadView

router = DefaultRouter()
router.register('collections', EvidenceCollectionViewSet, basename='evidence-collection')
router.register('', EvidenceViewSet, basename='evidence')

urlpatterns = [
    path('upload/', EvidenceUploadView.as_view(), name='evidence-upload'),
    path('', include(router.urls)),
]
