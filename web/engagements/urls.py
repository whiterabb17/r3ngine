from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ClientViewSet, EngagementViewSet, AssessmentViewSet,
    AssessmentScopeViewSet, AssessmentAssetViewSet
)

router = DefaultRouter()
router.register(r'clients', ClientViewSet, basename='client')
router.register(r'engagements', EngagementViewSet, basename='engagement')
router.register(r'assessments', AssessmentViewSet, basename='assessment')
router.register(r'scopes', AssessmentScopeViewSet, basename='assessment-scope')
router.register(r'assets', AssessmentAssetViewSet, basename='assessment-asset')

urlpatterns = [
    path('', include(router.urls)),
]
