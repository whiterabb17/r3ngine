from django.urls import path

from copilot.views import (
    CopilotChatAPIView,
    CopilotModelsAPIView,
    CopilotProposalApproveAPIView,
    CopilotProposalListCreateAPIView,
    CopilotProposalRejectAPIView,
    CopilotSessionDetailAPIView,
    CopilotSessionListCreateAPIView,
    CopilotSettingsAPIView,
    CopilotStatusAPIView,
    CopilotTraceDetailAPIView,
    CopilotTraceListAPIView,
    MsfAuxAbortAPIView,
    MsfAuxDetailAPIView,
    MsfAuxListAPIView,
)

urlpatterns = [
    path('status/', CopilotStatusAPIView.as_view()),
    path('settings/', CopilotSettingsAPIView.as_view()),
    path('models/', CopilotModelsAPIView.as_view()),
    path('sessions/', CopilotSessionListCreateAPIView.as_view()),
    path('sessions/<int:pk>/', CopilotSessionDetailAPIView.as_view()),
    path('chat/', CopilotChatAPIView.as_view()),
    path('proposals/', CopilotProposalListCreateAPIView.as_view()),
    path('proposals/<int:pk>/approve/', CopilotProposalApproveAPIView.as_view()),
    path('proposals/<int:pk>/reject/', CopilotProposalRejectAPIView.as_view()),
    path('trace/', CopilotTraceListAPIView.as_view()),
    path('trace/<int:pk>/', CopilotTraceDetailAPIView.as_view()),
    path('msf-aux/', MsfAuxListAPIView.as_view()),
    path('msf-aux/<int:pk>/', MsfAuxDetailAPIView.as_view()),
    path('msf-aux/<int:pk>/abort/', MsfAuxAbortAPIView.as_view()),
]
