from django.contrib import admin
from .models import (
    Client, Engagement, Assessment, AssessmentScope, 
    AssessmentAsset, AssessmentWorkflowState, AssessmentEvent
)

@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ('name', 'status', 'created_by', 'created_at')
    search_fields = ('name', 'email')
    list_filter = ('status',)

@admin.register(Engagement)
class EngagementAdmin(admin.ModelAdmin):
    list_display = ('name', 'client', 'engagement_type', 'status', 'start_date', 'end_date')
    search_fields = ('name', 'client__name')
    list_filter = ('status', 'engagement_type')

@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'engagement', 'assessment_type', 'status', 'started_at')
    search_fields = ('name', 'engagement__name')
    list_filter = ('status', 'assessment_type')

@admin.register(AssessmentScope)
class AssessmentScopeAdmin(admin.ModelAdmin):
    list_display = ('value', 'scope_type', 'assessment', 'status')
    search_fields = ('value',)
    list_filter = ('scope_type', 'status')

@admin.register(AssessmentAsset)
class AssessmentAssetAdmin(admin.ModelAdmin):
    list_display = ('assessment', 'content_type', 'object_id')
    search_fields = ('assessment__name',)

@admin.register(AssessmentWorkflowState)
class AssessmentWorkflowStateAdmin(admin.ModelAdmin):
    list_display = ('assessment', 'current_stage', 'progress_percent', 'workflow_id')
    search_fields = ('assessment__name', 'workflow_id')
    list_filter = ('current_stage',)

@admin.register(AssessmentEvent)
class AssessmentEventAdmin(admin.ModelAdmin):
    list_display = ('assessment', 'event_type', 'timestamp', 'user')
    search_fields = ('assessment__name', 'event_type')
    list_filter = ('event_type',)
