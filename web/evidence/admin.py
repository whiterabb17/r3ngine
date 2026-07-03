"""Evidence admin registration."""
from django.contrib import admin
from .models import Evidence, EvidenceCollection, EvidenceEvent, EvidenceAnnotation, EvidenceRetentionPolicy


class EvidenceEventInline(admin.TabularInline):
    model = EvidenceEvent
    extra = 0
    readonly_fields = ('event_type', 'actor', 'note', 'hash_at_event', 'timestamp', 'ip_address')
    can_delete = False


class EvidenceAnnotationInline(admin.TabularInline):
    model = EvidenceAnnotation
    extra = 0
    readonly_fields = ('author', 'annotation_type', 'content', 'region', 'created_at')
    can_delete = False


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ('uuid', 'title', 'evidence_type', 'status', 'file_size', 'collected_at')
    list_filter = ('evidence_type', 'status')
    search_fields = ('title', 'description', 'sha256_hash')
    readonly_fields = ('uuid', 'sha256_hash', 'file_size', 'mime_type', 'created_at', 'updated_at')
    inlines = [EvidenceEventInline, EvidenceAnnotationInline]


@admin.register(EvidenceCollection)
class EvidenceCollectionAdmin(admin.ModelAdmin):
    list_display = ('uuid', 'name', 'assessment', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('name',)
    readonly_fields = ('uuid', 'created_at', 'updated_at')


@admin.register(EvidenceRetentionPolicy)
class EvidenceRetentionPolicyAdmin(admin.ModelAdmin):
    list_display = ('collection', 'archive_after_days', 'purge_after_days', 'next_action_at')
    list_filter = ('purge_files',)
