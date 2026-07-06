"""Evidence REST API serializers."""
from rest_framework import serializers
from .models import Evidence, EvidenceCollection, EvidenceEvent, EvidenceAnnotation, EvidenceRetentionPolicy


class EvidenceEventSerializer(serializers.ModelSerializer):
    """Chain-of-custody event serializer (read-only)."""
    actor_username = serializers.CharField(source='actor.username', read_only=True, allow_null=True)

    class Meta:
        model = EvidenceEvent
        fields = ['id', 'event_type', 'actor_username', 'note', 'hash_at_event', 'timestamp', 'ip_address']
        read_only_fields = fields


class EvidenceAnnotationSerializer(serializers.ModelSerializer):
    """Evidence annotation serializer."""
    author_username = serializers.CharField(source='author.username', read_only=True, allow_null=True)

    class Meta:
        model = EvidenceAnnotation
        fields = ['id', 'annotation_type', 'content', 'region', 'author_username', 'created_at', 'updated_at']
        read_only_fields = ['author_username', 'created_at', 'updated_at']


class EvidenceSerializer(serializers.ModelSerializer):
    """Full evidence item serializer with chain-of-custody events and annotations."""
    events      = EvidenceEventSerializer(many=True, read_only=True)
    annotations = EvidenceAnnotationSerializer(many=True, read_only=True)
    collected_by_username = serializers.CharField(source='collected_by.username', read_only=True, allow_null=True)
    file_size_mb = serializers.FloatField(read_only=True)
    download_url = serializers.SerializerMethodField()
    vulnerability_ids = serializers.PrimaryKeyRelatedField(
        source='vulnerabilities', many=True, read_only=True
    )

    class Meta:
        model = Evidence
        fields = [
            'uuid', 'collection', 'evidence_type', 'title', 'description',
            'file_name', 'file_size', 'file_size_mb', 'mime_type', 'sha256_hash',
            'status', 'collected_at', 'collected_by_username', 'created_at', 'updated_at',
            'download_url', 'vulnerability_ids',
            'events', 'annotations',
        ]
        read_only_fields = [
            'uuid', 'sha256_hash', 'file_size', 'file_size_mb', 'mime_type',
            'collected_by_username', 'created_at', 'updated_at', 'download_url',
        ]

    def get_download_url(self, obj) -> str:
        """Return the server-relative download URL."""
        if obj.file_path:
            return f"/api/evidence/{obj.uuid}/download/"
        return ''


class EvidenceListSerializer(serializers.ModelSerializer):
    """Lightweight list serializer without nested events/annotations."""
    file_size_mb = serializers.FloatField(read_only=True)
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = Evidence
        fields = [
            'uuid', 'evidence_type', 'title', 'file_name', 'file_size_mb',
            'mime_type', 'status', 'collected_at', 'created_at', 'download_url',
        ]

    def get_download_url(self, obj) -> str:
        if obj.file_path:
            return f"/api/evidence/{obj.uuid}/download/"
        return ''


class EvidenceRetentionPolicySerializer(serializers.ModelSerializer):
    """Retention policy serializer."""
    class Meta:
        model = EvidenceRetentionPolicy
        fields = [
            'id', 'archive_after_days', 'purge_after_days',
            'purge_files', 'last_enforced_at', 'next_action_at',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['last_enforced_at', 'next_action_at', 'created_at', 'updated_at']


class EvidenceCollectionSerializer(serializers.ModelSerializer):
    """Evidence collection serializer with item count and retention policy."""
    item_count = serializers.SerializerMethodField()
    retention_policy = EvidenceRetentionPolicySerializer(read_only=True)

    class Meta:
        model = EvidenceCollection
        fields = [
            'uuid', 'assessment', 'scan_history', 'name', 'status',
            'item_count', 'retention_policy', 'created_at', 'updated_at',
        ]
        read_only_fields = ['uuid', 'created_at', 'updated_at']

    def get_item_count(self, obj) -> int:
        return obj.evidence_items.filter(status='Active').count()


class EvidenceUploadSerializer(serializers.Serializer):
    """Serializer for uploading a new evidence file via the API."""
    file          = serializers.FileField(help_text='The evidence file to upload.')
    title         = serializers.CharField(max_length=512)
    description   = serializers.CharField(required=False, allow_blank=True, default='')
    evidence_type = serializers.ChoiceField(
        choices=[
            'Screenshot', 'NetworkCapture', 'RequestResponse',
            'CommandOutput', 'Log', 'Report', 'Other'
        ]
    )
    collection_uuid     = serializers.UUIDField(help_text='UUID of the EvidenceCollection to add to.')
    vulnerability_ids   = serializers.ListField(child=serializers.IntegerField(), required=False, default=list)
    scope_ids           = serializers.ListField(child=serializers.IntegerField(), required=False, default=list)
