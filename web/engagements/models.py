import uuid
from django.db import models
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey

class Client(models.Model):
    STATUS_CHOICES = (
        ('Active', 'Active'),
        ('Inactive', 'Inactive'),
        ('Archived', 'Archived'),
    )

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    primary_contact = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=50, blank=True, null=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Active')
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_clients')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class Engagement(models.Model):
    ENGAGEMENT_TYPES = (
        ('Penetration Test', 'Penetration Test'),
        ('Vulnerability Assessment', 'Vulnerability Assessment'),
        ('Attack Surface Review', 'Attack Surface Review'),
        ('API Assessment', 'API Assessment'),
        ('AD Assessment', 'AD Assessment'),
        ('Hybrid Assessment', 'Hybrid Assessment'),
    )
    STATUS_CHOICES = (
        ('Draft', 'Draft'),
        ('Scheduled', 'Scheduled'),
        ('Active', 'Active'),
        ('Paused', 'Paused'),
        ('Completed', 'Completed'),
        ('Archived', 'Archived'),
    )

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='engagements')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    engagement_type = models.CharField(max_length=100, choices=ENGAGEMENT_TYPES)
    
    start_date = models.DateField(blank=True, null=True)
    end_date = models.DateField(blank=True, null=True)
    sla_due_date = models.DateField(blank=True, null=True)
    
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Draft')
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_engagements')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class Assessment(models.Model):
    ASSESSMENT_TYPES = (
        ('External', 'External'),
        ('Internal', 'Internal'),
        ('Web', 'Web'),
        ('API', 'API'),
        ('Mobile', 'Mobile'),
        ('Cloud', 'Cloud'),
        ('AD', 'AD'),
        ('Hybrid', 'Hybrid'),
    )
    STATUS_CHOICES = (
        ('Draft', 'Draft'),
        ('Ready', 'Ready'),
        ('Discovery', 'Discovery'),
        ('Enumeration', 'Enumeration'),
        ('Analysis', 'Analysis'),
        ('Correlation', 'Correlation'),
        ('Validation', 'Validation'),
        ('GraphSync', 'GraphSync'),
        ('Reporting', 'Reporting'),
        ('Review', 'Review'),
        ('Complete', 'Complete'),
        ('Failed', 'Failed'),
        ('Cancelled', 'Cancelled'),
    )

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='assessments')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    assessment_type = models.CharField(max_length=100, choices=ASSESSMENT_TYPES)
    
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Draft')
    
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    
    active_duration = models.DurationField(blank=True, null=True)
    paused_duration = models.DurationField(blank=True, null=True)
    total_duration = models.DurationField(blank=True, null=True)
    
    preferred_engine = models.ForeignKey(
        'scanEngine.EngineType',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assessments',
        help_text='Override engine; defaults to assessment-type default engine if unset.'
    )

    RETENTION_CHOICES = [
        (90, '90 Days'),
        (180, '180 Days'),
        (365, '1 Year'),
        (0, 'Forever'),
    ]
    retention_days = models.IntegerField(
        choices=RETENTION_CHOICES,
        default=365,
        help_text='How long evidence for this assessment is retained before archiving.'
    )

    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_assessments')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class AssessmentScope(models.Model):
    SCOPE_TYPES = (
        ('Domain', 'Domain'),
        ('Subdomain', 'Subdomain'),
        ('CIDR', 'CIDR'),
        ('IP', 'IP'),
        ('URL', 'URL'),
        ('Application', 'Application'),
        ('Cloud Asset', 'Cloud Asset'),
    )
    STATUS_CHOICES = (
        ('In Scope', 'In Scope'),
        ('Out Of Scope', 'Out Of Scope'),
        ('Excluded', 'Excluded'),
    )

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='scopes')
    scope_type = models.CharField(max_length=50, choices=SCOPE_TYPES)
    value = models.CharField(max_length=500)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='In Scope')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.scope_type}: {self.value}"

class AssessmentAsset(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='assets')
    
    # Generic relation to targetApp/startScan models (Domain, Subdomain, EndPoint, IpAddress, Technology)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    asset = GenericForeignKey('content_type', 'object_id')
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('assessment', 'content_type', 'object_id')

    def __str__(self):
        return f"{self.assessment.name} - {self.asset}"

class AssessmentWorkflowState(models.Model):
    assessment = models.OneToOneField(Assessment, on_delete=models.CASCADE, related_name='workflow_state')
    workflow_id = models.CharField(max_length=255, blank=True, null=True)
    run_id = models.CharField(max_length=255, blank=True, null=True)
    current_stage = models.CharField(max_length=100, blank=True, null=True)
    progress_percent = models.PositiveIntegerField(default=0)
    asset_count = models.PositiveIntegerField(default=0)
    finding_count = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"State for {self.assessment.name}: {self.current_stage} ({self.progress_percent}%)"

class AssessmentEvent(models.Model):
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='events')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assessment_events')
    event_type = models.CharField(max_length=100)
    event_data = models.JSONField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Event {self.event_type} on {self.assessment.name}"

class Asset(models.Model):
    """Canonical assessment-scoped attack-surface asset.

    Dedup key: sha256(assessment.uuid.hex || ':' || normalized_identifier).
    See docs/superpowers/plans/2026-07-05-phases-5-6-neo4j-and-correlation.md
    §4.5 for normalization rules.
    """
    ASSET_TYPE_CHOICES = (
        ('VPN Gateway', 'VPN Gateway'),
        ('Remote Access Protocol', 'Remote Access Protocol'),
        ('Identity & SSO', 'Identity & SSO'),
        ('Database', 'Database'),
        ('Admin Portal', 'Admin Portal'),
        ('CI/CD & Automation', 'CI/CD & Automation'),
        ('Container / Orchestration', 'Container / Orchestration'),
        ('Source Code Repository', 'Source Code Repository'),
        ('Cloud Storage', 'Cloud Storage'),
        ('Email Server', 'Email Server'),
        ('File Sharing', 'File Sharing'),
        ('Message Queue', 'Message Queue'),
        ('API Endpoint', 'API Endpoint'),
        ('Staging / Dev', 'Staging / Dev'),
        ('WAF / Edge', 'WAF / Edge'),
        ('VoIP / Communication', 'VoIP / Communication'),
        ('Web Application', 'Web Application'),
        ('Application', 'Application'),
        ('Unclassified Asset', 'Unclassified Asset'),
    )

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    assessment = models.ForeignKey(
        Assessment, on_delete=models.CASCADE, related_name='canonical_assets',
    )
    asset_type = models.CharField(
        max_length=64, choices=ASSET_TYPE_CHOICES, default='Unclassified Asset',
    )
    canonical_identifier = models.CharField(max_length=1024, db_index=True)
    canonical_key_hash = models.CharField(max_length=64, db_index=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    risk_score = models.FloatField(default=0.0)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        unique_together = ('assessment', 'canonical_key_hash')
        indexes = [
            models.Index(fields=['assessment', 'asset_type']),
            models.Index(fields=['assessment', '-risk_score']),
        ]

    def __str__(self):
        return f"{self.asset_type} :: {self.canonical_identifier}"


class AssetSource(models.Model):
    """A single tool observation that contributed to a canonical Asset."""
    SOURCE_TOOL_CHOICES = (
        ('httpx', 'httpx'),
        ('nuclei', 'nuclei'),
        ('katana', 'katana'),
        ('screenshot', 'screenshot'),
        ('ffuf', 'ffuf'),
        ('port_scan', 'port_scan'),
        ('exposure_engine', 'exposure_engine'),
        ('subdomain_enum', 'subdomain_enum'),
        ('other', 'other'),
    )

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='sources')
    source_tool = models.CharField(max_length=32, choices=SOURCE_TOOL_CHOICES)
    source_scan_history = models.ForeignKey(
        'startScan.ScanHistory', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='asset_sources',
    )
    source_content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    source_object_id = models.PositiveIntegerField()
    source_object = GenericForeignKey('source_content_type', 'source_object_id')
    observed_at = models.DateTimeField()
    payload = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['asset', 'source_tool']),
            models.Index(fields=['source_scan_history']),
        ]
        unique_together = ('asset', 'source_content_type', 'source_object_id')

    def __str__(self):
        return f"{self.source_tool} → {self.asset_id}"
