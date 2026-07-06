"""Evidence Platform models.

Evidence items are files or structured data collected during an assessment.
Each piece of evidence has:
  - A unique UUID and SHA-256 hash for tamper detection
  - A storage reference (path or S3 key)
  - A chain-of-custody log via EvidenceEvent
  - M2M relationships to Vulnerability and AssessmentScope
  - A retention policy enforced via EvidenceRetentionPolicy

Evidence lifecycle:
  Draft → Active → Archived → Purged
"""
import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class EvidenceCollection(models.Model):
    """Top-level grouping of evidence for an assessment.

    One collection per assessment run. Activities attach evidence items
    to the collection so analysts see all evidence for a single assessment
    in one place.

    Fields:
        uuid (UUIDField): Public-facing unique identifier.
        assessment (FK → Assessment): Parent assessment.
        scan_history (FK → ScanHistory): Linked scan run, set by PrepareAssessmentContextActivity.
        name (CharField): Human-readable name, e.g. "Assessment: External - 2026-07-01".
        status (CharField): One of Draft, Active, Archived, Purged.
        created_at, updated_at: Timestamps.
    """
    STATUS_CHOICES = [
        ('Draft',    'Draft'),
        ('Active',   'Active'),
        ('Archived', 'Archived'),
        ('Purged',   'Purged'),
    ]

    uuid         = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    assessment   = models.ForeignKey(
        'engagements.Assessment',
        on_delete=models.CASCADE,
        related_name='evidence_collections',
    )
    scan_history = models.ForeignKey(
        'startScan.ScanHistory',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='evidence_collections',
    )
    name       = models.CharField(max_length=512)
    status     = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Active')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Evidence Collection'
        verbose_name_plural = 'Evidence Collections'

    def __str__(self):
        return f"{self.name} ({self.status})"


class Evidence(models.Model):
    """An individual piece of evidence collected during an assessment.

    Stores a reference to a file or structured payload along with hashing
    metadata for integrity verification.

    Fields:
        uuid (UUIDField): Public-facing identifier.
        collection (FK → EvidenceCollection): Parent collection.
        evidence_type (CharField): Screenshot, NetworkCapture, RequestResponse, etc.
        title (CharField): Short description.
        description (TextField): Full context / analyst notes.
        file_path (CharField): Storage path or S3/MinIO key.
        file_name (CharField): Original filename.
        file_size (BigIntegerField): Size in bytes.
        mime_type (CharField): MIME type detected at upload.
        sha256_hash (CharField): Hex-encoded SHA-256 of file content (tamper detection).
        status (CharField): Draft, Active, Archived, Purged.
        collected_at (DateTimeField): When the evidence was gathered.
        collected_by (FK → User): Who or which activity collected it (can be null for automation).
        vulnerabilities (M2M → Vulnerability): Findings this evidence supports.
        scopes (M2M → AssessmentScope): Scope items (targets) in this evidence.
    """
    EVIDENCE_TYPE_CHOICES = [
        ('Screenshot',       'Screenshot'),
        ('NetworkCapture',   'Network Capture (PCAP/HAR)'),
        ('RequestResponse',  'HTTP Request/Response'),
        ('CommandOutput',    'Command Output'),
        ('Log',              'Log File'),
        ('Report',           'Report Document'),
        ('Other',            'Other'),
    ]
    STATUS_CHOICES = [
        ('Draft',    'Draft'),
        ('Active',   'Active'),
        ('Archived', 'Archived'),
        ('Purged',   'Purged'),
    ]

    uuid          = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    collection    = models.ForeignKey(
        EvidenceCollection,
        on_delete=models.CASCADE,
        related_name='evidence_items',
    )
    evidence_type = models.CharField(max_length=50, choices=EVIDENCE_TYPE_CHOICES, default='Screenshot')
    title         = models.CharField(max_length=512)
    description   = models.TextField(blank=True, null=True)

    # Storage
    file_path  = models.CharField(max_length=2048, blank=True, null=True, help_text='Storage key or filesystem path')
    file_name  = models.CharField(max_length=512, blank=True, null=True)
    file_size  = models.BigIntegerField(default=0, help_text='Size in bytes')
    mime_type  = models.CharField(max_length=255, blank=True, null=True)

    # Integrity
    sha256_hash = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        help_text='SHA-256 hex digest of raw file content for tamper detection'
    )

    # Lifecycle
    status       = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Active')
    collected_at = models.DateTimeField(default=timezone.now)
    collected_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='collected_evidence',
    )
    created_at   = models.DateTimeField(auto_now_add=True)
    updated_at   = models.DateTimeField(auto_now=True)

    # Relationships to findings
    vulnerabilities = models.ManyToManyField(
        'startScan.Vulnerability',
        blank=True,
        related_name='evidence_items',
        help_text='Vulnerabilities / findings this evidence supports',
    )

    # Relationships to scope items (targets)
    scopes = models.ManyToManyField(
        'engagements.AssessmentScope',
        blank=True,
        related_name='evidence_items',
        help_text='Scope entries (targets) this evidence is for',
    )

    class Meta:
        ordering = ['-collected_at']
        verbose_name = 'Evidence'
        verbose_name_plural = 'Evidence Items'
        indexes = [
            models.Index(fields=['collection', 'status']),
            models.Index(fields=['sha256_hash']),
            models.Index(fields=['evidence_type']),
        ]

    def __str__(self):
        return f"{self.evidence_type}: {self.title}"

    @property
    def file_size_mb(self) -> float:
        """Return file size in MB rounded to 2 decimal places."""
        return round(self.file_size / (1024 * 1024), 2) if self.file_size else 0.0


class EvidenceEvent(models.Model):
    """Chain-of-custody audit log for an Evidence item.

    Every time an Evidence record is created, updated, downloaded, verified,
    archived, or purged, an EvidenceEvent is written.

    Fields:
        evidence (FK → Evidence): The evidence item this event refers to.
        event_type (CharField): Created, Verified, Downloaded, Updated, Archived, Purged.
        actor (FK → User): User who triggered the event (null for automated events).
        note (TextField): Optional description.
        hash_at_event (CharField): SHA-256 at time of event (for verification events).
        timestamp (DateTimeField): When the event occurred.
    """
    EVENT_TYPE_CHOICES = [
        ('Created',    'Created'),
        ('Updated',    'Updated'),
        ('Verified',   'Integrity Verified'),
        ('Downloaded', 'Downloaded'),
        ('Annotated',  'Annotated'),
        ('Archived',   'Archived'),
        ('Purged',     'Purged'),
    ]

    evidence      = models.ForeignKey(Evidence, on_delete=models.CASCADE, related_name='events')
    event_type    = models.CharField(max_length=20, choices=EVENT_TYPE_CHOICES)
    actor         = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_events')
    note          = models.TextField(blank=True, null=True)
    hash_at_event = models.CharField(max_length=64, blank=True, null=True)
    timestamp     = models.DateTimeField(default=timezone.now)
    ip_address    = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['timestamp']
        verbose_name = 'Evidence Event'
        verbose_name_plural = 'Evidence Events'

    def __str__(self):
        return f"{self.event_type} @ {self.timestamp.isoformat()} by {self.actor or 'system'}"


class EvidenceAnnotation(models.Model):
    """Analyst annotation (note, tag, or highlight) on an Evidence item.

    Allows analysts to highlight specific sections of evidence (e.g. a
    specific line in a command output or region in a screenshot) and attach
    notes without modifying the original evidence file.

    Fields:
        evidence (FK → Evidence): The evidence being annotated.
        author (FK → User): Analyst who wrote the annotation.
        annotation_type (CharField): Note, Tag, Highlight.
        content (TextField): The text of the annotation.
        region (JSONField): Optional dict describing the highlighted region
            (e.g. {"x": 100, "y": 200, "w": 300, "h": 50} for screenshot crops).
        created_at, updated_at: Timestamps.
    """
    ANNOTATION_TYPE_CHOICES = [
        ('Note',      'Note'),
        ('Tag',       'Tag'),
        ('Highlight', 'Highlight'),
    ]

    evidence        = models.ForeignKey(Evidence, on_delete=models.CASCADE, related_name='annotations')
    author          = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='evidence_annotations')
    annotation_type = models.CharField(max_length=20, choices=ANNOTATION_TYPE_CHOICES, default='Note')
    content         = models.TextField()
    region          = models.JSONField(null=True, blank=True, help_text='Optional highlighted region descriptor')
    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['created_at']
        verbose_name = 'Evidence Annotation'
        verbose_name_plural = 'Evidence Annotations'

    def __str__(self):
        return f"{self.annotation_type} by {self.author} on Evidence {self.evidence_id}"


class EvidenceRetentionPolicy(models.Model):
    """Retention policy for an EvidenceCollection.

    Determines when evidence in a collection should be archived or purged.
    The evidence retention Temporal activity reads these policies to enforce
    lifecycle transitions.

    Fields:
        collection (OneToOneField → EvidenceCollection): The collection this policy governs.
        archive_after_days (IntegerField): Days after collection creation before archiving.
            0 = never archive.
        purge_after_days (IntegerField): Days after archiving before purging. 0 = never purge.
        purge_files (BooleanField): Whether to delete the actual files on purge (vs keep metadata).
        last_enforced_at (DateTimeField): When the retention policy was last checked/enforced.
        next_action_at (DateTimeField): Calculated next enforcement date.
    """
    collection         = models.OneToOneField(EvidenceCollection, on_delete=models.CASCADE, related_name='retention_policy')
    archive_after_days = models.IntegerField(default=365, help_text='Days until archive. 0=never.')
    purge_after_days   = models.IntegerField(default=0, help_text='Days after archive to purge. 0=never.')
    purge_files        = models.BooleanField(default=False, help_text='Delete actual files on purge?')
    last_enforced_at   = models.DateTimeField(null=True, blank=True)
    next_action_at     = models.DateTimeField(null=True, blank=True)
    created_at         = models.DateTimeField(auto_now_add=True)
    updated_at         = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Evidence Retention Policy'
        verbose_name_plural = 'Evidence Retention Policies'

    def __str__(self):
        return f"Retention for {self.collection.name}: archive={self.archive_after_days}d, purge={self.purge_after_days}d"
