import uuid
from django.conf import settings
from django.db import models


class McpInstanceSettings(models.Model):
    TRANSPORT_STDIO = 'stdio'
    TRANSPORT_HTTP = 'http'
    TRANSPORT_BOTH = 'both'
    TRANSPORT_CHOICES = (
        (TRANSPORT_STDIO, 'stdio'),
        (TRANSPORT_HTTP, 'http'),
        (TRANSPORT_BOTH, 'both'),
    )
    transport_mode = models.CharField(
        max_length=8, choices=TRANSPORT_CHOICES, default=TRANSPORT_STDIO
    )
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj


class McpApiKey(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='mcp_api_keys'
    )
    name = models.CharField(max_length=100)
    prefix = models.CharField(max_length=16)
    key_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'name')

    def is_active(self) -> bool:
        return self.revoked_at is None


class McpAgent(models.Model):
    id = models.CharField(max_length=64, primary_key=True)
    key = models.ForeignKey(
        McpApiKey, on_delete=models.CASCADE, related_name='agents'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='mcp_agents'
    )
    provider = models.CharField(max_length=80, blank=True, default='')
    ide = models.CharField(max_length=80, blank=True, default='')
    device_id = models.CharField(max_length=128, blank=True, default='')
    os_name = models.CharField(max_length=80, blank=True, default='')
    hostname = models.CharField(max_length=200, blank=True, default='')
    username = models.CharField(max_length=200, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now_add=True)
    banned_at = models.DateTimeField(null=True, blank=True)
    banned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='mcp_agents_banned',
    )

    class Meta:
        indexes = [
            models.Index(fields=['key', 'last_seen_at']),
            models.Index(fields=['user', 'last_seen_at']),
        ]


class McpAgentBan(models.Model):
    """Fingerprint bans that survive deleting the agent from the UI."""
    agent_id = models.CharField(max_length=64, unique=True)
    key = models.ForeignKey(
        McpApiKey, null=True, blank=True, on_delete=models.SET_NULL, related_name='agent_bans'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='mcp_agent_bans',
    )
    provider = models.CharField(max_length=80, blank=True, default='')
    ide = models.CharField(max_length=80, blank=True, default='')
    device_id = models.CharField(max_length=128, blank=True, default='')
    hostname = models.CharField(max_length=200, blank=True, default='')
    banned_at = models.DateTimeField(auto_now_add=True)
    banned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='mcp_agent_ban_actions',
    )


class McpSession(models.Model):
    CONNECTED_WINDOW_SECONDS = 120

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.ForeignKey(McpApiKey, on_delete=models.CASCADE, related_name='sessions')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='mcp_sessions'
    )
    agent = models.ForeignKey(
        McpAgent, null=True, blank=True, on_delete=models.SET_NULL, related_name='sessions'
    )
    provider = models.CharField(max_length=80, blank=True, default='')
    ide = models.CharField(max_length=80, blank=True, default='')
    device_id = models.CharField(max_length=128, blank=True, default='')
    os_name = models.CharField(max_length=80, blank=True, default='')
    hostname = models.CharField(max_length=200, blank=True, default='')
    agent_username = models.CharField(max_length=200, blank=True, default='')
    transport = models.CharField(max_length=8, choices=(('stdio', 'stdio'), ('http', 'http')))
    client_name = models.CharField(max_length=200, blank=True, default='')
    client_version = models.CharField(max_length=100, blank=True, default='')
    user_agent = models.CharField(max_length=300, blank=True, default='')
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    connected_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    def is_connected(self) -> bool:
        from datetime import timedelta
        from django.utils import timezone
        if self.revoked_at or self.ended_at:
            return False
        return self.last_seen_at >= timezone.now() - timedelta(seconds=self.CONNECTED_WINDOW_SECONDS)


class FollowupPlan(models.Model):
    """Durable agent/operator follow-up batch (propose → edit → approve → run)."""

    STATUS_PROPOSED = 'proposed'
    STATUS_APPROVED = 'approved'
    STATUS_RUNNING = 'running'
    STATUS_DONE = 'done'
    STATUS_FAILED = 'failed'
    STATUS_ABORTED = 'aborted'
    STATUS_REJECTED = 'rejected'
    STATUS_CHOICES = (
        (STATUS_PROPOSED, 'Proposed'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_DONE, 'Done'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_ABORTED, 'Aborted'),
        (STATUS_REJECTED, 'Rejected'),
    )

    project_slug = models.CharField(max_length=255, db_index=True)
    scan_id = models.IntegerField(null=True, blank=True, db_index=True)
    assessment_id = models.IntegerField(null=True, blank=True, db_index=True)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PROPOSED, db_index=True
    )
    rationale = models.TextField(blank=True, default='')
    steps = models.JSONField(default=list)
    temporal_workflow_ids = models.JSONField(default=list)
    retry_count = models.PositiveIntegerField(default=0)
    operator_edited = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='followup_plans_created',
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='followup_plans_updated',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['project_slug', 'status', '-created_at']),
            models.Index(fields=['scan_id', 'status']),
            models.Index(fields=['assessment_id', 'status']),
        ]

    def __str__(self):
        return f'FollowupPlan {self.id} ({self.status})'


class AttackPathProposal(models.Model):
    """Agent/operator attack-path mutation (propose → edit → approve → apply)."""

    STATUS_PROPOSED = 'proposed'
    STATUS_APPROVED = 'approved'
    STATUS_APPLIED = 'applied'
    STATUS_ABORTED = 'aborted'
    STATUS_REJECTED = 'rejected'
    STATUS_CHOICES = (
        (STATUS_PROPOSED, 'Proposed'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_APPLIED, 'Applied'),
        (STATUS_ABORTED, 'Aborted'),
        (STATUS_REJECTED, 'Rejected'),
    )

    OP_ENRICH = 'enrich'
    OP_CREATE = 'create'
    OP_UPDATE = 'update'
    OP_DISMISS = 'dismiss'
    OP_TRIGGER_APME = 'trigger_apme'
    OP_RECALCULATE_APME = 'recalculate_apme'
    OPERATION_CHOICES = (
        (OP_ENRICH, 'Enrich'),
        (OP_CREATE, 'Create'),
        (OP_UPDATE, 'Update'),
        (OP_DISMISS, 'Dismiss'),
        (OP_TRIGGER_APME, 'Trigger APME'),
        (OP_RECALCULATE_APME, 'Recalculate APME'),
    )

    project_slug = models.CharField(max_length=255, db_index=True)
    scan_id = models.IntegerField(null=True, blank=True, db_index=True)
    target_path_id = models.CharField(max_length=128, blank=True, default='', db_index=True)
    impact_assessment_id = models.IntegerField(null=True, blank=True, db_index=True)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PROPOSED, db_index=True
    )
    operation = models.CharField(max_length=32, choices=OPERATION_CHOICES)
    payload = models.JSONField(default=dict)
    rationale = models.TextField(blank=True, default='')
    agent_id = models.CharField(max_length=128, blank=True, default='')
    result = models.JSONField(null=True, blank=True)
    operator_edited = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='attack_path_proposals_created',
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='attack_path_proposals_updated',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    applied_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['project_slug', 'status', '-created_at']),
            models.Index(fields=['scan_id', 'status']),
            models.Index(fields=['target_path_id', 'status']),
        ]

    def __str__(self):
        return f'AttackPathProposal {self.id} ({self.operation}/{self.status})'


class SafePocAttempt(models.Model):
    """SAFE PoC attempt (propose → edit → approve → execute catalog template)."""

    STATUS_PROPOSED = 'proposed'
    STATUS_APPROVED = 'approved'
    STATUS_RUNNING = 'running'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'
    STATUS_ABORTED = 'aborted'
    STATUS_REJECTED = 'rejected'
    STATUS_CHOICES = (
        (STATUS_PROPOSED, 'Proposed'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_SUCCEEDED, 'Succeeded'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_ABORTED, 'Aborted'),
        (STATUS_REJECTED, 'Rejected'),
    )

    project_slug = models.CharField(max_length=255, db_index=True)
    scan_id = models.IntegerField(null=True, blank=True, db_index=True)
    vulnerability_id = models.IntegerField(db_index=True)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PROPOSED, db_index=True
    )
    template_id = models.CharField(max_length=64)
    params = models.JSONField(default=dict)
    rationale = models.TextField(blank=True, default='')
    agent_id = models.CharField(max_length=128, blank=True, default='')
    result = models.JSONField(null=True, blank=True)
    operator_edited = models.BooleanField(default=False)
    temporal_workflow_id = models.CharField(max_length=255, blank=True, default='')
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='safe_poc_attempts_created',
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='safe_poc_attempts_updated',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(
                fields=['project_slug', 'status', '-created_at'],
                name='mcp_safepoc_project_idx',
            ),
            models.Index(fields=['scan_id', 'status'], name='mcp_safepoc_scan_id_idx'),
            models.Index(
                fields=['vulnerability_id', 'status'],
                name='mcp_safepoc_vuln_id_idx',
            ),
        ]

    def __str__(self):
        return f'SafePocAttempt {self.id} ({self.template_id}/{self.status})'


class McpAuditEvent(models.Model):
    session = models.ForeignKey(
        McpSession, null=True, blank=True, on_delete=models.SET_NULL, related_name='events'
    )
    key = models.ForeignKey(
        McpApiKey, null=True, blank=True, on_delete=models.SET_NULL, related_name='audit_events'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='mcp_audit_events'
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    tool_name = models.CharField(max_length=120, blank=True, default='')
    method = models.CharField(max_length=8)
    path = models.CharField(max_length=300)
    status_code = models.PositiveSmallIntegerField()
    duration_ms = models.PositiveIntegerField(default=0)
    request_body = models.JSONField(null=True, blank=True)
    response_body = models.JSONField(null=True, blank=True)
    truncated = models.BooleanField(default=False)
    error_message = models.TextField(blank=True, default='')

    class Meta:
        indexes = [
            models.Index(fields=['session', 'created_at']),
            models.Index(fields=['user', 'created_at']),
        ]
