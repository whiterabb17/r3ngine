"""Assessment Copilot persistence — config, conversations, proposals, MSF aux, Trace."""
from __future__ import annotations

from django.conf import settings
from django.db import models


class CopilotSettings(models.Model):
    """Singleton-ish project-scoped co-pilot configuration."""

    SCOPE_PROJECT = 'project'
    SCOPE_ORG = 'org'
    SCOPE_GLOBAL = 'global'
    SCOPE_TIERED = 'tiered'
    SCOPE_CHOICES = (
        (SCOPE_PROJECT, 'Per project'),
        (SCOPE_ORG, 'Per organization'),
        (SCOPE_GLOBAL, 'Global (local corpus)'),
        (SCOPE_TIERED, 'Tiered (project + curated global)'),
    )

    project_slug = models.CharField(max_length=255, unique=True, db_index=True)
    enabled = models.BooleanField(default=True)
    memory_scope = models.CharField(
        max_length=16, choices=SCOPE_CHOICES, default=SCOPE_PROJECT,
    )
    model_id = models.CharField(max_length=255, blank=True, default='')
    org_id = models.CharField(max_length=255, blank=True, default='')
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='copilot_settings_updated',
    )

    class Meta:
        verbose_name = 'Copilot settings'
        verbose_name_plural = 'Copilot settings'

    def __str__(self):
        return f'CopilotSettings({self.project_slug})'


class CopilotSession(models.Model):
    """Saved chat conversation with the local assessment co-pilot."""

    project_slug = models.CharField(max_length=255, db_index=True)
    scan_id = models.IntegerField(null=True, blank=True, db_index=True)
    assessment_id = models.IntegerField(null=True, blank=True, db_index=True)
    title = models.CharField(max_length=255, blank=True, default='New conversation')
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='copilot_sessions',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['project_slug', '-updated_at']),
        ]
        ordering = ['-updated_at']

    def __str__(self):
        return f'CopilotSession {self.id}: {self.title}'


class CopilotMessage(models.Model):
    ROLE_USER = 'user'
    ROLE_ASSISTANT = 'assistant'
    ROLE_SYSTEM = 'system'
    ROLE_CHOICES = (
        (ROLE_USER, 'User'),
        (ROLE_ASSISTANT, 'Assistant'),
        (ROLE_SYSTEM, 'System'),
    )

    session = models.ForeignKey(
        CopilotSession, on_delete=models.CASCADE, related_name='messages',
    )
    role = models.CharField(max_length=16, choices=ROLE_CHOICES)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']


class CopilotActionProposal(models.Model):
    """Operator-facing proposal that delegates to existing gated APIs on approve."""

    TYPE_VALIDATE = 'validate'
    TYPE_SAFE_POC = 'safe_poc'
    TYPE_FOLLOWUP = 'followup'
    TYPE_REMEDIATION = 'remediation'
    TYPE_MSF_MODULE = 'msf_module'
    TYPE_CHOICES = (
        (TYPE_VALIDATE, 'Validate'),
        (TYPE_SAFE_POC, 'SAFE PoC'),
        (TYPE_FOLLOWUP, 'Follow-up'),
        (TYPE_REMEDIATION, 'Remediation'),
        (TYPE_MSF_MODULE, 'MSF module'),
    )

    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_FAILED = 'failed'
    STATUS_CHOICES = (
        (STATUS_PENDING, 'Pending'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_REJECTED, 'Rejected'),
        (STATUS_FAILED, 'Failed'),
    )

    project_slug = models.CharField(max_length=255, db_index=True)
    scan_id = models.IntegerField(null=True, blank=True, db_index=True)
    assessment_id = models.IntegerField(null=True, blank=True, db_index=True)
    vulnerability_id = models.IntegerField(null=True, blank=True, db_index=True)
    session = models.ForeignKey(
        CopilotSession,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='proposals',
    )
    action_type = models.CharField(max_length=32, choices=TYPE_CHOICES, db_index=True)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True,
    )
    summary = models.CharField(max_length=512, blank=True, default='')
    rationale = models.TextField(blank=True, default='')
    payload = models.JSONField(default=dict)
    safe_poc_attempt_id = models.IntegerField(null=True, blank=True)
    followup_plan_id = models.IntegerField(null=True, blank=True)
    msf_aux_attempt_id = models.IntegerField(null=True, blank=True)
    result = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='copilot_proposals_created',
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='copilot_proposals_decided',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['project_slug', 'status', '-created_at']),
            models.Index(fields=['vulnerability_id', 'status']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f'CopilotActionProposal {self.id} ({self.action_type}/{self.status})'


class MsfAuxAttempt(models.Model):
    """Gated Metasploit auxiliary/post run (propose → approve → Temporal → MSFRPC)."""

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
    vulnerability_id = models.IntegerField(null=True, blank=True, db_index=True)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PROPOSED, db_index=True,
    )
    module = models.CharField(max_length=255)
    options = models.JSONField(default=dict)
    rationale = models.TextField(blank=True, default='')
    result = models.JSONField(null=True, blank=True)
    error = models.TextField(blank=True, default='')
    temporal_workflow_id = models.CharField(max_length=255, blank=True, default='')
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='msf_aux_attempts_created',
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='msf_aux_attempts_decided',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(
                fields=['project_slug', 'status', '-created_at'],
                name='copilot_msf_project_idx',
            ),
            models.Index(
                fields=['vulnerability_id', 'status'],
                name='copilot_msf_vuln_idx',
            ),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f'MsfAuxAttempt {self.id} ({self.module}/{self.status})'


class CopilotTraceEvent(models.Model):
    """Operator-visible audit stream for Copilot turns, proposals, and MSF runs."""

    TYPE_RETRIEVE = 'retrieve'
    TYPE_DECISION = 'decision'
    TYPE_PROPOSAL = 'proposal'
    TYPE_MSF_AUX = 'msf_aux'
    TYPE_THOUGHT = 'thought'
    TYPE_ERROR = 'error'
    TYPE_CHOICES = (
        (TYPE_RETRIEVE, 'Retrieve'),
        (TYPE_DECISION, 'Decision'),
        (TYPE_PROPOSAL, 'Proposal'),
        (TYPE_MSF_AUX, 'MSF aux'),
        (TYPE_THOUGHT, 'Thought'),
        (TYPE_ERROR, 'Error'),
    )

    project_slug = models.CharField(max_length=255, db_index=True)
    session = models.ForeignKey(
        CopilotSession,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='trace_events',
    )
    turn_id = models.CharField(max_length=64, blank=True, default='', db_index=True)
    event_type = models.CharField(max_length=32, choices=TYPE_CHOICES, db_index=True)
    summary = models.CharField(max_length=512, blank=True, default='')
    payload = models.JSONField(default=dict, blank=True)
    proposal_id = models.IntegerField(null=True, blank=True, db_index=True)
    msf_aux_attempt_id = models.IntegerField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(
                fields=['project_slug', '-created_at'],
                name='copilot_tr_project_idx',
            ),
            models.Index(
                fields=['session', 'turn_id'],
                name='copilot_tr_session_idx',
            ),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f'CopilotTraceEvent {self.id} ({self.event_type})'
