"""Assessment Copilot persistence — config, conversations, action proposals."""
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
    TYPE_CHOICES = (
        (TYPE_VALIDATE, 'Validate'),
        (TYPE_SAFE_POC, 'SAFE PoC'),
        (TYPE_FOLLOWUP, 'Follow-up'),
        (TYPE_REMEDIATION, 'Remediation'),
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
    # Links to delegated entities after propose/approve
    safe_poc_attempt_id = models.IntegerField(null=True, blank=True)
    followup_plan_id = models.IntegerField(null=True, blank=True)
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
