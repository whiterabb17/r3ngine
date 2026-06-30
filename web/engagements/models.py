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
        ('Running', 'Running'),
        ('Review', 'Review'),
        ('Completed', 'Completed'),
        ('Archived', 'Archived'),
    )

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='assessments')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    assessment_type = models.CharField(max_length=100, choices=ASSESSMENT_TYPES)
    
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Draft')
    
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    
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
