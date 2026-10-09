from django.db import models
from reNgine.definitions import *
from django.contrib.auth.models import User


class SearchHistory(models.Model):
	query = models.CharField(max_length=1000)

	def __str__(self):
		return self.query


class Project(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	slug = models.SlugField(unique=True)
	insert_date = models.DateTimeField()

	def __str__(self):
		return self.slug


class OpenAiAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key
	

class OllamaSettings(models.Model):
	id = models.AutoField(primary_key=True)
	selected_model = models.CharField(max_length=500)
	use_ollama = models.BooleanField(default=True)

	def __str__(self):
		return self.selected_model


class NetlasAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key
	

class ChaosAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key
	

class HackerOneAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	username = models.CharField(max_length=500)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.username


class ShodanAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key


class CensysAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	api_key = models.CharField(max_length=500)

	def __str__(self):
		return self.api_key


class InAppNotification(models.Model):
	project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=True)
	notification_type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES, default='system')
	status = models.CharField(max_length=10, choices=NOTIFICATION_STATUS_TYPES, default='info')
	title = models.CharField(max_length=255)
	description = models.TextField()
	icon = models.CharField(max_length=50) # mdi icon class name
	is_read = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	redirect_link = models.URLField(max_length=255, blank=True, null=True)
	open_in_new_tab = models.BooleanField(default=False)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		if self.notification_type == 'system':
			return f"System wide notif: {self.title}"
		else:
			return f"Project wide notif: {self.project.name}: {self.title}"
		
	@property
	def is_system_wide(self):
		# property to determine if the notification is system wide or project specific
		return self.notification_type == 'system'


class UserPreferences(models.Model):
	UI_VERSIONS = (
		('v2', 'Version 2 (Default)'),
		('v3', 'Version 3 (Cyberpunk)'),
	)
	V3_INTENSITIES = (
		('clean', 'Clean'),
		('script_kiddie', 'Script Kiddie'),
		('hacker', 'Hacker'),
	)
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	bug_bounty_mode = models.BooleanField(default=True)
	enable_scan_queueing = models.BooleanField(default=False)
	ui_version = models.CharField(max_length=2, choices=UI_VERSIONS, default='v2')
	v3_intensity = models.CharField(max_length=20, choices=V3_INTENSITIES, default='clean')

	def __str__(self):
		return f"{self.user.username}'s preferences"


class LLMConfig(models.Model):
	provider = models.CharField(max_length=50) # ollama, openai, openai_compatible, anthropic, gemini
	api_key = models.CharField(max_length=500, blank=True, null=True)
	# API root of an openai_compatible provider, e.g. https://gateway.example/v1.
	base_url = models.CharField(max_length=500, blank=True, null=True)
	selected_model = models.CharField(max_length=500)
	is_active = models.BooleanField(default=True)

	def __str__(self):
		return f"{self.provider} - {self.selected_model}"


class LLMSettings(models.Model):
	"""Singleton operator switch for all LLM features (impact assessment, reports, ...)."""
	enabled = models.BooleanField(default=False)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		verbose_name = 'LLM settings'
		verbose_name_plural = 'LLM settings'

	def __str__(self):
		return 'enabled' if self.enabled else 'disabled'

	@classmethod
	def get_solo(cls):
		obj, _ = cls.objects.get_or_create(pk=1, defaults={'enabled': False})
		return obj


class SpiderfootAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	module_name = models.CharField(max_length=200)
	key_name = models.CharField(max_length=200, default='api_key')
	key_value = models.CharField(max_length=500)

	def __str__(self):
		return f"{self.module_name} - {self.key_name}"


class LeakLookupAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key


class AcunetixAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	server_url = models.CharField(max_length=500)
	api_key = models.CharField(max_length=500)

	def __str__(self):
		return self.server_url


class AcunetixTargetSubmission(models.Model):
	"""One row per host ever pushed to Acunetix, used to avoid re-submitting it.

	Acunetix reuses an existing target for a known address, but a scan that
	discovers the same live subdomain every day would still re-register and
	re-scan it. This table answers "did we already send this host recently?"
	without a round trip per host.
	"""
	id = models.AutoField(primary_key=True)
	host = models.CharField(max_length=500, unique=True)
	target_url = models.CharField(max_length=1000, blank=True, default='')
	acunetix_target_id = models.CharField(max_length=100, blank=True, default='')
	last_submitted_at = models.DateTimeField()
	submission_count = models.PositiveIntegerField(default=1)
	last_scan_history = models.ForeignKey(
		'startScan.ScanHistory', on_delete=models.SET_NULL, null=True, blank=True,
		related_name='acunetix_submissions',
	)

	class Meta:
		# Named explicitly: an unnamed Index gets a hash-derived name that only
		# makemigrations can compute, which a hand-written migration cannot match.
		indexes = [models.Index(fields=['last_submitted_at'], name='acu_submission_sent_idx')]

	def __str__(self):
		return f"{self.host} -> {self.acunetix_target_id or 'unregistered'}"


class LinkedInCredentials(models.Model):
	id = models.AutoField(primary_key=True)
	username = models.CharField(max_length=500, blank=True, default='')
	cookies_json = models.TextField(blank=True, default='')
	state_file_path = models.CharField(max_length=1000, blank=True, default='')
	last_validated_at = models.DateTimeField(null=True, blank=True)
	is_valid = models.BooleanField(default=False)

	def __str__(self):
		return self.username


class HunterIOAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key


class SecurityTrailsAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key


class WpScanAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key


class SOCConfiguration(models.Model):
	"""Global configuration for Mobile SOC features."""
	enable_live_log_streaming = models.BooleanField(default=False)
	log_retention_count = models.IntegerField(default=1000)
	
	def __str__(self):
		return "Global SOC Configuration"
	
	class Meta:
		verbose_name = "SOC Configuration"
		verbose_name_plural = "SOC Configurations"


class MobilePushToken(models.Model):
	"""
	Stores Expo push notification tokens for mobile app users.
	Each device registers its token after the user authenticates.
	Tokens are used by the backend to dispatch push notifications
	via the Expo Push Notification Service.
	"""
	# The authenticated user who owns this push token
	user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='push_tokens')
	# The Expo push token string (e.g. ExponentPushToken[xxxx])
	token = models.CharField(max_length=500, unique=True)
	# Optional human-readable label for the device (e.g. 'Samsung S24')
	device_label = models.CharField(max_length=100, blank=True, null=True)
	# Whether this token should receive notifications
	is_active = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		verbose_name = "Mobile Push Token"
		verbose_name_plural = "Mobile Push Tokens"
		ordering = ['-updated_at']

	def __str__(self):
		return f"{self.user.username} — {self.token[:40]}... "


class ProjectDiscoveryAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)

	def __str__(self):
		return self.key


class GitHubAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name = 'GitHub API Key'

	def __str__(self):
		return f"GitHub API Key ({self.key[:8]}...)"


class LeakSearchAPIKey(models.Model):
	id = models.AutoField(primary_key=True)
	key = models.CharField(max_length=500)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name = 'LeakSearch API Key'

	def __str__(self):
		return f"LeakSearch API Key ({self.key[:8]}...)"