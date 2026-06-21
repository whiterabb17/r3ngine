from dashboard.models import *
from django.contrib.humanize.templatetags.humanize import (naturalday, naturaltime)
from django.db.models import F, JSONField, Value, Q
from django.forms.models import model_to_dict
from recon_note.models import *
from reNgine.common_func import *
from reNgine.definitions import (
	ABORTED_TASK,
	RUNNING_TASK,
	SUCCESS_TASK,
	FAILED_TASK
)
from rest_framework import serializers
from scanEngine.models import *
from startScan.models import *
from targetApp.models import *
from dashboard.models import InAppNotification



class ProjectSerializer(serializers.ModelSerializer):
	insert_date_humanized = serializers.SerializerMethodField()

	class Meta:
		model = Project
		fields = '__all__'

	def get_insert_date_humanized(self, obj):
		if obj.insert_date:
			return naturaltime(obj.insert_date).title()


class EngineTypeSerializer(serializers.ModelSerializer):
	class Meta:
		model = EngineType
		fields = '__all__'


class OsintStagingSerializer(serializers.ModelSerializer):
	discovered_date_humanized = serializers.SerializerMethodField()
	target_domain_name = serializers.CharField(source='target_domain.name', read_only=True)
	scan_history_id = serializers.IntegerField(source='scan_history.id', read_only=True)

	class Meta:
		model = OsintStaging
		fields = '__all__'

	def get_discovered_date_humanized(self, obj):
		return naturaltime(obj.discovered_date)


class ProxySerializer(serializers.ModelSerializer):
	class Meta:
		model = Proxy
		fields = '__all__'


class ConfigurationSerializer(serializers.ModelSerializer):
	class Meta:
		model = Configuration
		fields = '__all__'


class SOCConfigurationSerializer(serializers.ModelSerializer):
	class Meta:
		model = SOCConfiguration
		fields = '__all__'


class HackerOneProgramAttributesSerializer(serializers.Serializer):


	"""
		Serializer for HackerOne Program
		IMP: THIS is not a model serializer, programs will not be stored in db
		due to ever changing nature of programs, rather cache will be used on these serializers
	"""
	handle = serializers.CharField(required=False)
	name = serializers.CharField(required=False)
	currency = serializers.CharField(required=False)
	submission_state = serializers.CharField(required=False)
	triage_active = serializers.BooleanField(allow_null=True, required=False)
	state = serializers.CharField(required=False)
	started_accepting_at = serializers.DateTimeField(required=False)
	bookmarked = serializers.BooleanField(required=False)
	allows_bounty_splitting = serializers.BooleanField(required=False)
	offers_bounties = serializers.BooleanField(required=False)
	open_scope = serializers.BooleanField(allow_null=True, required=False)
	fast_payments = serializers.BooleanField(allow_null=True, required=False)
	gold_standard_safe_harbor = serializers.BooleanField(allow_null=True, required=False)

	def to_representation(self, instance):
		return {key: value for key, value in instance.items()}


class HackerOneProgramSerializer(serializers.Serializer):
	id = serializers.CharField()
	type = serializers.CharField()
	attributes = HackerOneProgramAttributesSerializer()



class InAppNotificationSerializer(serializers.ModelSerializer):
	class Meta:
		model = InAppNotification
		fields = [
			'id', 
			'title', 
			'description', 
			'icon', 
			'is_read', 
			'created_at', 
			'notification_type', 
			'status',
			'redirect_link',
			'open_in_new_tab',
			'project'
		]
		read_only_fields = ['id', 'created_at']

	def get_project_name(self, obj):
		return obj.project.name if obj.project else None


class SearchHistorySerializer(serializers.ModelSerializer):
	class Meta:
		model = SearchHistory
		fields = ['query']


class MobilePushTokenSerializer(serializers.ModelSerializer):
	"""
	Serializer for MobilePushToken model.
	Used by RegisterPushTokenView to accept and return token registration data.
	The `user` field is automatically set from the authenticated request user.
	"""
	class Meta:
		model = MobilePushToken
		fields = ['id', 'token', 'device_label', 'is_active', 'created_at', 'updated_at']
		read_only_fields = ['id', 'is_active', 'created_at', 'updated_at']



class DomainSerializer(serializers.ModelSerializer):
	vuln_count = serializers.SerializerMethodField()
	subdomain_count = serializers.SerializerMethodField()
	vulnerability_count = serializers.SerializerMethodField()
	organization = serializers.SerializerMethodField()
	most_recent_scan = serializers.SerializerMethodField()
	insert_date = serializers.SerializerMethodField()
	insert_date_humanized = serializers.SerializerMethodField()
	start_scan_date = serializers.SerializerMethodField()
	start_scan_date_humanized = serializers.SerializerMethodField()
	most_recent_scan_status = serializers.SerializerMethodField()
	most_recent_scan_progress = serializers.SerializerMethodField()

	class Meta:
		model = Domain
		fields = '__all__'
		depth = 2

	def _get_recent_scan(self, obj):
		from django.apps import apps
		ScanHistory = apps.get_model('startScan.ScanHistory')
		return (
			ScanHistory.objects
			.filter(domain__id=obj.id)
			.order_by('-id')
			.first()
		)

	def get_vuln_count(self, obj):
		from startScan.models import Vulnerability
		return Vulnerability.objects.filter(target_domain=obj).count()

	def get_vulnerability_count(self, obj):
		from startScan.models import Vulnerability
		return Vulnerability.objects.filter(target_domain=obj).count()

	def get_subdomain_count(self, obj):
		from startScan.models import Subdomain
		return Subdomain.objects.filter(target_domain=obj).values('name').distinct().count()

	def get_organization(self, obj):
		if Organization.objects.filter(domains__id=obj.id).exists():
			return [org.name for org in Organization.objects.filter(domains__id=obj.id)]

	def get_most_recent_scan(self, obj):
		recent_scan = self._get_recent_scan(obj)
		return recent_scan.id if recent_scan else None

	def get_insert_date(self, obj):
		if obj.insert_date:
			return naturalday(obj.insert_date).title()

	def get_insert_date_humanized(self, obj):
		if obj.insert_date:
			return naturaltime(obj.insert_date).title()

	def get_start_scan_date(self, obj):
		if obj.start_scan_date:
			return naturalday(obj.start_scan_date).title()

	def get_start_scan_date_humanized(self, obj):
		if obj.start_scan_date:
			return naturaltime(obj.start_scan_date).title()

	def get_most_recent_scan_status(self, obj):
		recent_scan = self._get_recent_scan(obj)
		if recent_scan:
			from reNgine.definitions import CELERY_TASK_STATUS_MAP
			return CELERY_TASK_STATUS_MAP.get(recent_scan.scan_status, 'UNKNOWN')
		return 'NEVER_SCANNED'

	def get_most_recent_scan_progress(self, obj):
		recent_scan = self._get_recent_scan(obj)
		if recent_scan:
			return recent_scan.get_progress() or 0
		return 0


class SubScanResultSerializer(serializers.ModelSerializer):

	task = serializers.SerializerMethodField('get_task_name')
	subdomain_name = serializers.SerializerMethodField('get_subdomain_name')
	engine = serializers.SerializerMethodField('get_engine_name')

	class Meta:
		model = SubScan
		fields = [
			'id',
			'type',
			'subdomain_name',
			'start_scan_date',
			'stop_scan_date',
			'scan_history',
			'subdomain',
			'workflow_ids',
			'status',
			'subdomain_name',
			'task',
			'engine'
		]

	def get_subdomain_name(self, subscan):
		return subscan.subdomain.name

	def get_task_name(self, subscan):
		return subscan.type

	def get_engine_name(self, subscan):
		if subscan.engine:
			return subscan.engine.engine_name
		return ''


class ReconNoteSerializer(serializers.ModelSerializer):

	domain_name = serializers.SerializerMethodField('get_domain_name')
	subdomain_name = serializers.SerializerMethodField('get_subdomain_name')
	scan_started_time = serializers.SerializerMethodField('get_scan_started_time')

	class Meta:
		model = TodoNote
		fields = '__all__'

	def get_domain_name(self, note):
		if note.scan_history:
			return note.scan_history.domain.name

	def get_subdomain_name(self, note):
		if note.subdomain:
			return note.subdomain.name

	def get_scan_started_time(self, note):
		if note.scan_history:
			return note.scan_history.start_scan_date


class OnlySubdomainNameSerializer(serializers.ModelSerializer):
	class Meta:
		model = Subdomain
		fields = ['name', 'id']


class SubScanSerializer(serializers.ModelSerializer):

	subdomain_name = serializers.SerializerMethodField('get_subdomain_name')
	time_taken = serializers.SerializerMethodField('get_total_time_taken')
	elapsed_time = serializers.SerializerMethodField('get_elapsed_time')
	completed_ago = serializers.SerializerMethodField('get_completed_ago')
	engine = serializers.SerializerMethodField('get_engine_name')

	class Meta:
		model = SubScan
		fields = '__all__'

	def get_subdomain_name(self, subscan):
		return subscan.subdomain.name

	def get_total_time_taken(self, subscan):
		return subscan.get_total_time_taken()

	def get_elapsed_time(self, subscan):
		return subscan.get_elapsed_time()

	def get_completed_ago(self, subscan):
		return subscan.get_completed_ago()

	def get_engine_name(self, subscan):
		if subscan.engine:
			return subscan.engine.engine_name
		return ''


class CommandSerializer(serializers.ModelSerializer):
	class Meta:
		model = Command
		fields = '__all__'
		depth = 1


class MinimalUserSerializer(serializers.ModelSerializer):
	"""
		Serializer for User model
		Purpose of this serializer is to return minimal information about user
		Related to report by @RaDiTZz0
	"""
	class Meta:
		model = User
		fields = ['username']


class UserSerializer(serializers.ModelSerializer):
	full_name = serializers.SerializerMethodField('get_full_name')
	role = serializers.SerializerMethodField('get_role')
	last_login_humanized = serializers.SerializerMethodField('get_last_login_humanized')
	date_joined_humanized = serializers.SerializerMethodField('get_date_joined_humanized')

	class Meta:
		model = User
		fields = [
			'id', 
			'username', 
			'full_name', 
			'email', 
			'role', 
			'is_active', 
			'is_staff',
			'date_joined',
			'date_joined_humanized',
			'last_login',
			'last_login_humanized'
		]

	def get_full_name(self, obj):
		return obj.get_full_name() or obj.username

	def get_role(self, obj):
		from rolepermissions.roles import get_user_roles
		roles = get_user_roles(obj)
		if roles:
			return roles[0].get_name()
		return 'penetration_tester'

	def get_last_login_humanized(self, obj):
		from django.contrib.humanize.templatetags.humanize import naturaltime
		return naturaltime(obj.last_login) if obj.last_login else 'Never'

	def get_date_joined_humanized(self, obj):
		from django.contrib.humanize.templatetags.humanize import naturaltime
		return naturaltime(obj.date_joined)


class ScanHistorySerializer(serializers.ModelSerializer):

	subdomain_count = serializers.SerializerMethodField('get_subdomain_count')
	endpoint_count = serializers.SerializerMethodField('get_endpoint_count')
	vulnerability_count = serializers.SerializerMethodField('get_vulnerability_count')
	current_progress = serializers.SerializerMethodField('get_progress')
	completed_time = serializers.SerializerMethodField('get_total_scan_time_in_sec')
	elapsed_time = serializers.SerializerMethodField('get_elapsed_time')
	completed_ago = serializers.SerializerMethodField('get_completed_ago')
	organizations = serializers.SerializerMethodField('get_organizations')
	initiated_by = MinimalUserSerializer(read_only=True)
	max_severity = serializers.SerializerMethodField('get_max_severity')
	engine_name = serializers.SerializerMethodField('get_engine_name')
	is_spiderfoot_running = serializers.SerializerMethodField()
	successful_task_count = serializers.SerializerMethodField()
	failed_task_count = serializers.SerializerMethodField()
	total_task_count = serializers.SerializerMethodField()
	current_tier = serializers.SerializerMethodField()
	total_tiers = serializers.SerializerMethodField()
	current_tier_progress = serializers.SerializerMethodField()

	class Meta:
		model = ScanHistory
		fields = [
			'id',
			'subdomain_count',
			'endpoint_count',
			'vulnerability_count',
			'current_progress',
			'completed_time',
			'elapsed_time',
			'completed_ago',
			'organizations',
			'start_scan_date',
			'scan_status',
			'results_dir',
			'workflow_ids',
			'tasks',
			'stop_scan_date',
			'error_message',
			'domain',
			'scan_type',
			'initiated_by',
			'max_severity',
			'engine_name',
			'cfg_starting_point_path',
			'is_spiderfoot_running',
			'successful_task_count',
			'failed_task_count',
			'total_task_count',
			'current_tier',
			'total_tiers',
			'current_tier_progress',
		]
		depth = 1

	def get_is_spiderfoot_running(self, obj):
		return obj.scanactivity_set.filter(
			Q(name='spiderfoot_scan') | Q(title__icontains='spiderfoot'),
			status=RUNNING_TASK
		).exists()

	def _get_cached_task_counts(self, obj):
		cache_attr = f'_task_counts_{obj.pk}'
		if not hasattr(self, cache_attr):
			from api.scan_task_counts import get_task_counts
			setattr(self, cache_attr, get_task_counts(obj))
		return getattr(self, cache_attr)

	def get_successful_task_count(self, obj):
		return self._get_cached_task_counts(obj)[0]

	def get_failed_task_count(self, obj):
		return self._get_cached_task_counts(obj)[1]

	def get_total_task_count(self, obj):
		return self._get_cached_task_counts(obj)[2]

	def get_tier_info(self, obj):
		cache_attr = f'_tier_info_{obj.pk}'
		if hasattr(self, cache_attr):
			return getattr(self, cache_attr)

		activities = list(obj.scanactivity_set.all())
		if not activities:
			info = {'current_tier': 0, 'total_tiers': 0, 'current_tier_progress': 0}
			setattr(self, cache_attr, info)
			return info

		tiered_activities = [a for a in activities if a.tier is not None and a.tier > 0]
		if not tiered_activities:
			info = {'current_tier': 0, 'total_tiers': 0, 'current_tier_progress': 0}
			setattr(self, cache_attr, info)
			return info

		total_tiers = max(a.tier for a in tiered_activities)

		started_tiers = set()
		completed_tiers = set()

		tier_activities = {}
		for a in tiered_activities:
			tier_activities.setdefault(a.tier, []).append(a)
			if a.status in [RUNNING_TASK, SUCCESS_TASK, FAILED_TASK]:
				started_tiers.add(a.tier)

		for tier, acts in tier_activities.items():
			if all(a.status in [SUCCESS_TASK, FAILED_TASK] for a in acts):
				completed_tiers.add(tier)

		active_tier = 1
		uncompleted_started = [t for t in started_tiers if t not in completed_tiers]
		if uncompleted_started:
			active_tier = min(uncompleted_started)
		elif completed_tiers:
			active_tier = min(max(completed_tiers) + 1, total_tiers)
		elif obj.scan_status == RUNNING_TASK:
			active_tier = 1
		else:
			active_tier = 0

		current_tier_progress = 0
		if active_tier in tier_activities:
			acts = tier_activities[active_tier]
			completed_acts = sum(1 for a in acts if a.status in [SUCCESS_TASK, FAILED_TASK])
			current_tier_progress = round((completed_acts / len(acts)) * 100, 2)

		info = {
			'current_tier': active_tier,
			'total_tiers': total_tiers,
			'current_tier_progress': current_tier_progress
		}
		setattr(self, cache_attr, info)
		return info

	def get_current_tier(self, obj):
		return self.get_tier_info(obj)['current_tier']

	def get_total_tiers(self, obj):
		return self.get_tier_info(obj)['total_tiers']

	def get_current_tier_progress(self, obj):
		return self.get_tier_info(obj)['current_tier_progress']

	def get_max_severity(self, scan_history):
		from startScan.models import Vulnerability
		max_vuln = Vulnerability.objects.filter(scan_history=scan_history).order_by('-severity').first()
		if max_vuln:
			severity_map = {
				4: 'critical',
				3: 'high',
				2: 'medium',
				1: 'low',
				0: 'info',
				-1: 'unknown'
			}
			return severity_map.get(max_vuln.severity, 'unknown')
		return 'none'

	def get_engine_name(self, scan_history):
		if scan_history.scan_type:
			return scan_history.scan_type.engine_name
		return 'Standard'

	def get_subdomain_count(self, scan_history):
		if scan_history.get_subdomain_count:
			return scan_history.get_subdomain_count()

	def get_endpoint_count(self, scan_history):
		if scan_history.get_endpoint_count:
			return scan_history.get_endpoint_count()

	def get_vulnerability_count(self, scan_history):
		if scan_history.get_vulnerability_count:
			return scan_history.get_vulnerability_count()

	def get_progress(self, scan_history):
		return scan_history.get_progress()

	def get_total_scan_time_in_sec(self, scan_history):
		return scan_history.get_total_scan_time_in_sec()

	def get_elapsed_time(self, scan_history):
		return scan_history.get_elapsed_time()

	def get_completed_ago(self, scan_history):
		return scan_history.get_completed_ago()

	def get_organizations(self, scan_history):
		return [org.name for org in scan_history.domain.get_organization()]


class OrganizationSerializer(serializers.ModelSerializer):

	class Meta:
		model = Organization
		fields = '__all__'


class EngineSerializer(serializers.ModelSerializer):

	tasks = serializers.SerializerMethodField('get_tasks')
	configured_tools_count = serializers.SerializerMethodField('get_configured_tools_count')

	def get_tasks(self, instance):
		return instance.tasks

	def get_configured_tools_count(self, instance):
		"""
		Calculates the total number of unique tools configured in the scan engine
		by parsing its YAML configuration.

		Args:
			instance (EngineType): The EngineType model instance.

		Returns:
			int: The number of configured tools.
		"""
		if not instance.yaml_configuration:
			return 0
		try:
			import yaml
			config = yaml.safe_load(instance.yaml_configuration)
			if not isinstance(config, dict):
				return 0
			tools = set()
			boolean_tool_flags = [
				('port_scan', 'enable_nmap'),
				('port_scan', 'enable_network_enum'),
				('vulnerability_scan', 'run_nuclei'),
				('vulnerability_scan', 'run_dalfox'),
				('vulnerability_scan', 'run_crlfuzz'),
				('vulnerability_scan', 'run_acunetix'),
				('vulnerability_scan', 'run_wpscan'),
				('vulnerability_scan', 'run_s3scanner'),
				('vulnerability_scan', 'run_vigolium'),
				('vigolium_discovery', 'run_vigolium_discovery'),
				('vigolium_analysis', 'run_vigolium_analysis'),
				('firewall_vpn_scan', 'run_ike_scan'),
				('firewall_vpn_scan', 'run_sslscan'),
				('firewall_vpn_scan', 'enable_testssl'),
				('firewall_vpn_scan', 'enable_crt_sh'),
				('waf_detection', 'use_shodan'),
				('waf_detection', 'use_censys'),
				('waf_bypass', 'use_nuclei'),
				('waf_bypass', 'use_benchmarking'),
				('dir_file_fuzz', 'run_dirsearch'),
			]
			# Add section-level default tools
			if 'spiderfoot_scan' in config:
				tools.add('spiderfoot')
			if 'screenshot' in config:
				tools.add('playwright')
			if 'dir_file_fuzz' in config:
				tools.add('ffuf')

			for section_name, section_data in config.items():
				if not isinstance(section_data, dict):
					continue
				if 'uses_tools' in section_data and isinstance(section_data['uses_tools'], list):
					for t in section_data['uses_tools']:
						if isinstance(t, str):
							tools.add(t.strip().lower())
				if 'discover' in section_data and isinstance(section_data['discover'], list):
					for t in section_data['discover']:
						if isinstance(t, str):
							tools.add(t.strip().lower())
				if 'leaks_and_secrets' in section_data and isinstance(section_data['leaks_and_secrets'], dict):
					for tool_name, enabled in section_data['leaks_and_secrets'].items():
						if enabled is True:
							tools.add(tool_name.strip().lower())
			for section, flag in boolean_tool_flags:
				section_data = config.get(section)
				if isinstance(section_data, dict) and section_data.get(flag) is True:
					clean_name = flag.replace('run_', '').replace('enable_', '').replace('use_', '')
					tools.add(clean_name.strip().lower())
			return len(tools)
		except Exception:
			return 0

	class Meta:
		model = EngineType
		fields = [
			'id',
			'default_engine',
			'engine_name',
			'yaml_configuration',
			'tasks',
			'configured_tools_count'
		]


class OrganizationTargetsSerializer(serializers.ModelSerializer):

	class Meta:
		model = Domain
		fields = [
			'name',
			'id'
		]


class VisualiseVulnerabilitySerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Vulnerability
		fields = [
			'description',
			'http_url'
		]

	def get_description(self, vulnerability):
		return vulnerability.name


class VisualisePortSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')
	title = serializers.SerializerMethodField('get_title')

	class Meta:
		model = Port
		fields = [
			'description',
			'is_uncommon',
			'title',
		]

	def get_description(self, port):
		return str(port.number) + "/" + str(port.service_name)

	def get_title(self, port):
		if port.is_uncommon:
			return "Uncommon Port"


class VisualiseTechnologySerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Technology
		fields = [
			'description'
		]

	def get_description(self, tech):
		return tech.name


class VisualiseIpSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')
	children = serializers.SerializerMethodField('get_children')

	class Meta:
		model = IpAddress
		fields = [
			'description',
			'children'
		]

	def get_description(self, Ip):
		return Ip.address

	def get_children(self, ip):
		port = Port.objects.filter(
			ports__in=IpAddress.objects.filter(
				address=ip))
		serializer = VisualisePortSerializer(port, many=True)
		return serializer.data


class VisualiseEndpointSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = EndPoint
		fields = [
			'description',
			'http_url'
		]

	def get_description(self, endpoint):
		return endpoint.http_url


class VisualiseSubdomainSerializer(serializers.ModelSerializer):

	children = serializers.SerializerMethodField('get_children')
	description = serializers.SerializerMethodField('get_description')
	title = serializers.SerializerMethodField('get_title')

	class Meta:
		model = Subdomain
		fields = [
			'description',
			'children',
			'http_status',
			'title',
		]

	def get_description(self, subdomain):
		return subdomain.name

	def get_title(self, subdomain):
		if get_interesting_subdomains(subdomain.scan_history.id).filter(name=subdomain.name).exists():
			return "Interesting"

	def get_children(self, subdomain_name):
		scan_history = self.context.get('scan_history')
		subdomains = (
			Subdomain.objects
			.filter(scan_history=scan_history)
			.filter(name=subdomain_name)
		)

		ips = IpAddress.objects.filter(ip_addresses__in=subdomains)
		ip_serializer = VisualiseIpSerializer(ips, many=True)

		# endpoint = EndPoint.objects.filter(
		#     scan_history=self.context.get('scan_history')).filter(
		#     subdomain__name=subdomain_name)
		# endpoint_serializer = VisualiseEndpointSerializer(endpoint, many=True)

		technologies = Technology.objects.filter(technologies__in=subdomains)
		tech_serializer = VisualiseTechnologySerializer(technologies, many=True)

		vulnerability = (
			Vulnerability.objects
			.filter(scan_history=scan_history)
			.filter(subdomain=subdomain_name)
		)

		return_data = []
		if ip_serializer.data:
			return_data.append({
				'description': 'IPs',
				'children': ip_serializer.data
			})
		# if endpoint_serializer.data:
		#     return_data.append({
		#         'description': 'Endpoints',
		#         'children': endpoint_serializer.data
		#     })
		if tech_serializer.data:
			return_data.append({
				'description': 'Technologies',
				'children': tech_serializer.data
			})

		if vulnerability:
			vulnerability_data = []
			critical = vulnerability.filter(severity=4)
			if critical:
				critical_serializer = VisualiseVulnerabilitySerializer(
					critical,
					many=True
				)
				vulnerability_data.append({
					'description': 'Critical',
					'children': critical_serializer.data
				})
			high = vulnerability.filter(severity=3)
			if high:
				high_serializer = VisualiseVulnerabilitySerializer(
					high,
					many=True
				)
				vulnerability_data.append({
					'description': 'High',
					'children': high_serializer.data
				})
			medium = vulnerability.filter(severity=2)
			if medium:
				medium_serializer = VisualiseVulnerabilitySerializer(
					medium,
					many=True
				)
				vulnerability_data.append({
					'description': 'Medium',
					'children': medium_serializer.data
				})
			low = vulnerability.filter(severity=1)
			if low:
				low_serializer = VisualiseVulnerabilitySerializer(
					low,
					many=True
				)
				vulnerability_data.append({
					'description': 'Low',
					'children': low_serializer.data
				})
			info = vulnerability.filter(severity=0)
			if info:
				info_serializer = VisualiseVulnerabilitySerializer(
					info,
					many=True
				)
				vulnerability_data.append({
					'description': 'Informational',
					'children': info_serializer.data
				})
			uknown = vulnerability.filter(severity=-1)
			if uknown:
				uknown_serializer = VisualiseVulnerabilitySerializer(
					uknown,
					many=True
				)
				vulnerability_data.append({
					'description': 'Unknown',
					'children': uknown_serializer.data
				})

			if vulnerability_data:
				return_data.append({
					'description': 'Vulnerabilities',
					'children': vulnerability_data
				})

		if subdomain_name.screenshot_path:
			return_data.append({
				'description': 'Screenshot',
				'screenshot_path': subdomain_name.screenshot_path
			})
		return return_data


class VisualiseEmailSerializer(serializers.ModelSerializer):
	title = serializers.SerializerMethodField('get_title')
	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Email
		fields = [
			'description',
			'password',
			'title'
		]

	def get_description(self, email):
		if email.password:
			return email.address + " > " + email.password
		return email.address

	def get_title(self, email):
		if email.password:
			return "Exposed Creds"


class VisualiseDorkSerializer(serializers.ModelSerializer):

	title = serializers.SerializerMethodField('get_title')
	description = serializers.SerializerMethodField('get_description')
	http_url = serializers.SerializerMethodField('get_http_url')

	class Meta:
		model = Dork
		fields = [
			'title',
			'description',
			'http_url'
		]

	def get_title(self, dork):
		return dork.type

	def get_description(self, dork):
		return dork.type

	def get_http_url(self, dork):
		return dork.url


class VisualiseEmployeeSerializer(serializers.ModelSerializer):

	description = serializers.SerializerMethodField('get_description')

	class Meta:
		model = Employee
		fields = [
			'description'
		]

	def get_description(self, employee):
		if employee.designation:
			return employee.name + '--' + employee.designation
		return employee.name


class VisualiseDataSerializer(serializers.ModelSerializer):

	title = serializers.ReadOnlyField(default='Target')
	description = serializers.SerializerMethodField('get_description')
	children = serializers.SerializerMethodField('get_children')

	class Meta:
		model = ScanHistory
		fields = [
			'description',
			'title',
			'children',
		]

	def get_description(self, scan_history):
		return scan_history.domain.name

	def get_children(self, history):
		scan_history = ScanHistory.objects.filter(id=history.id)

		subdomain = Subdomain.objects.filter(scan_history=history)
		subdomain_serializer = VisualiseSubdomainSerializer(
			subdomain,
			many=True,
			context={'scan_history': history})

		email = Email.objects.filter(emails__in=scan_history)
		email_serializer = VisualiseEmailSerializer(email, many=True)

		dork = Dork.objects.filter(dorks__in=scan_history)
		dork_serializer = VisualiseDorkSerializer(dork, many=True)

		employee = Employee.objects.filter(employees__in=scan_history)
		employee_serializer = VisualiseEmployeeSerializer(employee, many=True)

		metainfo = MetaFinderDocument.objects.filter(
			scan_history__id=history.id)

		return_data = []

		if subdomain_serializer.data:
			return_data.append({
				'description': 'Subdomains',
				'children': subdomain_serializer.data})

		if email_serializer.data or employee_serializer.data or dork_serializer.data or metainfo:
			osint_data = []
			if email_serializer.data:
				osint_data.append({
					'description': 'Emails',
					'children': email_serializer.data})
			if employee_serializer.data:
				osint_data.append({
					'description': 'Employees',
					'children': employee_serializer.data})
			if dork_serializer.data:
				osint_data.append({
					'description': 'Dorks',
					'children': dork_serializer.data})

			if metainfo:
				metainfo_data = []
				usernames = (
					metainfo
					.annotate(description=F('author'))
					.values('description')
					.distinct()
					.annotate(children=Value([], output_field=JSONField()))
					.filter(author__isnull=False)
				)

				if usernames:
					metainfo_data.append({
						'description': 'Usernames',
						'children': usernames})

				software = (
					metainfo
					.annotate(description=F('producer'))
					.values('description')
					.distinct()
					.annotate(children=Value([], output_field=JSONField()))
					.filter(producer__isnull=False)
				)

				if software:
					metainfo_data.append({
						'description': 'Software',
						'children': software})

				os = (
					metainfo
					.annotate(description=F('os'))
					.values('description')
					.distinct()
					.annotate(children=Value([], output_field=JSONField()))
					.filter(os__isnull=False)
				)

				if os:
					metainfo_data.append({
						'description': 'OS',
						'children': os})

				if metainfo_data:
					osint_data.append({
						'description': 'Documents',
						'children': metainfo_data})

			if osint_data:
				return_data.append({
					'description': 'OSINT',
					'children': osint_data})

		return return_data


class S3BucketSerializer(serializers.ModelSerializer):
	class Meta:
		model = S3Bucket
		fields = '__all__'


class OnlySubdomainNameSerializer(serializers.ModelSerializer):
	class Meta:
		model = Subdomain
		fields = ['name', 'id']


class SubdomainChangesSerializer(serializers.ModelSerializer):

	change = serializers.SerializerMethodField('get_change')
	is_interesting = serializers.SerializerMethodField('get_is_interesting')

	class Meta:
		model = Subdomain
		fields = '__all__'

	def get_change(self, Subdomain):
		return Subdomain.change

	def get_is_interesting(self, Subdomain):
		return (
			get_interesting_subdomains(Subdomain.scan_history.id)
			.filter(name=Subdomain.name)
			.exists()
		)


class EndPointChangesSerializer(serializers.ModelSerializer):

	change = serializers.SerializerMethodField('get_change')

	class Meta:
		model = EndPoint
		fields = '__all__'

	def get_change(self, EndPoint):
		return EndPoint.change


class InterestingSubdomainSerializer(serializers.ModelSerializer):

	class Meta:
		model = Subdomain
		fields = ['name']


class EmailSerializer(serializers.ModelSerializer):

	class Meta:
		model = Email
		fields = '__all__'


class DorkSerializer(serializers.ModelSerializer):

	class Meta:
		model = Dork
		fields = '__all__'


class EmployeeSerializer(serializers.ModelSerializer):
	class Meta:
		model = Employee
		fields = '__all__'


class MetafinderDocumentSerializer(serializers.ModelSerializer):

	class Meta:
		model = MetaFinderDocument
		fields = '__all__'
		depth = 1


class MetafinderUserSerializer(serializers.ModelSerializer):

	class Meta:
		model = MetaFinderDocument
		fields = ['author']


class InterestingEndPointSerializer(serializers.ModelSerializer):

	class Meta:
		model = EndPoint
		fields = ['http_url']


class TechnologyCountSerializer(serializers.Serializer):
	count = serializers.CharField()
	name = serializers.CharField()


class DorkCountSerializer(serializers.Serializer):
	count = serializers.CharField()
	type = serializers.CharField()


class TechnologySerializer(serializers.ModelSerializer):
	class Meta:
		model = Technology
		fields = '__all__'


class ParameterEndpointSerializer(serializers.ModelSerializer):
	class Meta:
		model = EndPoint
		fields = ['id', 'http_url']


class ParameterSerializer(serializers.ModelSerializer):
	endpoint = ParameterEndpointSerializer(read_only=True)

	class Meta:
		model = Parameter
		fields = [
			'id', 'name', 'value', 'type',
			'confidence', 'sources', 'param_location',
			'data_type', 'is_auth_related',
			'observed_in_js', 'observed_in_openapi', 'observed_in_graphql',
			'endpoint',
		]


class PortSerializer(serializers.ModelSerializer):
	class Meta:
		model = Port
		fields = '__all__'


class IpSerializer(serializers.ModelSerializer):
	ports = PortSerializer(many=True)
	geo_iso_name = serializers.ReadOnlyField(source='geo_iso.name')

	class Meta:
		model = IpAddress
		fields = '__all__'


class DirectoryFileSerializer(serializers.ModelSerializer):

	class Meta:
		model = DirectoryFile
		fields = '__all__'


class EndPointDirectorySerializer(serializers.ModelSerializer):
	url = serializers.CharField(source='http_url')
	length = serializers.IntegerField(source='content_length', default=0)
	lines = serializers.SerializerMethodField()
	words = serializers.SerializerMethodField()
	name = serializers.SerializerMethodField()
	content_type = serializers.CharField(default='text/html')

	class Meta:
		model = EndPoint
		fields = ['id', 'length', 'lines', 'http_status', 'words', 'name', 'url', 'content_type']

	def get_lines(self, obj):
		return 0

	def get_words(self, obj):
		return 0

	def get_name(self, obj):
		import base64
		path = extract_path_from_url(obj.http_url) or '/'
		return base64.b64encode(path.encode('utf-8')).decode('utf-8')



class DirectoryScanSerializer(serializers.ModelSerializer):
	scanned_date = serializers.SerializerMethodField()
	formatted_date_for_id = serializers.SerializerMethodField()
	directory_files = DirectoryFileSerializer(many=True)

	class Meta:
		model = DirectoryScan
		fields = '__all__'

	def get_scanned_date(self, DirectoryScan):
		if DirectoryScan.scanned_date:
			return DirectoryScan.scanned_date.strftime("%b %d, %Y %H:%M")
		return None

	def get_formatted_date_for_id(self, DirectoryScan):
		if DirectoryScan.scanned_date:
			return DirectoryScan.scanned_date.strftime("%b_%d_%Y_%H_%M")
		return None


class IpSubdomainSerializer(serializers.ModelSerializer):

	class Meta:
		model = Subdomain
		fields = ['name', 'ip_addresses']
		depth = 1

class WafSerializer(serializers.ModelSerializer):

	class Meta:
		model = Waf
		fields = '__all__'


class WafBypassFindingSerializer(serializers.ModelSerializer):
	class Meta:
		model = WafBypassFinding
		fields = '__all__'


class ScreenshotSerializer(serializers.ModelSerializer):
	screenshot_path = serializers.SerializerMethodField('get_screenshot_path')
	subdomain_name = serializers.CharField(source='subdomain.name', read_only=True)

	class Meta:
		model = Screenshot
		fields = '__all__'

	def get_screenshot_path(self, screenshot):
		path = screenshot.screenshot_path
		if path:
			from django.conf import settings
			import os
			# If the path is already absolute (starts with /), try to make it relative to MEDIA_ROOT
			if os.path.isabs(path) and path.startswith(settings.MEDIA_ROOT):
				path = os.path.relpath(path, settings.MEDIA_ROOT)

			# If the path doesn't contain the results_dir prefix, add it
			results_dir = screenshot.scan_history.results_dir if screenshot.scan_history else ""
			if results_dir and results_dir.startswith(settings.MEDIA_ROOT):
				rel_results_dir = os.path.relpath(results_dir, settings.MEDIA_ROOT)
				# Check if rel_results_dir is already a prefix of path
				if not path.startswith(rel_results_dir):
					path = os.path.join(rel_results_dir, path)

			return path.replace('\\', '/')
		return None



class SubdomainSerializer(serializers.ModelSerializer):

	vuln_count = serializers.SerializerMethodField('get_vuln_count')

	is_interesting = serializers.SerializerMethodField('get_is_interesting')

	endpoint_count = serializers.SerializerMethodField('get_endpoint_count')
	info_count = serializers.SerializerMethodField('get_info_count')
	low_count = serializers.SerializerMethodField('get_low_count')
	medium_count = serializers.SerializerMethodField('get_medium_count')
	high_count = serializers.SerializerMethodField('get_high_count')
	critical_count = serializers.SerializerMethodField('get_critical_count')
	todos_count = serializers.SerializerMethodField('get_todos_count')
	directories_count = serializers.SerializerMethodField('get_directories_count')
	subscan_count = serializers.SerializerMethodField('get_subscan_count')
	ip_addresses = IpSerializer(many=True)
	waf = WafSerializer(many=True)
	technologies = TechnologySerializer(many=True)
	directories = DirectoryScanSerializer(many=True)
	waf_bypass_findings = WafBypassFindingSerializer(many=True, read_only=True)
	screenshots = ScreenshotSerializer(many=True, read_only=True)
	screenshot_path = serializers.SerializerMethodField('get_screenshot_path')


	class Meta:
		model = Subdomain
		fields = '__all__'

	def get_screenshot_path(self, subdomain):
		from reNgine.utilities import get_screenshot_path
		return get_screenshot_path(subdomain)


	def get_is_interesting(self, subdomain):
		scan_id = subdomain.scan_history.id if subdomain.scan_history else None
		return (
			get_interesting_subdomains(scan_id)
			.filter(name=subdomain.name)
			.exists()
		)

	def get_endpoint_count(self, subdomain):
		return subdomain.get_endpoint_count

	def get_info_count(self, subdomain):
		return subdomain.get_info_count

	def get_low_count(self, subdomain):
		return subdomain.get_low_count

	def get_medium_count(self, subdomain):
		return subdomain.get_medium_count

	def get_high_count(self, subdomain):
		return subdomain.get_high_count

	def get_critical_count(self, subdomain):
		return subdomain.get_critical_count

	def get_directories_count(self, subdomain):
		return subdomain.get_directories_count

	def get_subscan_count(self, subdomain):
		return subdomain.get_subscan_count

	def get_todos_count(self, subdomain):
		return len(subdomain.get_todos.filter(is_done=False))

	def get_vuln_count(self, obj):
		try:
			return obj.vuln_count
		except:
			return None


class EndpointSerializer(serializers.ModelSerializer):

	techs = TechnologySerializer(many=True)
	parameters = ParameterSerializer(many=True, read_only=True)

	class Meta:
		model = EndPoint
		fields = '__all__'


class EndpointOnlyURLsSerializer(serializers.ModelSerializer):

	class Meta:
		model = EndPoint
		fields = ['http_url']


class ValidationResultSerializer(serializers.ModelSerializer):
	class Meta:
		model = ValidationResult
		fields = '__all__'


class VulnerabilitySerializer(serializers.ModelSerializer):

	discovered_date = serializers.SerializerMethodField()
	severity = serializers.SerializerMethodField()
	scan_history = serializers.SerializerMethodField()
	validation_results = ValidationResultSerializer(many=True, read_only=True)

	def get_discovered_date(self, Vulnerability):
		if Vulnerability.discovered_date:
			return Vulnerability.discovered_date.strftime("%b %d, %Y %H:%M")
		return None

	def get_severity(self, Vulnerability):
		if Vulnerability.severity == 0:
			return "Info"
		elif Vulnerability.severity == 1:
			return "Low"
		elif Vulnerability.severity == 2:
			return "Medium"
		elif Vulnerability.severity == 3:
			return "High"
		elif Vulnerability.severity == 4:
			return "Critical"
		elif Vulnerability.severity == -1:
			return "Unknown"
		else:
			return "Unknown"
		
	def get_scan_history(self, vulnerability):
		scan_history_dict = {}
		scan_history = vulnerability.scan_history
		if scan_history:
			scan_history_dict = model_to_dict(
				scan_history, 
				exclude=['emails', 'employees', 'buckets', 'dorks']
			)
			scan_history_dict['domain'] = {
				'name': scan_history.domain.name,
			}
			scan_history_dict['initiated_by'] = MinimalUserSerializer(scan_history.initiated_by).data if scan_history.initiated_by else None
			scan_history_dict['aborted_by'] = MinimalUserSerializer(scan_history.aborted_by).data if scan_history.aborted_by else None
			scan_history_dict['completed_ago'] = scan_history.get_completed_ago()
		return scan_history_dict

	class Meta:
		model = Vulnerability
		fields = '__all__'
		depth = 2


class MonitoringDiscoverySerializer(serializers.ModelSerializer):
    domain_name = serializers.CharField(source='domain.name', read_only=True)
    scan_history_id = serializers.IntegerField(source='scan_history.id', read_only=True, allow_null=True)

    class Meta:
        model = MonitoringDiscovery
        fields = ['id', 'domain', 'domain_name', 'discovery_type', 'content', 'discovered_at', 'scan_history_id']


class ScanActivitySerializer(serializers.ModelSerializer):
	domain = serializers.SerializerMethodField('get_domain_name')
	completed_ago = serializers.SerializerMethodField('get_completed_ago')

	class Meta:
		model = ScanActivity
		fields = [
			'id', 'task_uid', 'title', 'name',
			'time', 'time_started', 'time_ended',
			'tier', 'status', 'error_message',
			'domain', 'completed_ago',
		]

	def get_domain_name(self, activity):
		if activity.scan_of:
			return activity.scan_of.domain.name
		return ''

	def get_completed_ago(self, activity):
		return naturaltime(activity.time).title()


class WordlistSerializer(serializers.ModelSerializer):
	class Meta:
		model = Wordlist
		fields = '__all__'


class ConfigurationSerializer(serializers.ModelSerializer):
	class Meta:
		model = Configuration
		fields = '__all__'


class SecretLeakSerializer(serializers.ModelSerializer):
	class Meta:
		model = SecretLeak
		fields = '__all__'


class VulnerabilityReportSettingSerializer(serializers.ModelSerializer):
	class Meta:
		model = VulnerabilityReportSetting
		fields = '__all__'
class NotificationSettingsSerializer(serializers.ModelSerializer):
	class Meta:
		model = Notification
		fields = '__all__'


class HardwareProfileSerializer(serializers.ModelSerializer):
	class Meta:
		model = HardwareProfile
		fields = '__all__'


class ScanProfileSerializer(serializers.ModelSerializer):
	class Meta:
		model = ScanProfile
		fields = '__all__'
		read_only_fields = ['id', 'is_builtin', 'created_at', 'updated_at']


class ExposureEvidenceSerializer(serializers.ModelSerializer):
	class Meta:
		model = ExposureEvidence
		fields = '__all__'


class ExposureSerializer(serializers.ModelSerializer):
	evidence = ExposureEvidenceSerializer(many=True, read_only=True)
	scan_history = serializers.SerializerMethodField()
	discovered_date = serializers.SerializerMethodField()

	class Meta:
		model = Exposure
		fields = '__all__'
		depth = 2

	def get_discovered_date(self, obj):
		if obj.first_seen:
			return obj.first_seen.strftime("%b %d, %Y %H:%M")
		return None

	def get_scan_history(self, obj):
		scan_history_dict = {}
		scan_history = obj.scan_history
		if scan_history:
			scan_history_dict = model_to_dict(
				scan_history, 
				exclude=['emails', 'employees', 'buckets', 'dorks']
			)
			if scan_history.domain:
				scan_history_dict['domain'] = {
					'name': scan_history.domain.name,
				}
			scan_history_dict['initiated_by'] = MinimalUserSerializer(scan_history.initiated_by).data if scan_history.initiated_by else None
			scan_history_dict['aborted_by'] = MinimalUserSerializer(scan_history.aborted_by).data if scan_history.aborted_by else None
			scan_history_dict['completed_ago'] = scan_history.get_completed_ago()
		return scan_history_dict

