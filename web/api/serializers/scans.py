from django.contrib.humanize.templatetags.humanize import naturaltime
from django.db.models import Count, IntegerField, Max, OuterRef, QuerySet, Subquery
from django.db.models.functions import Coalesce
from rest_framework import serializers

from api.serializers.users import MinimalUserSerializer
from reNgine.definitions import ABORTED_TASK, FAILED_TASK, RUNNING_TASK, SUCCESS_TASK
from startScan.models import (
	Command, EndPoint, ScanActivity, ScanHistory, SubScan, Subdomain, Vulnerability,
)


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


def _scan_related_total(model) -> Coalesce:
	"""Correlated count of a scan's rows in `model`.

	Three Count() annotations cannot be used instead: they span separate
	multi-valued relations, so Django joins subdomains by endpoints by
	vulnerabilities and the intermediate row count explodes long before
	distinct collapses it again.
	"""
	return Coalesce(
		Subquery(
			model.objects
			.filter(scan_history=OuterRef('pk'))
			.order_by()
			.values('scan_history')
			.annotate(total=Count('id'))
			.values('total')[:1],
			output_field=IntegerField(),
		),
		0,
	)


def with_scan_history_serializer_data(queryset: QuerySet) -> QuerySet:
	"""Attach everything ScanHistorySerializer reads, so a list costs a fixed number of queries.

	The serializer declares eighteen method fields; left unannotated, the
	counts, max severity, engine, initiator, organizations and task state each
	query once per row.
	"""
	return (
		queryset
		.select_related('domain', 'scan_type', 'initiated_by')
		.prefetch_related('domain__domains', 'scanactivity_set')
		.annotate(
			subdomain_count_ann=_scan_related_total(Subdomain),
			endpoint_count_ann=_scan_related_total(EndPoint),
			vulnerability_count_ann=_scan_related_total(Vulnerability),
			max_severity_ann=Subquery(
				Vulnerability.objects
				.filter(scan_history=OuterRef('pk'))
				.order_by()
				.values('scan_history')
				.annotate(top=Max('severity'))
				.values('top')[:1],
				output_field=IntegerField(),
			),
		)
	)


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
		# Read from the related manager rather than filtering in SQL, so a
		# prefetch_related('scanactivity_set') on the caller's queryset serves
		# this, get_tier_info and the task counts from one shared fetch.
		return any(
			a.status == RUNNING_TASK
			and (a.name == 'spiderfoot_scan'
				 or 'spiderfoot' in (a.title or '').lower())
			for a in obj.scanactivity_set.all()
		)

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

	@staticmethod
	def _latest_activities_by_name(acts):
		"""Collapse retry/resume duplicates to the latest row per task name.

		Later timestamps always win. Equal/missing timestamps prefer RUNNING
		over a non-running peer so a live attempt is not masked by a same-time
		FAILED placeholder — but an older RUNNING never overrides a newer
		terminal row.
		"""
		latest = {}
		for activity in acts:
			prev = latest.get(activity.name)
			if prev is None:
				latest[activity.name] = activity
				continue
			prev_time = prev.time or prev.time_started
			curr_time = activity.time or activity.time_started
			if curr_time and prev_time:
				if curr_time > prev_time:
					latest[activity.name] = activity
				elif (
					curr_time == prev_time
					and activity.status == RUNNING_TASK
					and prev.status != RUNNING_TASK
				):
					latest[activity.name] = activity
			elif curr_time and not prev_time:
				latest[activity.name] = activity
			elif (
				not curr_time
				and not prev_time
				and activity.status == RUNNING_TASK
				and prev.status != RUNNING_TASK
			):
				latest[activity.name] = activity
		return list(latest.values())

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
		terminal = {SUCCESS_TASK, FAILED_TASK, ABORTED_TASK}

		started_tiers = set()
		completed_tiers = set()
		running_tiers = set()
		tier_activities = {}
		effective_by_tier = {}

		for a in tiered_activities:
			tier_activities.setdefault(a.tier, []).append(a)

		# Derive tier state from the latest row per task name so orphaned
		# RUNNING duplicates from retries cannot pin current_tier.
		for tier, acts in tier_activities.items():
			effective = self._latest_activities_by_name(acts)
			effective_by_tier[tier] = effective
			if not effective:
				continue
			if any(a.status == RUNNING_TASK for a in effective):
				running_tiers.add(tier)
				started_tiers.add(tier)
			elif any(a.status in terminal for a in effective):
				started_tiers.add(tier)
			if all(a.status in terminal for a in effective):
				completed_tiers.add(tier)

		# Prefer tiers that are actually RUNNING. After crash recovery / resume,
		# higher tiers can still have leftover FAILED+INITIATED rows while work
		# has restarted on an earlier tier — max(uncompleted) would mis-report.
		uncompleted_started = [t for t in started_tiers if t not in completed_tiers]
		if running_tiers:
			active_tier = max(running_tiers)
		elif uncompleted_started:
			active_tier = max(uncompleted_started)
		elif completed_tiers:
			active_tier = min(max(completed_tiers) + 1, total_tiers)
		elif obj.scan_status == RUNNING_TASK:
			active_tier = 1
		else:
			active_tier = 0

		current_tier_progress = 0
		if active_tier in effective_by_tier:
			acts = effective_by_tier[active_tier]
			completed_acts = sum(1 for a in acts if a.status in terminal)
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

	SEVERITY_NAMES = {
		4: 'critical',
		3: 'high',
		2: 'medium',
		1: 'low',
		0: 'info',
		-1: 'unknown',
	}

	def get_max_severity(self, scan_history):
		if hasattr(scan_history, 'max_severity_ann'):
			severity = scan_history.max_severity_ann
			if severity is None:
				return 'none'
			return self.SEVERITY_NAMES.get(severity, 'unknown')

		from startScan.models import Vulnerability
		max_vuln = Vulnerability.objects.filter(scan_history=scan_history).order_by('-severity').first()
		if max_vuln:
			return self.SEVERITY_NAMES.get(max_vuln.severity, 'unknown')
		return 'none'

	def get_engine_name(self, scan_history):
		if scan_history.scan_type:
			return scan_history.scan_type.engine_name
		return 'Standard'

	# The three counts below prefer an annotation supplied by the caller's
	# queryset and fall back to the per-row query. Several views share this
	# serializer without annotating, so the fallback is load-bearing.
	def get_subdomain_count(self, scan_history):
		count = getattr(scan_history, 'subdomain_count_ann', None)
		return count if count is not None else scan_history.get_subdomain_count()

	def get_endpoint_count(self, scan_history):
		count = getattr(scan_history, 'endpoint_count_ann', None)
		return count if count is not None else scan_history.get_endpoint_count()

	def get_vulnerability_count(self, scan_history):
		count = getattr(scan_history, 'vulnerability_count_ann', None)
		return count if count is not None else scan_history.get_vulnerability_count()

	def get_progress(self, scan_history):
		return scan_history.get_progress()

	def get_total_scan_time_in_sec(self, scan_history):
		return scan_history.get_total_scan_time_in_sec()

	def get_elapsed_time(self, scan_history):
		return scan_history.get_elapsed_time()

	def get_completed_ago(self, scan_history):
		return scan_history.get_completed_ago()

	def get_organizations(self, scan_history):
		# Domain.get_organization() builds a fresh Organization queryset, which
		# no prefetch can serve. The reverse accessor returns the same set and
		# is satisfied by prefetch_related('domain__domains').
		return [org.name for org in scan_history.domain.domains.all()]


class ScanActivitySerializer(serializers.ModelSerializer):
	domain = serializers.SerializerMethodField('get_domain_name')
	completed_ago = serializers.SerializerMethodField('get_completed_ago')

	class Meta:
		model = ScanActivity
		fields = [
			'id', 'task_uid', 'title', 'name',
			'time', 'time_started', 'time_ended',
			'tier', 'status', 'error_message', 'target_host',
			'domain', 'completed_ago',
		]

	def get_domain_name(self, activity):
		if activity.scan_of:
			return activity.scan_of.domain.name
		return ''

	def get_completed_ago(self, activity):
		return naturaltime(activity.time).title()
