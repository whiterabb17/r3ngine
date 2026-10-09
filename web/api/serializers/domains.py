from django.apps import apps
from django.contrib.humanize.templatetags.humanize import naturalday, naturaltime
from django.db import models
from django.db.models import Count, Max, prefetch_related_objects
from rest_framework import serializers

from targetApp.models import Domain, Organization

DOMAIN_LIST_PREFETCHES = (
	'domains',
	'project',
	'monitor_engine',
	'temporal_schedule',
	'temporal_schedule__domain',
	'domain_info',
	'domain_info__registrar',
	'domain_info__registrant',
	'domain_info__admin',
	'domain_info__tech',
	'domain_info__status',
	'domain_info__name_servers',
	'domain_info__dns_records',
	'domain_info__related_domains',
	'domain_info__related_tlds',
	'domain_info__similar_domains',
	'domain_info__historical_ips',
)


def prime_domain_rows(domains: list[Domain]) -> None:
	"""Attach the per-row values DomainSerializer would otherwise query for.

	Values are stored as `*_ann` attributes the serializer prefers over its
	per-row queries: the vulnerability and distinct-subdomain counts, and the
	most recent scan (with its activities, for the progress figure).
	"""
	if not domains:
		return
	prefetch_related_objects(domains, *DOMAIN_LIST_PREFETCHES)

	Subdomain = apps.get_model('startScan.Subdomain')
	Vulnerability = apps.get_model('startScan.Vulnerability')
	ScanHistory = apps.get_model('startScan.ScanHistory')
	ids = [domain.id for domain in domains]

	vuln_counts = dict(
		Vulnerability.objects.filter(target_domain_id__in=ids)
		.order_by().values('target_domain_id')
		.annotate(total=Count('id'))
		.values_list('target_domain_id', 'total')
	)
	subdomain_counts = dict(
		Subdomain.objects.filter(target_domain_id__in=ids)
		.order_by().values('target_domain_id')
		.annotate(total=Count('name', distinct=True))
		.values_list('target_domain_id', 'total')
	)
	latest_ids = (
		ScanHistory.objects.filter(domain_id__in=ids)
		.order_by().values('domain_id')
		.annotate(latest=Max('id'))
		.values('latest')
	)
	recent_scans = {
		scan.domain_id: scan
		for scan in ScanHistory.objects.filter(id__in=latest_ids)
		.prefetch_related('scanactivity_set')
	}

	for domain in domains:
		domain.vuln_count_ann = vuln_counts.get(domain.id, 0)
		domain.subdomain_count_ann = subdomain_counts.get(domain.id, 0)
		domain.recent_scan_ann = recent_scans.get(domain.id)


class DomainListSerializer(serializers.ListSerializer):
	"""Serialize many targets at a cost independent of the row count.

	DomainSerializer nests domain_info two levels deep and derives six fields
	from per-row queries (three of them re-fetch the latest scan). This loads
	all of it once for the rows being serialized, usually one page.
	"""

	def to_representation(self, data) -> list:
		rows = list(data.all() if isinstance(data, models.manager.BaseManager) else data)
		prime_domain_rows(rows)
		return super().to_representation(rows)


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
		list_serializer_class = DomainListSerializer

	# The methods below prefer the values prime_domain_rows attached and fall
	# back to the per-row query when serializing a single target.

	def _get_recent_scan(self, obj):
		# None is a valid primed value (never scanned), so test for presence;
		# instance __dict__ rather than hasattr, which any mock satisfies.
		if 'recent_scan_ann' in vars(obj):
			return obj.recent_scan_ann
		ScanHistory = apps.get_model('startScan.ScanHistory')
		return (
			ScanHistory.objects
			.filter(domain__id=obj.id)
			.order_by('-id')
			.first()
		)

	def get_vuln_count(self, obj):
		count = getattr(obj, 'vuln_count_ann', None)
		if count is not None:
			return count
		from startScan.models import Vulnerability
		return Vulnerability.objects.filter(target_domain=obj).count()

	def get_vulnerability_count(self, obj):
		return self.get_vuln_count(obj)

	def get_subdomain_count(self, obj):
		count = getattr(obj, 'subdomain_count_ann', None)
		if count is not None:
			return count
		from startScan.models import Subdomain
		return Subdomain.objects.filter(target_domain=obj).values('name').distinct().count()

	def get_organization(self, obj):
		if 'domains' in getattr(obj, '_prefetched_objects_cache', {}):
			return [org.name for org in obj.domains.all()] or None
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


class OrganizationSerializer(serializers.ModelSerializer):

	class Meta:
		model = Organization
		fields = '__all__'


class OrganizationTargetsSerializer(serializers.ModelSerializer):

	class Meta:
		model = Domain
		fields = [
			'name',
			'id'
		]
