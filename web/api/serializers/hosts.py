from collections import defaultdict

from django.db import models
from django.db.models import Count, prefetch_related_objects
from rest_framework import serializers

from recon_note.models import TodoNote
from reNgine.common_func import extract_path_from_url, get_interesting_subdomains
from startScan.models import (
    DirectoryFile, DirectoryScan, EndPoint, IpAddress, Port, Screenshot, SubScan, Subdomain,
    Technology, Vulnerability, Waf, WafBypassFinding,
)


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


class InterestingSubdomainSerializer(serializers.ModelSerializer):

	class Meta:
		model = Subdomain
		fields = ['name']


class TechnologyCountSerializer(serializers.Serializer):
	count = serializers.CharField()
	name = serializers.CharField()


class TechnologySerializer(serializers.ModelSerializer):
	class Meta:
		model = Technology
		fields = '__all__'


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


class SubdomainListSerializer(serializers.ListSerializer):
	"""Serialize many subdomains at a cost independent of the row count.

	SubdomainSerializer reads eight counts, an is_interesting lookup and a
	screenshot fallback per row, and nests relations two levels deep. Serialized
	one row at a time that is well over a dozen queries per subdomain, and the
	datatable pages through hundreds. This loads the nested relations with
	prefetch_related_objects and the counts with grouped queries over the rows
	actually being serialized (usually one page), so every caller that passes
	many=True gets the flat cost without having to know the serializer's needs.
	"""

	def to_representation(self, data) -> list:
		rows = list(data.all() if isinstance(data, models.manager.BaseManager) else data)
		prime_subdomain_rows(rows)
		return super().to_representation(rows)


SUBDOMAIN_LIST_PREFETCHES = (
	'scan_history',
	'ip_addresses',
	'ip_addresses__geo_iso',
	'ip_addresses__ports',
	'ip_addresses__ip_subscan_ids',
	'waf',
	'technologies',
	'directories',
	'directories__directory_files',
	'directories__dir_subscan_ids',
	'waf_bypass_findings',
	'screenshots',
	'screenshots__scan_history',
)


def prime_subdomain_rows(subdomains: list[Subdomain]) -> None:
	"""Attach the per-row values SubdomainSerializer would otherwise query for.

	Each value is stored as a `*_ann` attribute that the serializer prefers over
	the model property. Rows without a scan keep the property fallback: their
	name-based lookups span every scan and are not worth batching.
	"""
	if not subdomains:
		return
	prefetch_related_objects(subdomains, *SUBDOMAIN_LIST_PREFETCHES)

	ids = [subdomain.id for subdomain in subdomains]
	subscan_counts = dict(
		SubScan.objects.filter(subdomain_id__in=ids)
		.order_by().values('subdomain_id')
		.annotate(total=Count('id', distinct=True))
		.values_list('subdomain_id', 'total')
	)
	# Subdomain.get_todos narrows to the row's scan when it has one.
	todos_by_scan = defaultdict(int)
	todos_any_scan = defaultdict(int)
	for subdomain_id, scan_id, total in (
		TodoNote.objects.filter(subdomain_id__in=ids, is_done=False)
		.order_by().values('subdomain_id', 'scan_history_id')
		.annotate(total=Count('id'))
		.values_list('subdomain_id', 'scan_history_id', 'total')
	):
		todos_by_scan[(subdomain_id, scan_id)] += total
		todos_any_scan[subdomain_id] += total

	for subdomain in subdomains:
		subdomain.subscan_count_ann = subscan_counts.get(subdomain.id, 0)
		subdomain.todos_count_ann = (
			todos_by_scan[(subdomain.id, subdomain.scan_history_id)]
			if subdomain.scan_history_id is not None
			else todos_any_scan[subdomain.id]
		)
		subdomain.directories_count_ann = len({
			directory_file.id
			for directory_scan in subdomain.directories.all()
			for directory_file in directory_scan.directory_files.all()
		})

	scoped = [subdomain for subdomain in subdomains if subdomain.scan_history_id is not None]
	if not scoped:
		return
	scan_ids = {subdomain.scan_history_id for subdomain in scoped}
	names = {subdomain.name for subdomain in scoped}

	# Subdomain.get_endpoint_count and get_vulnerabilities match on the
	# subdomain name within the scan, not on the foreign key; so do these.
	endpoint_counts = {
		(scan_id, name): total
		for scan_id, name, total in (
			EndPoint.objects
			.filter(scan_history_id__in=scan_ids, subdomain__name__in=names)
			.order_by().values('scan_history_id', 'subdomain__name')
			.annotate(total=Count('id'))
			.values_list('scan_history_id', 'subdomain__name', 'total')
		)
	}
	severity_counts = defaultdict(dict)
	for scan_id, name, severity, total in (
		Vulnerability.objects
		.filter(scan_history_id__in=scan_ids, subdomain__name__in=names)
		.order_by().values('scan_history_id', 'subdomain__name', 'severity')
		.annotate(total=Count('id'))
		.values_list('scan_history_id', 'subdomain__name', 'severity', 'total')
	):
		severity_counts[(scan_id, name)][severity] = total
	interesting = set(
		get_interesting_subdomains()
		.filter(scan_history_id__in=scan_ids, name__in=names)
		.values_list('scan_history_id', 'name')
	)

	for subdomain in scoped:
		key = (subdomain.scan_history_id, subdomain.name)
		subdomain.endpoint_count_ann = endpoint_counts.get(key, 0)
		subdomain.severity_counts_ann = severity_counts.get(key, {})
		subdomain.is_interesting_ann = key in interesting


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
		list_serializer_class = SubdomainListSerializer

	def get_screenshot_path(self, subdomain):
		from reNgine.utilities import get_screenshot_path
		return get_screenshot_path(subdomain)

	# Every method below prefers the value prime_subdomain_rows attached and
	# falls back to the per-row query when serializing a single subdomain.

	def get_is_interesting(self, subdomain):
		interesting = getattr(subdomain, 'is_interesting_ann', None)
		if interesting is not None:
			return interesting
		scan_id = subdomain.scan_history.id if subdomain.scan_history else None
		return (
			get_interesting_subdomains(scan_id)
			.filter(name=subdomain.name)
			.exists()
		)

	def get_endpoint_count(self, subdomain):
		count = getattr(subdomain, 'endpoint_count_ann', None)
		return count if count is not None else subdomain.get_endpoint_count

	def get_info_count(self, subdomain):
		return self._severity_count(subdomain, 0, 'get_info_count')

	def get_low_count(self, subdomain):
		return self._severity_count(subdomain, 1, 'get_low_count')

	def get_medium_count(self, subdomain):
		return self._severity_count(subdomain, 2, 'get_medium_count')

	def get_high_count(self, subdomain):
		return self._severity_count(subdomain, 3, 'get_high_count')

	def get_critical_count(self, subdomain):
		return self._severity_count(subdomain, 4, 'get_critical_count')

	def get_directories_count(self, subdomain):
		count = getattr(subdomain, 'directories_count_ann', None)
		return count if count is not None else subdomain.get_directories_count

	def get_subscan_count(self, subdomain):
		count = getattr(subdomain, 'subscan_count_ann', None)
		return count if count is not None else subdomain.get_subscan_count

	def get_todos_count(self, subdomain):
		count = getattr(subdomain, 'todos_count_ann', None)
		if count is not None:
			return count
		return len(subdomain.get_todos.filter(is_done=False))

	def get_vuln_count(self, obj):
		# Only present when the queryset was annotated with vuln_count.
		return getattr(obj, 'vuln_count', None)

	def _severity_count(self, subdomain: Subdomain, severity: int, fallback: str) -> int:
		counts = getattr(subdomain, 'severity_counts_ann', None)
		if counts is None:
			return getattr(subdomain, fallback)
		return counts.get(severity, 0)
