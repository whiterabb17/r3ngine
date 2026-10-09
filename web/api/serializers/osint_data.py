from django.contrib.humanize.templatetags.humanize import naturaltime
from rest_framework import serializers

from startScan.models import (
    Dork, Email, EmailBreach, Employee, MetaFinderDocument, MonitoringDiscovery, OsintStaging,
    S3Bucket, SecretLeak,
)


class OsintStagingSerializer(serializers.ModelSerializer):
	discovered_date_humanized = serializers.SerializerMethodField()
	target_domain_name = serializers.CharField(source='target_domain.name', read_only=True)
	scan_history_id = serializers.IntegerField(source='scan_history.id', read_only=True)

	class Meta:
		model = OsintStaging
		fields = '__all__'

	def get_discovered_date_humanized(self, obj):
		return naturaltime(obj.discovered_date)


class S3BucketSerializer(serializers.ModelSerializer):
	class Meta:
		model = S3Bucket
		fields = '__all__'


class EmailSerializer(serializers.ModelSerializer):
	breach_count = serializers.IntegerField(read_only=True, required=False)

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


class DorkCountSerializer(serializers.Serializer):
	count = serializers.CharField()
	type = serializers.CharField()


class MonitoringDiscoverySerializer(serializers.ModelSerializer):
    domain_name = serializers.CharField(source='domain.name', read_only=True)
    scan_history_id = serializers.IntegerField(source='scan_history.id', read_only=True, allow_null=True)

    class Meta:
        model = MonitoringDiscovery
        fields = ['id', 'domain', 'domain_name', 'discovery_type', 'content', 'discovered_at', 'scan_history_id']


class SecretLeakSerializer(serializers.ModelSerializer):
	class Meta:
		model = SecretLeak
		fields = '__all__'


class EmailBreachSerializer(serializers.ModelSerializer):
	class Meta:
		model = EmailBreach
		fields = '__all__'
