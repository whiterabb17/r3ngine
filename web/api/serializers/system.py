from rest_framework import serializers

from dashboard.models import SOCConfiguration
from scanEngine.models import Notification, Proxy, VulnerabilityReportSetting


class ProxySerializer(serializers.ModelSerializer):
	class Meta:
		model = Proxy
		fields = '__all__'


class SOCConfigurationSerializer(serializers.ModelSerializer):
	class Meta:
		model = SOCConfiguration
		fields = '__all__'


class VulnerabilityReportSettingSerializer(serializers.ModelSerializer):
	class Meta:
		model = VulnerabilityReportSetting
		fields = '__all__'
class NotificationSettingsSerializer(serializers.ModelSerializer):
	class Meta:
		model = Notification
		fields = '__all__'
