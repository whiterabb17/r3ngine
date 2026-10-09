from rest_framework import serializers

from dashboard.models import InAppNotification, MobilePushToken


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
