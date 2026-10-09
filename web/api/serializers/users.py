from django.contrib.auth.models import User
from rest_framework import serializers


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
