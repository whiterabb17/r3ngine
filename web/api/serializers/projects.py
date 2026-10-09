from django.contrib.humanize.templatetags.humanize import naturaltime
from rest_framework import serializers

from dashboard.models import Project, SearchHistory


class ProjectSerializer(serializers.ModelSerializer):
	insert_date_humanized = serializers.SerializerMethodField()

	class Meta:
		model = Project
		fields = '__all__'

	def get_insert_date_humanized(self, obj):
		if obj.insert_date:
			return naturaltime(obj.insert_date).title()


class SearchHistorySerializer(serializers.ModelSerializer):
	class Meta:
		model = SearchHistory
		fields = ['query']
