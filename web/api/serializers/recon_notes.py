from rest_framework import serializers

from recon_note.models import TodoNote


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
