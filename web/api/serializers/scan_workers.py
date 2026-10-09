from rest_framework import serializers

from reNgine.utils.secret_tokens import generate_token, hash_token
from reNgine.utils.task_queues import validate_worker_name
from scanEngine.models import WORKER_TOKEN_PREFIX, ScanWorker


class ScanWorkerSerializer(serializers.ModelSerializer):
	"""Remote worker. The token is generated here and returned only by create."""

	class Meta:
		model = ScanWorker
		fields = [
			'id', 'name', 'description', 'task_queue', 'hostname', 'ip_address',
			'is_active', 'last_heartbeat',
		]
		# task_queue follows the name: run_temporal_orchestrator --worker-name
		# listens on a queue named after the worker.
		read_only_fields = ['id', 'task_queue', 'last_heartbeat', 'hostname', 'ip_address']

	def validate_name(self, value: str) -> str:
		# The name becomes two Temporal queue names and a CLI argument on the
		# worker host; the Go executor rejects anything outside this charset.
		try:
			return validate_worker_name(value)
		except ValueError as exc:
			raise serializers.ValidationError(str(exc))

	def create(self, validated_data):
		token = generate_token(WORKER_TOKEN_PREFIX)
		worker = ScanWorker.objects.create(
			task_queue=validated_data['name'],
			auth_token_hash=hash_token(token),
			**validated_data,
		)
		worker.plaintext_token = token
		return worker

	def to_representation(self, instance):
		data = super().to_representation(instance)
		token = getattr(instance, 'plaintext_token', None)
		if token:
			data['auth_token'] = token
		return data
