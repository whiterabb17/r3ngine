from rest_framework import serializers


class HackerOneProgramAttributesSerializer(serializers.Serializer):


	"""
		Serializer for HackerOne Program
		IMP: THIS is not a model serializer, programs will not be stored in db
		due to ever changing nature of programs, rather cache will be used on these serializers
	"""
	handle = serializers.CharField(required=False)
	name = serializers.CharField(required=False)
	currency = serializers.CharField(required=False)
	submission_state = serializers.CharField(required=False)
	triage_active = serializers.BooleanField(allow_null=True, required=False)
	state = serializers.CharField(required=False)
	started_accepting_at = serializers.DateTimeField(required=False)
	bookmarked = serializers.BooleanField(required=False)
	allows_bounty_splitting = serializers.BooleanField(required=False)
	offers_bounties = serializers.BooleanField(required=False)
	open_scope = serializers.BooleanField(allow_null=True, required=False)
	fast_payments = serializers.BooleanField(allow_null=True, required=False)
	gold_standard_safe_harbor = serializers.BooleanField(allow_null=True, required=False)

	def to_representation(self, instance):
		return {key: value for key, value in instance.items()}


class HackerOneProgramSerializer(serializers.Serializer):
	id = serializers.CharField()
	type = serializers.CharField()
	attributes = HackerOneProgramAttributesSerializer()
